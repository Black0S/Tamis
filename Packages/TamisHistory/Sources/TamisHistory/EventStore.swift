import Foundation
import SQLite3

/// What Tamis decided, and when.
///
/// The shape is dictated by volume. A browsing session produces tens of thousands of
/// requests an hour, so a row has to be small and an insert has to be rare: domains and
/// applications are stored once and referenced by identifier, and events are buffered
/// in memory and written in batches. One `INSERT` per request would make the logging
/// cost more than the filtering.
///
/// **Full URLs are kept only for what was blocked.** A query string carries session
/// tokens and identifiers, and for a request that was allowed it has no diagnostic
/// value whatsoever — the only question anyone asks later is why something *was*
/// blocked.
public actor EventStore {

    public enum Action: Int32, Sendable, CaseIterable {
        case allowed = 0
        case blocked = 1
        /// Tunnelled without being looked at — an exclusion, or an application set to
        /// pass through.
        case tunnelled = 2

        public var title: String {
            switch self {
            case .allowed:   "autorisée"
            case .blocked:   "bloquée"
            case .tunnelled: "non déchiffrée"
            }
        }
    }

    public enum Layer: Int32, Sendable {
        case dns = 0
        case proxy = 1
    }

    /// One decision, as the caller reports it.
    public struct Event: Sendable, Equatable {
        public let date: Date
        public let domain: String
        public let bundleID: String?
        public let action: Action
        public let layer: Layer
        /// The rule responsible, for a block. Nothing otherwise.
        public let rule: String?
        /// Kept for blocks only. See the type's own note.
        public let url: String?

        public init(
            date: Date = .now, domain: String, bundleID: String? = nil,
            action: Action, layer: Layer, rule: String? = nil, url: String? = nil
        ) {
            self.date = date
            self.domain = domain
            self.bundleID = bundleID
            self.action = action
            self.layer = layer
            self.rule = rule
            // Enforced here rather than trusted from the caller: this is the promise,
            // and a promise kept by convention is a promise that eventually breaks.
            self.url = action == .blocked ? url : nil
        }
    }

    /// A row as the interface reads it back.
    public struct Record: Sendable, Equatable, Identifiable {
        public let id: Int64
        public let date: Date
        public let domain: String
        public let bundleID: String?
        public let action: Action
        public let layer: Layer
        public let rule: String?
        public let url: String?
    }

    public struct Statistics: Sendable, Equatable {
        public var total = 0
        public var blocked = 0
        public var tunnelled = 0
        public var distinctDomains = 0
        public var fileBytes = Int64(0)
        public var oldest: Date?

        public init() {}
    }

    public enum Failure: Error, Sendable, Equatable {
        case cannotOpen(String)
        case sql(String)
    }

    /// Retention. Whichever limit is reached first is the one that applies.
    public struct Retention: Sendable, Equatable {
        public var days: Int
        public var maxBytes: Int64

        public init(days: Int = 7, maxBytes: Int64 = 256 * 1024 * 1024) {
            self.days = days
            self.maxBytes = maxBytes
        }

        public static let `default` = Retention()
    }

    public nonisolated let url: URL
    public var retention: Retention

    private var database: OpaquePointer?
    private var buffer: [Event] = []
    private var domainIDs: [String: Int64] = [:]
    private var appIDs: [String: Int64] = [:]
    private var insertsSincePurge = 0

    /// Logging stops rather than filtering. A disk that cannot be written to is a
    /// reason to keep less history, never a reason to stop protecting anything.
    public private(set) var isLogging = true
    public private(set) var loggingStoppedReason: String?

    static let flushThreshold = 1_000
    static let purgeInterval = 20_000
    /// Below this much free space, logging stops. The number is from the spec.
    static let freeSpaceFloor = Int64(1024 * 1024 * 1024)

    public init(url: URL, retention: Retention = .default) {
        self.url = url
        self.retention = retention
    }

    public static func defaultURL() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        let directory = support.appending(path: "Tamis", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appending(path: "history.sqlite")
    }

    // MARK: Opening

    public func open() throws {
        guard database == nil else { return }
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )

        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(url.path(percentEncoded: false), &handle, flags, nil) == SQLITE_OK,
              let handle
        else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "inconnu"
            sqlite3_close_v2(handle)
            throw Failure.cannotOpen(message)
        }
        database = handle

        // WAL so a reader — the interface — never blocks the writer, and NORMAL because
        // losing the last second of a *log* to a power cut is not worth an fsync per
        // batch.
        try execute("PRAGMA journal_mode = WAL")
        try execute("PRAGMA synchronous = NORMAL")
        try execute("PRAGMA foreign_keys = ON")
        try createSchema()

        // 0600. FileVault is what actually protects this; the mode stops another
        // account on the same Mac reading it. See the README on what is not encrypted.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url.path(percentEncoded: false)
        )
    }

    public func close() throws {
        try flush()
        if let database { sqlite3_close_v2(database) }
        database = nil
    }

    private func createSchema() throws {
        try execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id   INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        );
        """)
        try execute("""
        CREATE TABLE IF NOT EXISTS apps (
            id        INTEGER PRIMARY KEY,
            bundle_id TEXT NOT NULL UNIQUE
        );
        """)
        try execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY,
            ts        INTEGER NOT NULL,
            domain_id INTEGER NOT NULL REFERENCES domains(id),
            app_id    INTEGER REFERENCES apps(id),
            action    INTEGER NOT NULL,
            layer     INTEGER NOT NULL,
            rule      TEXT
        );
        """)
        // Separate table, so a row for an allowed request cannot carry a URL even by
        // accident — there is nowhere to put one.
        try execute("""
        CREATE TABLE IF NOT EXISTS blocked_details (
            event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
            url      TEXT NOT NULL
        );
        """)
        try execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
        try execute("CREATE INDEX IF NOT EXISTS events_action ON events(action, ts)")
    }

    // MARK: Writing

    /// Buffers. Nothing touches the disk until a batch is full or ``flush()`` is called.
    public func record(_ event: Event) {
        guard isLogging else { return }
        buffer.append(event)
        if buffer.count >= Self.flushThreshold { try? flush() }
    }

    public func record(contentsOf events: [Event]) {
        for event in events { record(event) }
    }

    public func flush() throws {
        guard !buffer.isEmpty, let database, isLogging else { buffer.removeAll(); return }

        if let reason = spaceProblem() {
            stopLogging(reason)
            return
        }

        let pending = buffer
        buffer.removeAll(keepingCapacity: true)

        do {
            try execute("BEGIN IMMEDIATE")
            for event in pending {
                let domainID = try identifier(
                    for: event.domain, in: "domains", column: "name", cache: &domainIDs
                )
                var appID: Int64?
                if let bundleID = event.bundleID {
                    appID = try identifier(
                        for: bundleID, in: "apps", column: "bundle_id", cache: &appIDs
                    )
                }

                let statement = try prepare("""
                INSERT INTO events (ts, domain_id, app_id, action, layer, rule)
                VALUES (?, ?, ?, ?, ?, ?)
                """)
                defer { sqlite3_finalize(statement) }
                sqlite3_bind_int64(statement, 1, Int64(event.date.timeIntervalSince1970))
                sqlite3_bind_int64(statement, 2, domainID)
                if let appID { sqlite3_bind_int64(statement, 3, appID) }
                else { sqlite3_bind_null(statement, 3) }
                sqlite3_bind_int(statement, 4, event.action.rawValue)
                sqlite3_bind_int(statement, 5, event.layer.rawValue)
                bindText(statement, 6, event.rule)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw sqlError() }

                if let url = event.url {
                    let eventID = sqlite3_last_insert_rowid(database)
                    let detail = try prepare(
                        "INSERT INTO blocked_details (event_id, url) VALUES (?, ?)"
                    )
                    defer { sqlite3_finalize(detail) }
                    sqlite3_bind_int64(detail, 1, eventID)
                    bindText(detail, 2, url)
                    guard sqlite3_step(detail) == SQLITE_DONE else { throw sqlError() }
                }
            }
            try execute("COMMIT")
            insertsSincePurge += pending.count
        } catch {
            try? execute("ROLLBACK")
            stopLogging("Écriture impossible : \(error)")
            throw error
        }

        // At launch and every so many inserts, never on a timer: a timer wakes the
        // machine to do nothing on a Mac that is not browsing.
        if insertsSincePurge >= Self.purgeInterval {
            insertsSincePurge = 0
            try? purge()
        }
    }

    /// Both limits, whichever bites first.
    public func purge(now: Date = .now) throws {
        guard database != nil else { return }
        // Buffered events first. Purging around them would delete what is on disk and
        // then write the old rows in afterwards, which looks exactly like a purge that
        // does nothing. `flush` returns immediately on an empty buffer, so the two
        // calling each other terminates.
        try flush()
        let cutoff = Int64(now.timeIntervalSince1970) - Int64(retention.days) * 86_400
        let statement = try prepare("DELETE FROM events WHERE ts < ?")
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, cutoff)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw sqlError() }

        // Then the size cap: drop the oldest tenth until it fits, rather than computing
        // a row count from a byte target that only the file system really knows.
        var guardCounter = 0
        while try fileBytes() > retention.maxBytes, guardCounter < 40 {
            guardCounter += 1
            try execute("""
            DELETE FROM events WHERE id IN (
                SELECT id FROM events ORDER BY ts ASC
                LIMIT MAX(1, (SELECT COUNT(*) / 10 FROM events))
            )
            """)
            if try count("SELECT COUNT(*) FROM events") == 0 { break }
            try execute("PRAGMA wal_checkpoint(TRUNCATE)")
        }
        try execute("DELETE FROM domains WHERE id NOT IN (SELECT domain_id FROM events)")
        try execute("DELETE FROM apps WHERE id NOT IN (SELECT app_id FROM events WHERE app_id IS NOT NULL)")
        try execute("VACUUM")
    }

    /// The button that is the real privacy control, given there is no encryption here.
    public func eraseAll() throws {
        buffer.removeAll()
        try execute("DELETE FROM events")
        try execute("DELETE FROM domains")
        try execute("DELETE FROM apps")
        try execute("PRAGMA wal_checkpoint(TRUNCATE)")
        try execute("VACUUM")
        domainIDs.removeAll()
        appIDs.removeAll()
    }

    public func setRetention(_ retention: Retention) throws {
        self.retention = retention
        try purge()
    }

    public func resumeLogging() {
        isLogging = true
        loggingStoppedReason = nil
    }

    // MARK: Reading

    /// Newest first. `action` narrows to one kind.
    public func recent(limit: Int = 200, action: Action? = nil) throws -> [Record] {
        try flush()
        var sql = """
        SELECT e.id, e.ts, d.name, a.bundle_id, e.action, e.layer, e.rule, b.url
        FROM events e
        JOIN domains d ON d.id = e.domain_id
        LEFT JOIN apps a ON a.id = e.app_id
        LEFT JOIN blocked_details b ON b.event_id = e.id
        """
        if action != nil { sql += " WHERE e.action = ?" }
        sql += " ORDER BY e.ts DESC, e.id DESC LIMIT ?"

        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        var index: Int32 = 1
        if let action { sqlite3_bind_int(statement, index, action.rawValue); index += 1 }
        sqlite3_bind_int(statement, index, Int32(limit))

        var records: [Record] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            records.append(Record(
                id: sqlite3_column_int64(statement, 0),
                date: Date(timeIntervalSince1970: TimeInterval(sqlite3_column_int64(statement, 1))),
                domain: text(statement, 2) ?? "",
                bundleID: text(statement, 3),
                action: Action(rawValue: sqlite3_column_int(statement, 4)) ?? .allowed,
                layer: Layer(rawValue: sqlite3_column_int(statement, 5)) ?? .proxy,
                rule: text(statement, 6),
                url: text(statement, 7)
            ))
        }
        return records
    }

    /// The domains seen most often, which is the question the history screen exists to
    /// answer — not "what happened at 14:03".
    public func topDomains(limit: Int = 20, action: Action? = nil) throws -> [(domain: String, count: Int)] {
        try flush()
        var sql = """
        SELECT d.name, COUNT(*) AS n FROM events e JOIN domains d ON d.id = e.domain_id
        """
        if action != nil { sql += " WHERE e.action = ?" }
        sql += " GROUP BY d.name ORDER BY n DESC LIMIT ?"

        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        var index: Int32 = 1
        if let action { sqlite3_bind_int(statement, index, action.rawValue); index += 1 }
        sqlite3_bind_int(statement, index, Int32(limit))

        var rows: [(String, Int)] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            rows.append((text(statement, 0) ?? "", Int(sqlite3_column_int64(statement, 1))))
        }
        return rows
    }

    public func statistics() throws -> Statistics {
        try flush()
        var statistics = Statistics()
        statistics.total = try count("SELECT COUNT(*) FROM events")
        statistics.blocked = try count("SELECT COUNT(*) FROM events WHERE action = 1")
        statistics.tunnelled = try count("SELECT COUNT(*) FROM events WHERE action = 2")
        statistics.distinctDomains = try count("SELECT COUNT(*) FROM domains")
        statistics.fileBytes = try fileBytes()
        let oldest = try count("SELECT COALESCE(MIN(ts), 0) FROM events")
        statistics.oldest = oldest == 0 ? nil : Date(timeIntervalSince1970: TimeInterval(oldest))
        return statistics
    }

    // MARK: Internals

    private func stopLogging(_ reason: String) {
        isLogging = false
        loggingStoppedReason = reason
        buffer.removeAll()
    }

    private func spaceProblem() -> String? {
        guard let values = try? url.deletingLastPathComponent().resourceValues(
            forKeys: [.volumeAvailableCapacityForImportantUsageKey]
        ), let available = values.volumeAvailableCapacityForImportantUsage
        else { return nil }
        guard available < Self.freeSpaceFloor else { return nil }
        return "Moins d'un gigaoctet disponible. La journalisation est arrêtée ; "
             + "le filtrage continue."
    }

    /// Read through `FileManager`, not through `URL.resourceValues`.
    ///
    /// A `URL` caches what it was told about a file, and these URLs are built before
    /// the file exists — so the cached answer is "absent", forever. The size cap read
    /// that answer and therefore never fired, which is the kind of limit that looks
    /// implemented and is not.
    private func fileBytes() throws -> Int64 {
        let paths = [url, url.appendingPathExtension("wal"), url.appendingPathExtension("shm")]
        return paths.reduce(Int64(0)) { total, path in
            let attributes = try? FileManager.default.attributesOfItem(
                atPath: path.path(percentEncoded: false)
            )
            return total + ((attributes?[.size] as? NSNumber)?.int64Value ?? 0)
        }
    }

    private func identifier(
        for value: String, in table: String, column: String, cache: inout [String: Int64]
    ) throws -> Int64 {
        if let cached = cache[value] { return cached }

        let insert = try prepare("INSERT OR IGNORE INTO \(table) (\(column)) VALUES (?)")
        bindText(insert, 1, value)
        _ = sqlite3_step(insert)
        sqlite3_finalize(insert)

        let select = try prepare("SELECT id FROM \(table) WHERE \(column) = ?")
        defer { sqlite3_finalize(select) }
        bindText(select, 1, value)
        guard sqlite3_step(select) == SQLITE_ROW else { throw sqlError() }
        let id = sqlite3_column_int64(select, 0)
        cache[value] = id
        return id
    }

    private func execute(_ sql: String) throws {
        guard let database else { throw Failure.sql("base fermée") }
        var error: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(database, sql, nil, nil, &error) == SQLITE_OK else {
            let message = error.map { String(cString: $0) } ?? "inconnu"
            sqlite3_free(error)
            throw Failure.sql(message)
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer? {
        guard let database else { throw Failure.sql("base fermée") }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqlError()
        }
        return statement
    }

    private func count(_ sql: String) throws -> Int {
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(statement, 0))
    }

    private func sqlError() -> Failure {
        .sql(database.map { String(cString: sqlite3_errmsg($0)) } ?? "inconnu")
    }

    private func bindText(_ statement: OpaquePointer?, _ index: Int32, _ value: String?) {
        guard let value else { sqlite3_bind_null(statement, index); return }
        // SQLITE_TRANSIENT: SQLite copies the bytes, because the Swift string's buffer
        // does not outlive this call.
        sqlite3_bind_text(statement, index, value, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
    }

    private func text(_ statement: OpaquePointer?, _ index: Int32) -> String? {
        guard let pointer = sqlite3_column_text(statement, index) else { return nil }
        return String(cString: pointer)
    }
}
