import Foundation

/// Downloaded lists on disk, two versions of each.
///
/// Keeping the previous version costs one copy of a text file and buys both the diff
/// and the rollback outright. Regenerating either from the network is not equivalent:
/// upstream has already moved on.
///
/// Everything lives under one directory, so copying it is a backup and a migration.
public struct ListStore: Sendable {

    public struct Version: Sendable, Equatable, Codable {
        public let fetchedAt: Date
        public let entryCount: Int
        /// Whatever the server said, for a conditional request next time.
        public let etag: String?
        public let lastModified: String?
    }

    public struct Metadata: Sendable, Equatable, Codable {
        public var current: Version?
        public var previous: Version?
        /// Removals the user has not ruled on. Not applied while they sit here.
        public var pendingRemovals: [String] = []
        public var lastFailure: String?
    }

    public let root: URL
    private var fileManager: FileManager { .default }

    /// `~/Library/Application Support/Tamis/Lists`.
    public static func defaultRoot() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        return support.appending(path: "Tamis/Lists", directoryHint: .isDirectory)
    }

    public init(root: URL) {
        self.root = root
    }

    // MARK: Layout

    private func directory(for id: String) -> URL {
        // Identifiers carry a colon (`adguard:118`), which is legal in a POSIX path but
        // shows up as a directory separator in the Finder. Swapped for something plain.
        root.appending(path: id.replacingOccurrences(of: ":", with: "_"), directoryHint: .isDirectory)
    }

    private func currentURL(_ id: String) -> URL { directory(for: id).appending(path: "current.txt") }
    private func previousURL(_ id: String) -> URL { directory(for: id).appending(path: "previous.txt") }
    private func metadataURL(_ id: String) -> URL { directory(for: id).appending(path: "meta.json") }

    // MARK: Reading

    public func text(for id: String) throws -> String? {
        let url = currentURL(id)
        guard fileManager.fileExists(atPath: url.path(percentEncoded: false)) else { return nil }
        return try String(contentsOf: url, encoding: .utf8)
    }

    public func previousText(for id: String) throws -> String? {
        let url = previousURL(id)
        guard fileManager.fileExists(atPath: url.path(percentEncoded: false)) else { return nil }
        return try String(contentsOf: url, encoding: .utf8)
    }

    public func metadata(for id: String) -> Metadata {
        guard let data = try? Data(contentsOf: metadataURL(id)),
              let metadata = try? JSONDecoder().decode(Metadata.self, from: data)
        else { return Metadata() }
        return metadata
    }

    public func storedIdentifiers() -> [String] {
        let contents = (try? fileManager.contentsOfDirectory(atPath: root.path(percentEncoded: false)))
        return (contents ?? []).map { $0.replacingOccurrences(of: "_", with: ":") }.sorted()
    }

    // MARK: Writing

    /// Replaces the current version, moving it to `previous` first.
    public func store(
        _ text: String,
        for id: String,
        entryCount: Int,
        etag: String? = nil,
        lastModified: String? = nil,
        now: Date = .now
    ) throws {
        let directory = directory(for: id)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)

        var metadata = metadata(for: id)
        let current = currentURL(id)
        if fileManager.fileExists(atPath: current.path(percentEncoded: false)) {
            let previous = previousURL(id)
            try? fileManager.removeItem(at: previous)
            try fileManager.moveItem(at: current, to: previous)
            metadata.previous = metadata.current
        }

        // Written whole and moved into place, so an interrupted write cannot leave a
        // half a blocklist behind looking like a complete one.
        let temporary = directory.appending(path: "current.txt.partial")
        try Data(text.utf8).write(to: temporary, options: .atomic)
        try fileManager.moveItem(at: temporary, to: current)

        metadata.current = Version(
            fetchedAt: now, entryCount: entryCount, etag: etag, lastModified: lastModified
        )
        metadata.lastFailure = nil
        try write(metadata, for: id)
    }

    /// Puts the previous version back. Free, because it is still there.
    @discardableResult
    public func rollback(id: String) throws -> Bool {
        let previous = previousURL(id)
        guard fileManager.fileExists(atPath: previous.path(percentEncoded: false)) else {
            return false
        }
        let current = currentURL(id)
        try? fileManager.removeItem(at: current)
        try fileManager.moveItem(at: previous, to: current)

        var metadata = metadata(for: id)
        metadata.current = metadata.previous
        metadata.previous = nil
        try write(metadata, for: id)
        return true
    }

    public func write(_ metadata: Metadata, for id: String) throws {
        try fileManager.createDirectory(at: directory(for: id), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(metadata).write(to: metadataURL(id), options: .atomic)
    }

    public func recordFailure(_ reason: String, for id: String) throws {
        var metadata = metadata(for: id)
        metadata.lastFailure = reason
        try write(metadata, for: id)
    }

    /// Forgets a list entirely — both versions and the metadata.
    public func remove(id: String) throws {
        try? fileManager.removeItem(at: directory(for: id))
    }
}
