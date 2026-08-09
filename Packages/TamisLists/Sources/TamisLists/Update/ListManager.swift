import Foundation

/// What the user has subscribed to, and everything that follows from it.
///
/// The pieces below it each do one thing — catalogue, store, downloader, guardrails,
/// diff. This is where they meet, and it is the only place that knows the sequence:
/// fetch, judge, diff, store, or refuse and leave what is in use untouched.
///
/// An actor because a refresh of forty lists runs concurrently and they all write to
/// the same state file.
public actor ListManager {

    /// A list the user chose. Nothing here at first launch, by design.
    public struct Subscription: Sendable, Equatable, Codable, Identifiable {
        public let id: String
        public let addedAt: Date
        /// Set for lists added by URL, which have no catalogue entry behind them.
        public let customURL: URL?
        public let customName: String?

        public init(id: String, addedAt: Date = .now, customURL: URL? = nil, customName: String? = nil) {
            self.id = id
            self.addedAt = addedAt
            self.customURL = customURL
            self.customName = customName
        }
    }

    public enum Failure: Error, Sendable, Equatable {
        case unknownList(String)
        case rejected(UpdateGuard.Rejection)
        case download(String)
    }

    private let catalog: FilterListCatalog
    private let store: ListStore
    /// Where the lists live, for the interface's "reveal in the Finder".
    public nonisolated var storeRoot: URL { store.root }
    private let fetcher: any ListFetching
    /// Readable JSON, kept next to the lists so copying one directory is a backup.
    private let stateURL: URL

    private var subscriptions: [String: Subscription] = [:]

    public init(
        catalog: FilterListCatalog = .bundled,
        store: ListStore,
        fetcher: any ListFetching = ListDownloader(),
        stateURL: URL? = nil
    ) {
        self.catalog = catalog
        self.store = store
        self.fetcher = fetcher
        self.stateURL = stateURL ?? store.root.appending(path: "subscriptions.json")
        self.subscriptions = Self.loadState(from: self.stateURL)
    }

    // MARK: What is subscribed

    public var enabled: [Subscription] {
        subscriptions.values.sorted { $0.id < $1.id }
    }

    public func isEnabled(_ id: String) -> Bool { subscriptions[id] != nil }

    /// The catalogue entry behind a subscription, when there is one.
    public func entry(for id: String) -> FilterListCatalog.Entry? { catalog[id] }

    public func downloadURL(for id: String) -> URL? {
        subscriptions[id]?.customURL ?? catalog[id]?.downloadURL
    }

    public func displayName(for id: String) -> String {
        subscriptions[id]?.customName ?? catalog[id]?.name ?? id
    }

    public func metadata(for id: String) -> ListStore.Metadata { store.metadata(for: id) }

    public func text(for id: String) throws -> String? { try store.text(for: id) }

    /// Text of every enabled list of a given format, for whoever compiles the engine.
    ///
    /// A list that is subscribed but has not downloaded yet is simply absent — not an
    /// empty string, which would look to a caller like a list that blocks nothing.
    public func enabledTexts(format: FilterListCatalog.Format) -> [(id: String, text: String)] {
        enabled.compactMap { subscription in
            guard (catalog[subscription.id]?.format ?? .adblock) == format,
                  let text = try? store.text(for: subscription.id)
            else { return nil }
            return (subscription.id, text)
        }
    }

    // MARK: Subscribing

    /// Subscribes and downloads. On refusal the subscription is not created: a list
    /// that is on but empty is worse than one that is visibly off.
    @discardableResult
    public func enable(_ id: String) async throws -> UpdateOutcome {
        guard let url = catalog[id]?.downloadURL else { throw Failure.unknownList(id) }
        let outcome = try await fetch(id: id, url: url, policy: .blocklist)
        if case .anomaly(let rejection) = outcome { throw Failure.rejected(rejection) }
        subscriptions[id] = Subscription(id: id)
        try saveState()
        return outcome
    }

    /// "Ajouter par URL" — a list the catalogue has never heard of.
    @discardableResult
    public func add(url: URL, name: String) async throws -> String {
        let id = "url:" + url.absoluteString
        let outcome = try await fetch(id: id, url: url, policy: .blocklist)
        if case .anomaly(let rejection) = outcome { throw Failure.rejected(rejection) }
        subscriptions[id] = Subscription(id: id, customURL: url, customName: name)
        try saveState()
        return id
    }

    /// Unsubscribes, and forgets the downloaded copies with it.
    ///
    /// Leaving them would mean a list the user turned off still occupying disk, and
    /// still there to be silently reused if they turned it back on months later.
    public func disable(_ id: String) throws {
        subscriptions[id] = nil
        try store.remove(id: id)
        try saveState()
    }

    // MARK: Refreshing

    @discardableResult
    public func refresh(_ id: String) async -> UpdateOutcome {
        guard let url = downloadURL(for: id) else { return .anomaly(.unparsable(reason: "URL inconnue")) }
        do {
            return try await fetch(id: id, url: url, policy: .blocklist)
        } catch {
            let reason = (error as? ListDownloader.Failure).map(String.init(describing:))
                ?? error.localizedDescription
            try? store.recordFailure(reason, for: id)
            return .anomaly(.unparsable(reason: reason))
        }
    }

    /// Refreshes everything subscribed, concurrently.
    ///
    /// One list failing must not stop the rest: a dead mirror is common, and the other
    /// thirty-nine lists have nothing to do with it.
    public func refreshAll() async -> [String: UpdateOutcome] {
        let identifiers = enabled.map(\.id)
        return await withTaskGroup(of: (String, UpdateOutcome).self) { group in
            for id in identifiers {
                group.addTask { (id, await self.refresh(id)) }
            }
            var results: [String: UpdateOutcome] = [:]
            for await (id, outcome) in group { results[id] = outcome }
            return results
        }
    }

    // MARK: The sequence

    private func fetch(id: String, url: URL, policy: UpdateGuard.Policy) async throws -> UpdateOutcome {
        let stored = store.metadata(for: id)
        let payload: ListPayload
        do {
            payload = try await fetcher.fetch(
                url, etag: stored.current?.etag, lastModified: stored.current?.lastModified
            )
        } catch {
            throw Failure.download(String(describing: error))
        }

        // Nothing changed upstream: the copy in use is already the current one.
        if payload.isUnchanged { return .routine(ListDiff(added: [], removed: [])) }

        let proposed = Self.entries(in: payload.text)
        let currentText = (try? store.text(for: id)) ?? nil
        let current = currentText.map(Self.entries) ?? []

        if let rejection = UpdateGuard.check(
            policy: policy,
            statusCode: payload.statusCode,
            contentLength: payload.contentLength,
            receivedBytes: payload.bytes,
            proposedCount: proposed.count,
            currentCount: current.count
        ) {
            try? store.recordFailure(rejection.summary, for: id)
            return .anomaly(rejection)
        }

        let diff = ListDiff(from: current, to: proposed)
        try store.store(
            payload.text, for: id, entryCount: proposed.count,
            etag: payload.etag, lastModified: payload.lastModified
        )
        return UpdateOutcome.decide(policy: policy, rejection: nil, diff: diff)
    }

    /// Lines that carry a rule, in either syntax.
    ///
    /// Counting raw lines instead would make a list that gained forty comment lines
    /// look like a list that gained forty rules — and the amplitude guardrail reads
    /// this number.
    static func entries(in text: String) -> [String] {
        text.split(separator: "\n", omittingEmptySubsequences: true).compactMap { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty,
                  !trimmed.hasPrefix("!"),      // Adblock Plus
                  !trimmed.hasPrefix("#"),      // hosts, and Zen's exclusions
                  !trimmed.hasPrefix("//"),     // AdGuard's exclusions
                  !trimmed.hasPrefix("[")       // [Adblock Plus 2.0] header
            else { return nil }
            return trimmed
        }
    }

    // MARK: State

    private struct State: Codable {
        var subscriptions: [Subscription]
    }

    private static func loadState(from url: URL) -> [String: Subscription] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: url),
              let state = try? decoder.decode(State.self, from: data)
        else { return [:] }
        return Dictionary(state.subscriptions.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    private func saveState() throws {
        try FileManager.default.createDirectory(
            at: stateURL.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let state = State(subscriptions: enabled)
        try encoder.encode(state).write(to: stateURL, options: .atomic)
    }
}
