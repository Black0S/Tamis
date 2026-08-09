import Foundation
import Testing
@testable import TamisLists

/// Answers whatever the test tells it to, so the sequence can be exercised without a
/// network and without waiting on anyone's mirror.
private struct StubFetcher: ListFetching {
    let respond: @Sendable (URL) async throws -> ListPayload

    func fetch(_ url: URL, etag: String?, lastModified: String?) async throws -> ListPayload {
        try await respond(url)
    }

    static func serving(_ text: String, statusCode: Int = 200, etag: String? = nil) -> StubFetcher {
        StubFetcher { _ in
            ListPayload(
                statusCode: statusCode, contentLength: text.utf8.count, bytes: text.utf8.count,
                text: text, etag: etag, lastModified: nil
            )
        }
    }
}

@Suite("List manager")
struct ListManagerTests {

    private func makeRoot() throws -> URL {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-manager-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private let catalog = FilterListCatalog(entries: [
        .init(id: "test:ads", name: "Test — Ads", description: "",
              downloadURL: URL(string: "https://lists.example.org/ads.txt")!,
              homepage: "", registry: "Test", category: .ads, format: .adblock,
              languages: [], recommendedByRegistry: false, inSuggestedSelection: true,
              deprecated: false, trust: nil),
        .init(id: "test:dns", name: "Test — DNS", description: "",
              downloadURL: URL(string: "https://lists.example.org/hosts.txt")!,
              homepage: "", registry: "Test", category: .dns, format: .hosts,
              languages: [], recommendedByRegistry: false, inSuggestedSelection: false,
              deprecated: false, trust: nil),
    ])

    /// The founding rule, checked at the only place that could break it.
    @Test("Nothing is subscribed until someone asks")
    func nothingByDefault() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root), fetcher: StubFetcher.serving("x")
        )
        #expect(await manager.enabled.isEmpty)
        #expect(await manager.enabledTexts(format: .adblock).isEmpty)
    }

    @Test("Enabling downloads, stores, and shows up as enabled")
    func enable() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root),
            fetcher: StubFetcher.serving("||ads.example^\n||track.example^\n", etag: "\"v1\"")
        )
        try await manager.enable("test:ads")

        #expect(await manager.isEnabled("test:ads"))
        #expect(try await manager.text(for: "test:ads")?.contains("||ads.example^") == true)
        #expect(await manager.metadata(for: "test:ads").current?.entryCount == 2)
        #expect(await manager.metadata(for: "test:ads").current?.etag == "\"v1\"")
    }

    /// A list that is on but holds nothing is worse than one that is visibly off: the
    /// interface would report protection that is not there.
    @Test("A refused download leaves no subscription behind")
    func refusedEnableDoesNotSubscribe() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root),
            fetcher: StubFetcher.serving("! only a comment\n")
        )
        await #expect(throws: ListManager.Failure.rejected(.empty)) {
            try await manager.enable("test:ads")
        }
        #expect(await manager.enabled.isEmpty)
        #expect(try await manager.text(for: "test:ads") == nil)
    }

    @Test("An unknown identifier is refused rather than invented")
    func unknownList() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root), fetcher: StubFetcher.serving("x")
        )
        await #expect(throws: ListManager.Failure.unknownList("nope")) {
            try await manager.enable("nope")
        }
    }

    @Test("Disabling forgets the downloaded copies too")
    func disable() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root),
            fetcher: StubFetcher.serving("||ads.example^\n")
        )
        try await manager.enable("test:ads")
        try await manager.disable("test:ads")

        #expect(await manager.enabled.isEmpty)
        #expect(try await manager.text(for: "test:ads") == nil)
    }

    @Test("Subscriptions survive a restart")
    func statePersists() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let first = ListManager(
            catalog: catalog, store: ListStore(root: root),
            fetcher: StubFetcher.serving("||ads.example^\n")
        )
        try await first.enable("test:ads")

        let second = ListManager(
            catalog: catalog, store: ListStore(root: root), fetcher: StubFetcher.serving("x")
        )
        #expect(await second.isEnabled("test:ads"))
        #expect(await second.enabledTexts(format: .adblock).count == 1)
    }

    /// The state file is meant to be readable and copyable by hand.
    @Test("The state file is legible JSON with dates in it")
    func stateIsReadable() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root),
            fetcher: StubFetcher.serving("||ads.example^\n")
        )
        try await manager.enable("test:ads")

        let json = try String(contentsOf: root.appending(path: "subscriptions.json"), encoding: .utf8)
        #expect(json.contains("test:ads"))
        #expect(json.contains("addedAt"))
        #expect(json.contains("-"), "an ISO date, not a floating-point interval")
    }

    @Test("304 leaves what is in use exactly where it is")
    func notModified() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ListStore(root: root)

        let manager = ListManager(
            catalog: catalog, store: store,
            fetcher: StubFetcher.serving("||ads.example^\n", etag: "\"v1\"")
        )
        try await manager.enable("test:ads")

        let unchanged = ListManager(
            catalog: catalog, store: store,
            fetcher: StubFetcher.serving("", statusCode: 304)
        )
        let outcome = await unchanged.refresh("test:ads")
        #expect(outcome == .routine(ListDiff(added: [], removed: [])))
        #expect(try await unchanged.text(for: "test:ads") == "||ads.example^\n")
    }

    @Test("A refresh that shrinks a blocklist still applies")
    func blocklistShrinks() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ListStore(root: root)

        let big = String(repeating: "||a.example^\n", count: 1)
            + (0..<500).map { "||host\($0).example^" }.joined(separator: "\n")
        let first = ListManager(catalog: catalog, store: store, fetcher: StubFetcher.serving(big))
        try await first.enable("test:ads")

        let second = ListManager(
            catalog: catalog, store: store, fetcher: StubFetcher.serving("||a.example^\n")
        )
        let outcome = await second.refresh("test:ads")
        guard case .routine(let diff) = outcome else {
            Issue.record("a shorter blocklist blocks less, which is not a danger: \(outcome)")
            return
        }
        #expect(diff.removed.count == 500)
        // And rollback is right there, because the previous version was kept.
        #expect(try store.previousText(for: "test:ads")?.contains("host499") == true)
    }

    /// A dead mirror is common. The other lists have nothing to do with it.
    @Test("One list failing does not stop the others")
    func refreshAllContinues() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ListStore(root: root)

        let working = ListManager(
            catalog: catalog, store: store, fetcher: StubFetcher.serving("||a.example^\n")
        )
        try await working.enable("test:ads")
        try await working.enable("test:dns")

        let flaky = ListManager(catalog: catalog, store: store, fetcher: StubFetcher { url in
            if url.absoluteString.contains("hosts") { throw ListDownloader.Failure.notHTTP }
            return ListPayload(statusCode: 200, contentLength: 15, bytes: 15,
                               text: "||b.example^\n", etag: nil, lastModified: nil)
        })
        let results = await flaky.refreshAll()

        #expect(results.count == 2)
        #expect(results["test:ads"]?.needsAttention == false)
        #expect(results["test:dns"]?.needsAttention == true)
        #expect(try await flaky.text(for: "test:ads") == "||b.example^\n")
    }

    @Test("A list added by URL behaves like any other")
    func addByURL() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root),
            fetcher: StubFetcher.serving("||custom.example^\n")
        )
        let url = URL(string: "https://elsewhere.example/list.txt")!
        let id = try await manager.add(url: url, name: "Ma liste")

        #expect(await manager.isEnabled(id))
        #expect(await manager.displayName(for: id) == "Ma liste")
        #expect(await manager.downloadURL(for: id) == url)
        #expect(await manager.enabledTexts(format: .adblock).count == 1)
    }

    @Test("Formats are kept apart, so each engine gets its own lists")
    func formatsSeparate() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let manager = ListManager(
            catalog: catalog, store: ListStore(root: root),
            fetcher: StubFetcher.serving("0.0.0.0 ads.example\n")
        )
        try await manager.enable("test:ads")
        try await manager.enable("test:dns")

        #expect(await manager.enabledTexts(format: .adblock).map(\.id) == ["test:ads"])
        #expect(await manager.enabledTexts(format: .hosts).map(\.id) == ["test:dns"])
    }

    /// The amplitude guardrail reads this count, so a list that gained forty comment
    /// lines must not look like a list that gained forty rules.
    @Test("Comments and headers are not entries")
    func entryCounting() {
        let text = """
        [Adblock Plus 2.0]
        ! Title: Test
        # a hosts-style comment
        // an AdGuard-style comment

        ||ads.example^
        0.0.0.0 tracker.example
        """
        #expect(ListManager.entries(in: text) == ["||ads.example^", "0.0.0.0 tracker.example"])
    }
}
