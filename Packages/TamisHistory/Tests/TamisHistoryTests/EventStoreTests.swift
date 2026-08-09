import Foundation
import Testing
@testable import TamisHistory

@Suite("Event store")
struct EventStoreTests {

    private func makeStore(retention: EventStore.Retention = .default) async throws -> EventStore {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-history-\(UUID().uuidString)/history.sqlite")
        let store = EventStore(url: url, retention: retention)
        try await store.open()
        return store
    }

    private func destroy(_ store: EventStore) async {
        try? await store.close()
        try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent())
    }

    @Test("An event goes in and comes back")
    func roundTrip() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        await store.record(.init(
            domain: "ads.doubleclick.net", bundleID: "com.apple.Safari",
            action: .blocked, layer: .proxy,
            rule: "||doubleclick.net^", url: "https://ads.doubleclick.net/x.js?id=1"
        ))
        let records = try await store.recent()

        #expect(records.count == 1)
        #expect(records[0].domain == "ads.doubleclick.net")
        #expect(records[0].bundleID == "com.apple.Safari")
        #expect(records[0].action == .blocked)
        #expect(records[0].rule == "||doubleclick.net^")
        #expect(records[0].url?.contains("id=1") == true)
    }

    /// The promise, enforced where it cannot be forgotten. A query string on an allowed
    /// request carries session tokens and answers no question anyone will ask later.
    @Test("A full URL is kept for a block and dropped for anything else", arguments: [
        EventStore.Action.allowed, .tunnelled,
    ])
    func urlsOnlyForBlocks(action: EventStore.Action) async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        await store.record(.init(
            domain: "example.com", action: action, layer: .proxy,
            url: "https://example.com/page?session=secret"
        ))
        let records = try await store.recent()
        #expect(records[0].url == nil)
    }

    /// Constructing the event is where it is decided, so no caller can route around it.
    @Test("The URL is dropped at construction, not at write time")
    func urlDroppedInInitialiser() {
        let event = EventStore.Event(
            domain: "example.com", action: .allowed, layer: .proxy,
            url: "https://example.com/?token=abc"
        )
        #expect(event.url == nil)
    }

    @Test("Nothing is written until a flush")
    func buffered() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        for i in 0..<10 {
            await store.record(.init(domain: "d\(i).example", action: .allowed, layer: .dns))
        }
        // `recent` flushes first, which is what makes the buffer invisible to a reader.
        #expect(try await store.recent().count == 10)
    }

    @Test("A batch larger than the threshold writes itself")
    func autoFlush() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        let events = (0..<EventStore.flushThreshold + 5).map {
            EventStore.Event(domain: "d\($0 % 50).example", action: .allowed, layer: .proxy)
        }
        await store.record(contentsOf: events)
        #expect(try await store.statistics().total == events.count)
    }

    /// Domains and applications are stored once. Volume is the whole reason the schema
    /// looks like this.
    @Test("Repeated domains are stored once")
    func normalised() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        for _ in 0..<500 {
            await store.record(.init(
                domain: "ads.example", bundleID: "com.apple.Safari",
                action: .blocked, layer: .proxy
            ))
        }
        let statistics = try await store.statistics()
        #expect(statistics.total == 500)
        #expect(statistics.distinctDomains == 1)
    }

    @Test("Old events are purged by age")
    func purgeByAge() async throws {
        let store = try await makeStore(retention: .init(days: 7))
        defer { Task { await destroy(store) } }

        let now = Date()
        await store.record(.init(date: now.addingTimeInterval(-30 * 86_400),
                                 domain: "vieux.example", action: .allowed, layer: .dns))
        await store.record(.init(date: now, domain: "recent.example", action: .allowed, layer: .dns))
        try await store.purge(now: now)

        let records = try await store.recent()
        #expect(records.map(\.domain) == ["recent.example"])
    }

    /// The other half of "whichever limit is reached first". Age alone would let a busy
    /// afternoon fill the disk inside the retention window.
    @Test("The size cap purges even when nothing is old")
    func purgeBySize() async throws {
        let store = try await makeStore(retention: .init(days: 3650, maxBytes: 128 * 1024))
        defer { Task { await destroy(store) } }

        let events = (0..<20_000).map {
            EventStore.Event(domain: "host\($0 % 500).example", action: .blocked,
                             layer: .proxy, url: "https://host\($0 % 500).example/x?y=z")
        }
        await store.record(contentsOf: events)
        #expect(try await store.statistics().fileBytes > 128 * 1024)

        try await store.purge()
        let after = try await store.statistics()
        #expect(after.total < 20_000, "rien n'a été purgé")
        #expect(after.total > 0, "tout a été purgé")
    }

    @Test("Changing the retention purges immediately")
    func retentionChange() async throws {
        let store = try await makeStore(retention: .init(days: 30))
        defer { Task { await destroy(store) } }

        await store.record(.init(date: Date().addingTimeInterval(-10 * 86_400),
                                 domain: "d.example", action: .allowed, layer: .dns))
        #expect(try await store.recent().count == 1)

        try await store.setRetention(.init(days: 1))
        #expect(try await store.recent().isEmpty)
    }

    /// The real privacy control, given the file is not encrypted by Tamis.
    @Test("Erasing leaves nothing behind")
    func eraseAll() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        for i in 0..<200 {
            await store.record(.init(domain: "d\(i).example", action: .blocked,
                                     layer: .proxy, url: "https://d\(i).example/x"))
        }
        try await store.eraseAll()

        let statistics = try await store.statistics()
        #expect(statistics.total == 0)
        #expect(statistics.distinctDomains == 0)
        #expect(try await store.recent().isEmpty)
    }

    @Test("The busiest domains are what the screen asks for")
    func topDomains() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        for _ in 0..<10 { await store.record(.init(domain: "beaucoup.example", action: .blocked, layer: .proxy)) }
        for _ in 0..<3 { await store.record(.init(domain: "peu.example", action: .blocked, layer: .proxy)) }
        await store.record(.init(domain: "autorisé.example", action: .allowed, layer: .proxy))

        let top = try await store.topDomains(action: .blocked)
        #expect(top.first?.domain == "beaucoup.example")
        #expect(top.first?.count == 10)
        #expect(!top.contains { $0.domain == "autorisé.example" })
    }

    @Test("Filtering by action returns only that kind")
    func filterByAction() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        await store.record(.init(domain: "a.example", action: .blocked, layer: .proxy))
        await store.record(.init(domain: "b.example", action: .allowed, layer: .proxy))
        await store.record(.init(domain: "c.example", action: .tunnelled, layer: .proxy))

        #expect(try await store.recent(action: .blocked).map(\.domain) == ["a.example"])
        #expect(try await store.recent(action: .tunnelled).map(\.domain) == ["c.example"])
        #expect(try await store.recent().count == 3)
    }

    @Test("Data survives a reopen")
    func persistence() async throws {
        let store = try await makeStore()
        let url = store.url
        await store.record(.init(domain: "persistant.example", action: .blocked, layer: .dns))
        try await store.close()

        let reopened = EventStore(url: url)
        try await reopened.open()
        defer { Task { await destroy(reopened) } }
        #expect(try await reopened.recent().map(\.domain) == ["persistant.example"])
    }

    /// Stopping the log is not stopping the filtering, and the distinction has to
    /// survive contact with a full disk.
    @Test("Logging can stop while everything else carries on")
    func loggingStops() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        #expect(await store.isLogging)
        await store.record(.init(domain: "a.example", action: .allowed, layer: .dns))
        #expect(try await store.recent().count == 1)

        await store.resumeLogging()
        #expect(await store.isLogging)
        #expect(await store.loggingStoppedReason == nil)
    }

    @Test("The file is readable only by its owner")
    func permissions() async throws {
        let store = try await makeStore()
        defer { Task { await destroy(store) } }

        await store.record(.init(domain: "a.example", action: .allowed, layer: .dns))
        _ = try await store.recent()

        let attributes = try FileManager.default.attributesOfItem(
            atPath: store.url.path(percentEncoded: false)
        )
        #expect((attributes[.posixPermissions] as? NSNumber)?.int16Value == 0o600)
    }
}
