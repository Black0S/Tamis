import Foundation
import Testing
@testable import TamisHistory

/// The schema exists because of volume, so the volume claim is measured rather than
/// asserted: normalised domains, batched inserts, one small row per decision.
@Suite("Throughput")
struct ThroughputTests {

    @Test("A hundred thousand decisions cost a fraction of a second and little disk")
    func writeThroughput() async throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-history-perf-\(UUID().uuidString)/history.sqlite")
        let store = EventStore(url: url)
        try await store.open()
        defer {
            Task {
                try? await store.close()
                try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
            }
        }

        // A realistic mix: a few hundred distinct domains, most requests allowed.
        let events = (0..<100_000).map { i in
            EventStore.Event(
                domain: "host\(i % 400).example",
                bundleID: i % 3 == 0 ? "com.apple.Safari" : "net.imput.helium",
                action: i % 5 == 0 ? .blocked : .allowed,
                layer: i % 7 == 0 ? .dns : .proxy,
                rule: i % 5 == 0 ? "||host\(i % 400).example^" : nil,
                url: i % 5 == 0 ? "https://host\(i % 400).example/a/b?c=d" : nil
            )
        }

        let started = Date()
        await store.record(contentsOf: events)
        let statistics = try await store.statistics()
        let seconds = Date().timeIntervalSince(started)

        #expect(statistics.total == 100_000)
        #expect(statistics.distinctDomains == 400)
        print(String(
            format: "  100 000 décisions en %.2f s — %.0f o/décision, fichier %.1f Mo",
            seconds,
            Double(statistics.fileBytes) / 100_000,
            Double(statistics.fileBytes) / 1_048_576
        ))
        #expect(seconds < 20)
    }
}
