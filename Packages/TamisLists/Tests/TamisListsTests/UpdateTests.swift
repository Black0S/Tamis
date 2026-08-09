import Foundation
import Testing
@testable import TamisLists

@Suite("Update guardrails")
struct UpdateGuardTests {

    @Test("Anything but 200 is refused")
    func status() {
        #expect(UpdateGuard.checkTransport(statusCode: 404, contentLength: nil, receivedBytes: 10)
                == .httpStatus(404))
        #expect(UpdateGuard.checkTransport(statusCode: 200, contentLength: nil, receivedBytes: 10)
                == nil)
    }

    /// The frequent failure, and the one that most resembles success.
    @Test("A body shorter than Content-Length is a truncated download")
    func truncation() {
        #expect(UpdateGuard.checkTransport(statusCode: 200, contentLength: 5_000, receivedBytes: 2_400)
                == .truncated(expected: 5_000, received: 2_400))
        #expect(UpdateGuard.checkTransport(statusCode: 200, contentLength: 5_000, receivedBytes: 5_000)
                == nil)
    }

    @Test("An empty list never replaces one that has entries")
    func empty() {
        #expect(UpdateGuard.check(policy: .exclusions, proposedCount: 0, currentCount: 100)
                == .empty)
    }

    /// Relative alone would fire on mac.txt losing four of its nineteen entries.
    @Test("A small list can lose a large fraction")
    func smallListShrinks() {
        #expect(UpdateGuard.amplitude(current: 19, proposed: 14) == nil)
        #expect(UpdateGuard.amplitude(current: 30, proposed: 20) == nil)
    }

    /// Absolute alone would fire on 4 000 entries losing 26 of them.
    @Test("A large list can lose an absolute handful")
    func largeListShrinks() {
        #expect(UpdateGuard.amplitude(current: 4_000, proposed: 3_950) == nil)
    }

    @Test("Both conditions together is what fires")
    func amplitudeFires() {
        #expect(UpdateGuard.amplitude(current: 4_000, proposed: 1_000)
                == .amplitude(current: 4_000, proposed: 1_000))
        #expect(UpdateGuard.amplitude(current: 200, proposed: 100)
                == .amplitude(current: 200, proposed: 100))
    }

    @Test("Growth is never an anomaly")
    func growth() {
        #expect(UpdateGuard.amplitude(current: 100, proposed: 100_000) == nil)
    }

    /// The question the size checks answer — losing protection — has no equivalent for
    /// a blocklist, where a shorter list simply blocks less.
    @Test("Blocklists are not size-checked")
    func blocklistPolicy() {
        #expect(UpdateGuard.check(policy: .blocklist, proposedCount: 10, currentCount: 100_000)
                == nil)
        #expect(UpdateGuard.check(policy: .exclusions, proposedCount: 10, currentCount: 100_000)
                == .amplitude(current: 100_000, proposed: 10))
    }

    @Test("Blocklists are still checked for transport and emptiness")
    func blocklistStillChecked() {
        #expect(UpdateGuard.check(policy: .blocklist, statusCode: 503,
                                  receivedBytes: 0, proposedCount: 1, currentCount: 1)
                == .httpStatus(503))
        #expect(UpdateGuard.check(policy: .blocklist, proposedCount: 0, currentCount: 1)
                == .empty)
    }

    /// Upstream moving 200 domains between two files is not a loss, and a per-file
    /// check would reject both halves of it.
    @Test("Amplitude is judged on the total, not file by file")
    func totalsNotFiles() {
        // banks 4 000 → 3 800 and sensitive 180 → 380: two alarming files, no change.
        #expect(UpdateGuard.amplitude(current: 4_180, proposed: 4_180) == nil)
        #expect(UpdateGuard.amplitude(current: 4_000, proposed: 3_800) == nil)
    }
}

@Suite("Diff and outcome")
struct DiffTests {

    @Test("Additions and removals are separated")
    func diff() {
        let diff = ListDiff(from: ["a", "b", "c"], to: ["b", "c", "d"])
        #expect(diff.added == ["d"])
        #expect(diff.removed == ["a"])
        #expect(!diff.isRoutine)
    }

    @Test("Nothing removed is nothing to decide")
    func routine() {
        let diff = ListDiff(from: ["a"], to: ["a", "b"])
        #expect(diff.isRoutine)
        #expect(UpdateOutcome.decide(policy: .exclusions, rejection: nil, diff: diff)
                == .routine(diff))
    }

    /// The asymmetry that matters: holding an addition back would leave a bank
    /// unprotected while the user is away, so waiting has to run the other direction.
    @Test("Removals wait, and the additions in the same update do not")
    func removalsWait() {
        let diff = ListDiff(from: ["a", "b"], to: ["b", "c"])
        let outcome = UpdateOutcome.decide(policy: .exclusions, rejection: nil, diff: diff)

        guard case .awaitingValidation(let applied, let pending) = outcome else {
            Issue.record("expected a validation, got \(outcome)")
            return
        }
        #expect(applied.added == ["c"])
        #expect(applied.removed.isEmpty)
        #expect(pending == ["a"])
        #expect(outcome.needsAttention)
    }

    @Test("A blocklist removal applies without asking")
    func blocklistApplies() {
        let diff = ListDiff(from: ["a", "b"], to: ["b"])
        #expect(UpdateOutcome.decide(policy: .blocklist, rejection: nil, diff: diff)
                == .routine(diff))
    }

    @Test("A guardrail means nothing is applied")
    func anomaly() {
        let diff = ListDiff(from: ["a", "b"], to: [])
        let outcome = UpdateOutcome.decide(
            policy: .exclusions, rejection: .empty, diff: diff
        )
        #expect(outcome == .anomaly(.empty))
        #expect(outcome.needsAttention)
    }
}

@Suite("List store")
struct ListStoreTests {

    private func makeStore() throws -> ListStore {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return ListStore(root: root)
    }

    @Test("A stored list reads back")
    func roundTrip() throws {
        let store = try makeStore()
        defer { try? FileManager.default.removeItem(at: store.root) }

        try store.store("a\nb\n", for: "adguard:118", entryCount: 2, etag: "\"x\"")
        #expect(try store.text(for: "adguard:118") == "a\nb\n")
        #expect(store.metadata(for: "adguard:118").current?.entryCount == 2)
        #expect(store.metadata(for: "adguard:118").current?.etag == "\"x\"")
        #expect(store.storedIdentifiers() == ["adguard:118"])
    }

    @Test("Storing again keeps the version it replaced")
    func keepsPrevious() throws {
        let store = try makeStore()
        defer { try? FileManager.default.removeItem(at: store.root) }

        try store.store("v1\n", for: "l", entryCount: 1)
        try store.store("v2\n", for: "l", entryCount: 1)
        #expect(try store.text(for: "l") == "v2\n")
        #expect(try store.previousText(for: "l") == "v1\n")
    }

    /// Free, because the file never left.
    @Test("Rollback restores the previous version")
    func rollback() throws {
        let store = try makeStore()
        defer { try? FileManager.default.removeItem(at: store.root) }

        try store.store("v1\n", for: "l", entryCount: 1)
        try store.store("v2\n", for: "l", entryCount: 2)
        #expect(try store.rollback(id: "l"))
        #expect(try store.text(for: "l") == "v1\n")
        #expect(store.metadata(for: "l").current?.entryCount == 1)
        // Nothing left to go back to.
        #expect(try store.rollback(id: "l") == false)
    }

    @Test("A list never fetched reads as absent, not as empty")
    func absent() throws {
        let store = try makeStore()
        defer { try? FileManager.default.removeItem(at: store.root) }
        #expect(try store.text(for: "never") == nil)
        #expect(store.metadata(for: "never").current == nil)
    }

    @Test("Pending removals survive across reads")
    func pending() throws {
        let store = try makeStore()
        defer { try? FileManager.default.removeItem(at: store.root) }

        var metadata = store.metadata(for: "l")
        metadata.pendingRemovals = ["idmsa.apple.com"]
        try store.write(metadata, for: "l")
        #expect(store.metadata(for: "l").pendingRemovals == ["idmsa.apple.com"])
    }

    /// `adguard:118` on disk would look like a directory separator in the Finder, and
    /// the store is meant to be copyable by hand.
    @Test("Identifiers with a colon are stored under a plain name")
    func colonInIdentifier() throws {
        let store = try makeStore()
        defer { try? FileManager.default.removeItem(at: store.root) }

        try store.store("x", for: "adguard:118", entryCount: 1)
        let names = try FileManager.default.contentsOfDirectory(
            atPath: store.root.path(percentEncoded: false)
        )
        #expect(names == ["adguard_118"])
        #expect(try store.text(for: "adguard:118") == "x")
    }

    @Test("Removing a list leaves nothing behind")
    func remove() throws {
        let store = try makeStore()
        defer { try? FileManager.default.removeItem(at: store.root) }

        try store.store("x", for: "l", entryCount: 1)
        try store.remove(id: "l")
        #expect(try store.text(for: "l") == nil)
        #expect(store.storedIdentifiers().isEmpty)
    }
}
