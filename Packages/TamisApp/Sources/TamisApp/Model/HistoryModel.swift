import Foundation
import Observation
import TamisHistory

/// Drives the History screen, and is what everything else writes its decisions to.
@MainActor
@Observable
final class HistoryModel {

    /// What the screen is showing. The default is what the screen is *for*: which
    /// domains keep coming back, not what happened at 14:03.
    enum Scope: String, CaseIterable, Identifiable {
        case blocked, all, tunnelled
        var id: String { rawValue }

        var title: String {
            switch self {
            case .blocked:   "Bloquées"
            case .all:       "Tout"
            case .tunnelled: "Non déchiffrées"
            }
        }

        var action: EventStore.Action? {
            switch self {
            case .blocked:   .blocked
            case .all:       nil
            case .tunnelled: .tunnelled
            }
        }
    }

    let store: EventStore
    private(set) var records: [EventStore.Record] = []
    private(set) var topDomains: [(domain: String, count: Int)] = []
    private(set) var statistics = EventStore.Statistics()
    private(set) var loggingStoppedReason: String?
    var scope: Scope = .blocked { didSet { Task { await reload() } } }
    var lastError: String?

    private var isOpen = false

    init(store: EventStore) {
        self.store = store
    }

    static func makeDefault() -> HistoryModel {
        let url = ProcessInfo.processInfo.environment["TAMIS_HISTORY"].map(URL.init(fileURLWithPath:))
            ?? (try? EventStore.defaultURL())
            ?? URL(fileURLWithPath: NSTemporaryDirectory()).appending(path: "Tamis/history.sqlite")
        return HistoryModel(store: EventStore(url: url))
    }

    /// Opened lazily and once. A user who never opens the History screen still has
    /// their decisions recorded, so this cannot wait for the view.
    func openIfNeeded() async {
        guard !isOpen else { return }
        do {
            try await store.open()
            isOpen = true
        } catch {
            lastError = "L'historique n'a pas pu être ouvert : \(error)"
        }
    }

    func record(_ event: EventStore.Event) async {
        await openIfNeeded()
        await store.record(event)
    }

    func reload() async {
        await openIfNeeded()
        do {
            records = try await store.recent(limit: 300, action: scope.action)
            topDomains = try await store.topDomains(limit: 12, action: scope.action)
            statistics = try await store.statistics()
            loggingStoppedReason = await store.loggingStoppedReason
        } catch {
            lastError = "\(error)"
        }
    }

    func eraseAll() async {
        do {
            try await store.eraseAll()
            await reload()
        } catch {
            lastError = "\(error)"
        }
    }

    func setRetention(days: Int) async {
        do {
            let current = await store.retention
            try await store.setRetention(.init(days: days, maxBytes: current.maxBytes))
            await reload()
        } catch {
            lastError = "\(error)"
        }
    }

    var retentionDays: Int = 7
}
