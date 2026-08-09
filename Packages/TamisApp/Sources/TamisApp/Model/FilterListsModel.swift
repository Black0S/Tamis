import Foundation
import Observation
import TamisLists

/// Drives the Filters screen.
///
/// Everything the views need is here as plain values; the actor underneath is never
/// touched from a view. That is what keeps a download of four megabytes from being a
/// frozen window, and what lets one list fail while the other ten carry on.
@MainActor
@Observable
final class FilterListsModel {

    /// One catalogue entry, plus what Tamis knows about it locally.
    struct Row: Identifiable, Sendable {
        let entry: FilterListCatalog.Entry
        var isEnabled = false
        var entryCount: Int?
        var updatedAt: Date?
        var failure: String?
        /// A download in flight. The row stays visible and interactive elsewhere.
        var isBusy = false

        var id: String { entry.id }
    }

    let catalog: FilterListCatalog
    private let manager: ListManager

    private(set) var rows: [Row] = []
    var search = ""
    /// `nil` shows every category at once.
    var category: FilterListCatalog.Category?

    /// Set when a download is refused. Kept on screen until dismissed: a list that
    /// silently failed to enable is a list the user believes is protecting them.
    var lastError: String?

    init(catalog: FilterListCatalog = .bundled, manager: ListManager) {
        self.catalog = catalog
        self.manager = manager
        self.rows = catalog.entries.map { Row(entry: $0) }
    }

    /// The manager's own root, so the app and the command-line tools share a state.
    static func makeDefault() -> FilterListsModel {
        let root = (try? ListStore.defaultRoot())
            ?? URL(fileURLWithPath: NSTemporaryDirectory()).appending(path: "Tamis/Lists")
        let store = ListStore(root: root)
        return FilterListsModel(manager: ListManager(store: store))
    }

    // MARK: Reading

    var visibleRows: [Row] {
        let matching = search.isEmpty ? catalog.entries : catalog.search(search)
        let allowed = Set(matching.map(\.id))
        return rows.filter { row in
            allowed.contains(row.id) && (category == nil || row.entry.category == category)
        }
    }

    /// Categories in display order, each with how many of its lists are on.
    var categorySummary: [(category: FilterListCatalog.Category, total: Int, enabled: Int)] {
        catalog.populatedCategories.map { category in
            let inCategory = rows.filter { $0.entry.category == category }
            return (category, inCategory.count, inCategory.count(where: \.isEnabled))
        }
    }

    var enabledCount: Int { rows.count(where: \.isEnabled) }
    var totalEntryCount: Int { rows.compactMap(\.entryCount).reduce(0, +) }
    var isSuggestedSelectionApplied: Bool {
        catalog.suggestedSelection.allSatisfy { entry in
            rows.first { $0.id == entry.id }?.isEnabled == true
        }
    }

    // MARK: Loading

    /// Reads what is on disk into the rows.
    ///
    /// Called at launch, not only when the Filters screen opens: the dashboard asks the
    /// same question, and a model that only learns the truth once someone visits one
    /// screen tells every other screen that nothing is enabled.
    ///
    /// Metadata is read for subscribed lists only. The other hundred and fifty have
    /// none, and asking would be a hundred and fifty pointless trips to the disk.
    func reload() async {
        let enabled = Set(await manager.enabled.map(\.id))
        var metadata: [String: ListStore.Metadata] = [:]
        for id in enabled { metadata[id] = await manager.metadata(for: id) }

        rows = rows.map { row in
            var row = row
            row.isEnabled = enabled.contains(row.id)
            let stored = metadata[row.id]
            row.entryCount = stored?.current?.entryCount
            row.updatedAt = stored?.current?.fetchedAt
            row.failure = stored?.lastFailure
            return row
        }
    }

    // MARK: Acting

    func toggle(_ id: String) async {
        guard let index = rows.firstIndex(where: { $0.id == id }) else { return }
        if rows[index].isEnabled {
            try? await manager.disable(id)
            rows[index].isEnabled = false
            rows[index].entryCount = nil
            rows[index].updatedAt = nil
            rows[index].failure = nil
            return
        }
        await enable(id, at: index)
    }

    private func enable(_ id: String, at index: Int) async {
        rows[index].isBusy = true
        rows[index].failure = nil
        defer { rows[index].isBusy = false }

        do {
            try await manager.enable(id)
            let metadata = await manager.metadata(for: id)
            rows[index].isEnabled = true
            rows[index].entryCount = metadata.current?.entryCount
            rows[index].updatedAt = metadata.current?.fetchedAt
        } catch {
            // The toggle goes back to off, because that is the truth: nothing was
            // stored and nothing is being filtered.
            rows[index].isEnabled = false
            rows[index].failure = Self.describe(error)
            lastError = "\(rows[index].entry.name) — \(Self.describe(error))"
        }
    }

    /// The one-click set. Applied one list at a time so the screen fills in as it goes
    /// rather than staying blank for ten seconds.
    func applySuggestedSelection() async {
        for entry in catalog.suggestedSelection {
            guard let index = rows.firstIndex(where: { $0.id == entry.id }),
                  !rows[index].isEnabled
            else { continue }
            await enable(entry.id, at: index)
        }
    }

    func refreshAll() async {
        let results = await manager.refreshAll()
        await reload()
        let failed = results.filter { if case .anomaly = $0.value { true } else { false } }
        if !failed.isEmpty {
            lastError = failed.count == 1
                ? "1 liste n'a pas pu être mise à jour."
                : "\(failed.count) listes n'ont pas pu être mises à jour."
        }
    }

    func addList(url: URL, name: String) async {
        do {
            _ = try await manager.add(url: url, name: name)
            await reload()
        } catch {
            lastError = "\(name) — \(Self.describe(error))"
        }
    }

    private static func describe(_ error: Error) -> String {
        switch error {
        case ListManager.Failure.rejected(let rejection): rejection.summary
        case ListManager.Failure.unknownList: "Liste inconnue du catalogue."
        case ListManager.Failure.download(let reason):    "Téléchargement impossible : \(reason)"
        default: error.localizedDescription
        }
    }
}
