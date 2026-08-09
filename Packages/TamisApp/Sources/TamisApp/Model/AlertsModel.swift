import Foundation
import Observation

/// What Tamis needs to tell the user, and the distinction that makes it honest.
///
/// A **condition** describes something that is still true. It is derived from the state
/// of the other models every time it is read, never stored — which is what makes
/// "cannot be dismissed while it holds" a fact rather than a promise. Storing conditions
/// and hoping to remember to clear them produces the one outcome worth avoiding: a user
/// who believes they are protected because they dismissed the notice saying otherwise.
///
/// An **event** already happened. It can be read and cleared, and it is stored, because
/// there is nothing left to derive it from.
@MainActor
@Observable
final class AlertsModel {

    struct Alert: Identifiable, Sendable {
        enum Kind: Sendable { case condition, event }
        enum Severity: Sendable, Comparable {
            case info, warning, error
        }

        let id: String
        let kind: Kind
        let severity: Severity
        let title: String
        let detail: String
        /// The screen that can do something about it.
        let section: MainWindow.Section?

        var isDismissible: Bool { kind == .event }

        var symbol: String {
            switch severity {
            case .info:    "info.circle"
            case .warning: "exclamationmark.triangle"
            case .error:   "xmark.octagon"
            }
        }
    }

    private var events: [Alert] = []
    private var dismissed: Set<String> = []

    /// Everything currently worth saying, conditions first.
    func alerts(
        lists: FilterListsModel,
        engines: EngineModel,
        resolver: ResolverModel,
        scripts: ScriptsModel,
        history: HistoryModel
    ) -> [Alert] {
        var alerts = conditions(
            lists: lists, engines: engines, resolver: resolver,
            scripts: scripts, history: history
        )
        alerts.append(contentsOf: events.filter { !dismissed.contains($0.id) })
        return alerts.sorted { $0.severity > $1.severity }
    }

    private func conditions(
        lists: FilterListsModel,
        engines: EngineModel,
        resolver: ResolverModel,
        scripts: ScriptsModel,
        history: HistoryModel
    ) -> [Alert] {
        var alerts: [Alert] = []

        // The founding state, stated as a condition rather than left as three zeroes on
        // the dashboard. It is not a fault, so it is information, not a warning.
        if lists.enabledCount == 0 {
            alerts.append(Alert(
                id: "no-lists", kind: .condition, severity: .info,
                title: "Aucune liste de filtres activée",
                detail: "Tamis ne bloque rien pour l'instant. Les exclusions HTTPS "
                      + "restent actives : vos connexions sensibles ne sont pas déchiffrées.",
                section: .filters
            ))
        } else if engines.state.compiled == nil && !engines.state.isBuilding {
            alerts.append(Alert(
                id: "engines-not-built", kind: .condition, severity: .warning,
                title: "Les moteurs ne sont pas compilés",
                detail: "Des listes sont activées mais rien n'est chargé en mémoire, "
                      + "donc rien n'est filtré.",
                section: .filters
            ))
        }

        // A list that failed to update is a list frozen at its last good version, which
        // is not obvious from anywhere else.
        let failing = lists.rows.filter { $0.isEnabled && $0.failure != nil }
        for row in failing {
            alerts.append(Alert(
                id: "list-failure-\(row.id)", kind: .condition, severity: .warning,
                title: "\(row.entry.name) n'a pas pu être mise à jour",
                detail: (row.failure ?? "") + " La version précédente reste en service.",
                section: .filters
            ))
        }

        if case .failed(let reason) = resolver.state {
            alerts.append(Alert(
                id: "resolver-failed", kind: .condition, severity: .error,
                title: "Le résolveur local n'a pas démarré",
                detail: reason, section: .dns
            ))
        }

        // Upstream failures do not stop the resolver; they make its answers worse, and
        // nothing else on screen would say so.
        if resolver.statistics.upstreamFailures > 0 {
            alerts.append(Alert(
                id: "upstream-failures", kind: .condition, severity: .warning,
                title: "\(resolver.statistics.upstreamFailures) échecs de résolution amont",
                detail: "Le résolveur chiffré n'a pas répondu. Les requêtes concernées "
                      + "ont échoué plutôt que d'être envoyées en clair.",
                section: .dns
            ))
        }

        if let reason = history.loggingStoppedReason {
            alerts.append(Alert(
                id: "logging-stopped", kind: .condition, severity: .warning,
                title: "Journalisation arrêtée",
                detail: reason, section: .history
            ))
        }

        // A script that is on but whose file no longer parses does nothing, silently,
        // on every page it claims to match.
        let modified = scripts.nodes.compactMap { node -> String? in
            guard case .entry(let entry) = node.content,
                  entry.isLocallyModified, scripts.effectivelyEnabled.contains(node.path)
            else { return nil }
            return entry.name
        }
        if !modified.isEmpty {
            alerts.append(Alert(
                id: "scripts-modified", kind: .condition, severity: .info,
                title: modified.count == 1
                    ? "1 script modifié localement"
                    : "\(modified.count) scripts modifiés localement",
                detail: modified.joined(separator: ", ")
                      + ". Une mise à jour écraserait ces modifications ; "
                      + "« Revenir à la version d'origine » les annule.",
                section: .scripts
            ))
        }

        return alerts
    }

    // MARK: Events

    /// Something that happened and is over. Stored, because nothing else remembers it.
    func record(
        id: String = UUID().uuidString,
        severity: Alert.Severity,
        title: String,
        detail: String,
        section: MainWindow.Section? = nil
    ) {
        events.insert(Alert(
            id: id, kind: .event, severity: severity,
            title: title, detail: detail, section: section
        ), at: 0)
        if events.count > 100 { events.removeLast(events.count - 100) }
    }

    /// Refuses a condition, which cannot be reached from here anyway — the identifier
    /// would simply be regenerated on the next read. Written as a guard so the intent
    /// survives someone later wiring a dismiss button to everything.
    func dismiss(_ alert: Alert) {
        guard alert.isDismissible else { return }
        dismissed.insert(alert.id)
    }

    func dismissAllEvents() {
        dismissed.formUnion(events.map(\.id))
    }
}
