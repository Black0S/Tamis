import Foundation
import Observation

/// What the interface shows, and the only place it is decided.
///
/// The views read this and nothing else. Keeping the engines, the resolver and the
/// proxy behind one observable object is what will let the app be driven by real
/// components later without a single view changing — the shape of the data is the
/// contract, not who produces it.
@MainActor
@Observable
final class AppState {

    enum Protection: Sendable, Equatable {
        case active
        case paused(until: Date?)
        /// Onboarding has not run: nothing is installed, so nothing is filtered.
        case notConfigured

        var isActive: Bool { self == .active }
    }

    var protection: Protection = .notConfigured

    var blockedToday = 0
    var bytesSaved = 0
    /// Requests Tamis could not see, which is what would justify the layer it does not
    /// have. Shown so the answer comes from measurement rather than assumption.
    var unfilteredFlows = 0

    var dnsProvider = "Cloudflare"
    var alerts: [Alert] = []
    var recent: [Decision] = []

    // MARK: Types

    /// Alerts split in two, and the distinction is behavioural rather than cosmetic.
    ///
    /// A condition describes a state that is still true; letting it be dismissed
    /// manufactures a user who believes they are protected. An event already happened
    /// and can be read and cleared.
    struct Alert: Identifiable, Sendable, Equatable {
        enum Kind: Sendable, Equatable { case condition, event }
        enum Severity: Sendable, Equatable { case info, warning, error }

        let id: UUID
        let kind: Kind
        let severity: Severity
        let title: String
        let detail: String

        var isDismissible: Bool { kind == .event }
    }

    struct Decision: Identifiable, Sendable, Equatable {
        enum Outcome: Sendable, Equatable {
            case blocked(rule: String)
            case allowed
        }
        let id: UUID
        let date: Date
        let host: String
        let outcome: Outcome
    }
}

// MARK: - Preview data

extension AppState {
    /// A populated state, so the layout can be judged against something that looks like
    /// use rather than against empty boxes.
    static func previewRunning() -> AppState {
        let state = AppState()
        state.protection = .active
        state.blockedToday = 12_847
        state.bytesSaved = 3_200_000_000
        state.unfilteredFlows = 4
        state.alerts = [
            .init(
                id: UUID(), kind: .condition, severity: .warning,
                title: "Mullvad a repris le contrôle du DNS",
                detail: "Le filtrage DNS est en pause. Le filtrage web reste actif."
            )
        ]
        state.recent = [
            .init(id: UUID(), date: .now, host: "ads.doubleclick.net",
                  outcome: .blocked(rule: "||doubleclick.net^")),
            .init(id: UUID(), date: .now.addingTimeInterval(-4), host: "static.lemonde.fr",
                  outcome: .allowed),
        ]
        return state
    }
}
