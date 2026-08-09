import Foundation
import Observation

/// Whether Tamis is protecting anything, which is the one piece of state that belongs
/// to no single screen.
///
/// This used to hold counters and lists as well. They were placeholders, and every one
/// of them has been replaced by the model that actually owns the data — the lists, the
/// engines, the resolver, the log. What is left is what genuinely has no other home.
@MainActor
@Observable
final class AppState {

    enum Protection: Sendable, Equatable {
        case active
        case paused(until: Date?)
        /// Onboarding has not run: nothing is installed, so nothing is filtered. This
        /// is the honest state today — the app manages filtering, it does not yet
        /// carry traffic.
        case notConfigured

        var isActive: Bool { self == .active }
    }

    var protection: Protection = .notConfigured
}

extension AppState {
    static func previewRunning() -> AppState {
        let state = AppState()
        state.protection = .active
        return state
    }
}
