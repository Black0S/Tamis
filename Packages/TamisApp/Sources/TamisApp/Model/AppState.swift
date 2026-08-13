import Foundation
import Observation
import TamisSystem

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

    /// Whether Tamis is installed on this Mac, as of the last time anybody looked.
    ///
    /// Held here rather than read from `Installation.isInstalled` inside a view body.
    /// That property reads the filesystem, which is not observable, so SwiftUI had no
    /// reason to redraw when it changed — the dashboard went on saying "Tamis n'est pas
    /// installé" through a successful installation, which is the same class of error as
    /// a rollback that reports success without looking.
    private(set) var isInstalled = Installation.isInstalled

    /// Reads the machine again. Called when the window appears, when it comes back to
    /// the front, and when the first-run flow closes.
    func refreshInstallationState() {
        isInstalled = Installation.isInstalled
    }
}

extension AppState {
    static func previewRunning() -> AppState {
        let state = AppState()
        state.protection = .active
        return state
    }
}
