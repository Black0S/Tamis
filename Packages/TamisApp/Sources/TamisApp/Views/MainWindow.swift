import SwiftUI

/// The window's shell: a sidebar and whatever it selects.
///
/// `NavigationSplitView` with a source list is the standard macOS arrangement, and
/// standard is the point — the whole visual direction is to look like a system panel
/// rather than to have a look of its own. No brand colour: `accentColor` follows
/// whatever the user chose in System Settings.
struct MainWindow: View {
    @Environment(AppState.self) private var state
    @Environment(FilterListsModel.self) private var lists
    @Environment(EngineModel.self) private var engines
    @Environment(AlertsModel.self) private var alertsModel
    @Environment(ResolverModel.self) private var resolver
    @Environment(ScriptsModel.self) private var scripts
    @Environment(HistoryModel.self) private var history
    @State private var selection: Section? = .dashboard
    /// `TAMIS_ONBOARDING=1` opens the first-run flow at launch. A seam for driving it
    /// without hunting for a button, like `TAMIS_STORE` for the list directory.
    @State private var isOnboarding =
        ProcessInfo.processInfo.environment["TAMIS_ONBOARDING"] == "1"

    enum Section: String, CaseIterable, Identifiable, Hashable {
        case dashboard, history, filters, dns, applications, scripts, alerts, settings

        var id: String { rawValue }

        var title: String {
            switch self {
            case .dashboard:    "Tableau de bord"
            case .history:      "Historique"
            case .filters:      "Filtres"
            case .dns:          "DNS"
            case .applications: "Applications"
            case .scripts:      "Scripts"
            case .alerts:       "Alertes"
            case .settings:     "Réglages"
            }
        }

        var symbol: String {
            switch self {
            case .dashboard:    "square.grid.2x2"
            case .history:      "clock.arrow.circlepath"
            case .filters:      "line.3.horizontal.decrease.circle"
            case .dns:          "globe"
            case .applications: "app.badge"
            case .scripts:      "curlybraces"
            case .alerts:       "bell"
            case .settings:     "gearshape"
            }
        }

        /// Groups, so the list reads as three intentions rather than eight items.
        static let groups: [(title: String?, items: [Section])] = [
            (nil, [.dashboard, .history]),
            ("Filtrage", [.filters, .dns, .applications, .scripts]),
            (nil, [.alerts, .settings]),
        ]
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                ForEach(Array(Section.groups.enumerated()), id: \.offset) { _, group in
                    if let title = group.title {
                        SwiftUI.Section(title) { rows(group.items) }
                    } else {
                        SwiftUI.Section { rows(group.items) }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 200, max: 240)
        } detail: {
            switch selection {
            case .dashboard, .none: DashboardView(onChooseLists: { selection = .filters },
                                                  onConfigure: { isOnboarding = true })
            case .filters:          FiltersView()
            case .dns:              DNSView()
            case .scripts:          ScriptsView()
            case .applications:     ApplicationsView()
            case .history:          HistoryView()
            case .alerts:           AlertsView(onOpen: { selection = $0 })
            case .settings:         SettingsView()
            case .some(let section): PlaceholderView(section: section)
            }
        }
        // Offered rather than forced: the window works before installation, and a
        // first-run sheet nobody can dismiss is a first-run sheet people resent.
        .sheet(isPresented: $isOnboarding) {
            // The machine is read again on the way out: the flow may have installed
            // something, and the dashboard used to keep saying it had not.
            OnboardingView(onFinish: {
                isOnboarding = false
                state.refreshInstallationState()
            })
        }
        // Before anything is shown, so no screen opens on a state it invented.
        .task {
            state.refreshInstallationState()
            await lists.reload()
            engines.rebuild()
        }
        // And again when the window comes back to the front, because the install can
        // also be undone from a terminal while the app is open.
        .onReceive(NotificationCenter.default.publisher(
            for: NSApplication.didBecomeActiveNotification
        )) { _ in
            state.refreshInstallationState()
        }
    }

    /// Derived, like the alerts themselves, so the badge cannot outlive what it counts.
    private var outstandingAlerts: Int {
        alertsModel.alerts(
            lists: lists, engines: engines, resolver: resolver,
            scripts: scripts, history: history
        ).count { $0.severity != .info }
    }

    @ViewBuilder
    private func rows(_ items: [Section]) -> some View {
        ForEach(items) { item in
            Label(item.title, systemImage: item.symbol)
                .badge(item == .alerts ? outstandingAlerts : 0)
                .tag(item)
        }
    }
}

/// A section that exists in the navigation but not yet in code.
///
/// Said plainly rather than left blank: a screen that looks broken and a screen that is
/// not written yet are indistinguishable otherwise, and the first invites a bug report.
struct PlaceholderView: View {
    let section: MainWindow.Section

    var body: some View {
        ContentUnavailableView {
            Label(section.title, systemImage: section.symbol)
        } description: {
            Text("Cet écran n'est pas encore écrit.")
        }
        .navigationTitle(section.title)
    }
}

#Preview("Fenêtre principale") {
    MainWindow()
        .environment(AppState.previewRunning())
        .environment(FilterListsModel.makeDefault())
        .environment(EngineModel(manager: FilterListsModel.makeDefault().manager))
        .environment(ResolverModel())
        .environment(ScriptsModel.makeDefault())
        .environment(ApplicationsModel())
        .environment(HistoryModel.makeDefault())
        .environment(AlertsModel())
        .frame(width: 1000, height: 680)
}
