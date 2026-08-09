import SwiftUI

/// The window's shell: a sidebar and whatever it selects.
///
/// `NavigationSplitView` with a source list is the standard macOS arrangement, and
/// standard is the point — the whole visual direction is to look like a system panel
/// rather than to have a look of its own. No brand colour: `accentColor` follows
/// whatever the user chose in System Settings.
struct MainWindow: View {
    @Environment(AppState.self) private var state
    @State private var selection: Section? = .dashboard

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
            case .dashboard: DashboardView()
            case .none:      DashboardView()
            default:         PlaceholderView(section: selection ?? .dashboard)
            }
        }
    }

    @ViewBuilder
    private func rows(_ items: [Section]) -> some View {
        ForEach(items) { item in
            Label(item.title, systemImage: item.symbol)
                .badge(item == .alerts ? state.alerts.count : 0)
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
        .frame(width: 1000, height: 680)
}
