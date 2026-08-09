import SwiftUI

/// The menu bar panel: what Tamis is doing, and the three things worth doing from here.
///
/// Everything else lives in the window. A menu bar panel that grows into a second
/// interface is a menu bar panel nobody reads.
struct MenuBarPanel: View {
    @Environment(AppState.self) private var state
    @Environment(FilterListsModel.self) private var lists
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            statusRow
            Divider().padding(.vertical, 10)

            if lists.enabledCount > 0 {
                todayRow
            } else {
                noListsRow
            }

            Divider().padding(.vertical, 10)
            dnsRow
            Divider().padding(.vertical, 10)
            actions
        }
        .padding(14)
        .frame(width: 320)
    }

    private var statusRow: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Tamis").font(.headline)
                Text(state.protection.label)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("Protection", isOn: .constant(state.protection.isActive))
                .toggleStyle(.switch)
                .labelsHidden()
                .disabled(state.protection == .notConfigured)
        }
    }

    private var todayRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(state.blockedToday.formatted())
                    .font(.title2).fontWeight(.medium).monospacedDigit()
                Text("bloquées aujourd'hui")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(Formatting.bytes(state.bytesSaved))
                    .font(.title2).fontWeight(.medium).monospacedDigit()
                Text("économisés")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var noListsRow: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
            Text("Aucune liste de filtres activée.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var dnsRow: some View {
        HStack {
            Label("DNS", systemImage: "globe")
            Spacer()
            Text(state.dnsProvider).foregroundStyle(.secondary)
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 4) {
            Button {
                state.protection = .paused(until: .now.addingTimeInterval(5 * 60))
            } label: {
                Label("Suspendre 5 minutes", systemImage: "pause.circle")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .disabled(!state.protection.isActive)

            Button {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                Label("Ouvrir Tamis", systemImage: "macwindow")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Button {
                NSApp.terminate(nil)
            } label: {
                Label("Quitter", systemImage: "power")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .buttonStyle(.plain)
        .labelStyle(MenuRowLabelStyle())
    }
}

/// Fixed-width icon column, so the labels line up whatever the symbol.
private struct MenuRowLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 8) {
            configuration.icon.frame(width: 16)
            configuration.title
        }
        .contentShape(.rect)
    }
}

#Preview("En fonctionnement") {
    MenuBarPanel()
        .environment(AppState.previewRunning())
        .environment(FilterListsModel.makeDefault())
}

#Preview("Premier lancement") {
    MenuBarPanel()
        .environment(AppState())
        .environment(FilterListsModel.makeDefault())
}
