import SwiftUI

struct DashboardView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header

                if !state.hasAnyList {
                    NoListsNotice()
                }

                HStack(spacing: 16) {
                    StatTile(
                        value: state.blockedToday.formatted(),
                        caption: "requêtes bloquées",
                        symbol: "hand.raised"
                    )
                    StatTile(
                        value: Formatting.bytes(state.bytesSaved),
                        caption: "données économisées",
                        symbol: "arrow.down.circle"
                    )
                    StatTile(
                        value: state.unfilteredFlows.formatted(),
                        caption: "flux non filtrés",
                        symbol: "questionmark.circle"
                    )
                }

                dnsRow
                Spacer(minLength: 0)
            }
            .padding(24)
        }
        .navigationTitle("Tableau de bord")
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Protection").font(.title2).fontWeight(.semibold)
                Text(state.protection.label).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("Protection", isOn: .constant(state.protection.isActive))
                .toggleStyle(.switch)
                .labelsHidden()
                .disabled(state.protection == .notConfigured)
        }
    }

    private var dnsRow: some View {
        GroupBox {
            HStack {
                Label("Résolveur DNS", systemImage: "globe")
                Spacer()
                Text(state.dnsProvider).foregroundStyle(.secondary)
            }
            .padding(4)
        }
    }
}

/// Shown when no filter list is enabled — which is the state at first launch, on
/// purpose, because Tamis downloads nothing until the user chooses.
///
/// Worded so it reads as deliberate rather than broken. A dashboard showing zeroes with
/// no explanation is indistinguishable from one that is failing.
struct NoListsNotice: View {
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Label("Aucune liste de filtres activée", systemImage: "info.circle")
                    .font(.headline)
                Text("""
                Tamis protège déjà vos connexions sensibles et n'envoie aucune donnée. \
                Rien n'est téléchargé tant que vous n'avez pas choisi.
                """)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                Button("Choisir des listes de filtres…") {}
                    .buttonStyle(.borderedProminent)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }
}

struct StatTile: View {
    let value: String
    let caption: String
    let symbol: String

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Image(systemName: symbol).foregroundStyle(.secondary)
                Text(value).font(.title).fontWeight(.medium).monospacedDigit()
                Text(caption).font(.callout).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }
}

#Preview("En fonctionnement") {
    DashboardView()
        .environment(AppState.previewRunning())
        .frame(width: 820, height: 600)
}

#Preview("Premier lancement") {
    DashboardView()
        .environment(AppState())
        .frame(width: 820, height: 600)
}
