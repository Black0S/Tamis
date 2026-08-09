import SwiftUI

struct DashboardView: View {
    @Environment(AppState.self) private var state
    @Environment(FilterListsModel.self) private var lists
    @Environment(EngineModel.self) private var engines
    /// Set by the window, so the empty state can send the user to the Filters screen
    /// instead of describing where it is.
    var onChooseLists: () -> Void = {}

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header

                if lists.enabledCount == 0 {
                    NoListsNotice(onChooseLists: onChooseLists)
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

                if lists.enabledCount > 0 { listsRow }
                if lists.enabledCount > 0 { engineRow }
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

    /// The counterpart to the empty state. Removing the notice and putting nothing in
    /// its place would leave the screen unable to say whether anything is loaded — the
    /// same ambiguity, one step later.
    private var listsRow: some View {
        GroupBox {
            HStack {
                Label("Listes de filtres", systemImage: "line.3.horizontal.decrease.circle")
                Spacer()
                Text("\(lists.enabledCount) activées · \(lists.totalEntryCount.formatted()) règles")
                    .foregroundStyle(.secondary).monospacedDigit()
                Button("Gérer…", action: onChooseLists).buttonStyle(.link)
            }
            .padding(4)
        }
    }

    /// What is actually compiled, which is not the same question as what is
    /// subscribed. A list downloaded but not yet built blocks nothing, and saying
    /// "11 lists" while the engines are empty would be a claim of protection.
    @ViewBuilder
    private var engineRow: some View {
        GroupBox {
            HStack {
                Label("Moteurs", systemImage: "gearshape.2")
                Spacer()
                switch engines.state {
                case .idle:
                    Text("pas encore compilés").foregroundStyle(.secondary)
                case .building:
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("compilation…").foregroundStyle(.secondary)
                    }
                case .ready(let compiled):
                    Text("\(compiled.networkRules.formatted()) réseau · "
                         + "\(compiled.cosmeticRules.formatted()) cosmétiques · "
                         + "\(compiled.blockedDomains.formatted()) domaines")
                        .foregroundStyle(.secondary).monospacedDigit()
                        // What is not enforced belongs next to what is. A coverage
                        // figure with nothing subtracted from it is a claim, not a
                        // measurement.
                        .help("\(compiled.notEnforced.formatted()) règles comprises mais "
                              + "non appliquées comme blocage. Compilé en "
                              + String(format: "%.1f s", compiled.duration) + ".")
                }
            }
            .padding(4)
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
    var onChooseLists: () -> Void = {}

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

                Button("Choisir des listes de filtres…", action: onChooseLists)
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
        .environment(FilterListsModel.makeDefault())
        .environment(EngineModel(manager: FilterListsModel.makeDefault().manager))
        .frame(width: 820, height: 600)
}

#Preview("Premier lancement") {
    DashboardView()
        .environment(AppState())
        .environment(FilterListsModel.makeDefault())
        .environment(EngineModel(manager: FilterListsModel.makeDefault().manager))
        .frame(width: 820, height: 600)
}
