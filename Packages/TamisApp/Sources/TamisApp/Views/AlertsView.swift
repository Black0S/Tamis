import SwiftUI

struct AlertsView: View {
    @Environment(AlertsModel.self) private var model
    @Environment(FilterListsModel.self) private var lists
    @Environment(EngineModel.self) private var engines
    @Environment(ResolverModel.self) private var resolver
    @Environment(ScriptsModel.self) private var scripts
    @Environment(HistoryModel.self) private var history

    /// Set by the window, so an alert can lead to the screen that fixes it.
    var onOpen: (MainWindow.Section) -> Void = { _ in }

    private var alerts: [AlertsModel.Alert] {
        model.alerts(
            lists: lists, engines: engines, resolver: resolver,
            scripts: scripts, history: history
        )
    }

    var body: some View {
        Group {
            if alerts.isEmpty { empty } else { list }
        }
        .navigationTitle("Alertes")
    }

    private var empty: some View {
        ContentUnavailableView {
            Label("Rien à signaler", systemImage: "checkmark.circle")
        } description: {
            Text("Les conditions qui méritent votre attention apparaîtront ici, "
                 + "et y resteront tant qu'elles seront vraies.")
        }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(alerts) { alert in
                    GroupBox {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: alert.symbol)
                                .foregroundStyle(colour(for: alert.severity))
                                .font(.title3)

                            VStack(alignment: .leading, spacing: 4) {
                                Text(alert.title).fontWeight(.medium)
                                Text(alert.detail)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)

                                HStack(spacing: 12) {
                                    if let section = alert.section {
                                        Button("Ouvrir \(section.title)") { onOpen(section) }
                                            .buttonStyle(.link)
                                    }
                                    // Only events. A condition has no dismiss control at
                                    // all, rather than one that refuses — a button that
                                    // does nothing teaches the user to distrust buttons.
                                    if alert.isDismissible {
                                        Button("Ignorer") { model.dismiss(alert) }
                                            .buttonStyle(.link)
                                    }
                                }
                            }
                            Spacer(minLength: 0)

                            if alert.kind == .condition {
                                Text("en cours")
                                    .font(.caption2)
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(.secondary.opacity(0.15), in: .capsule)
                                    .foregroundStyle(.secondary)
                                    .help("Cette alerte disparaîtra d'elle-même quand la "
                                          + "situation qu'elle décrit cessera.")
                            }
                        }
                        .padding(6)
                    }
                }
            }
            .padding(20)
        }
    }

    private func colour(for severity: AlertsModel.Alert.Severity) -> Color {
        switch severity {
        case .info:    .secondary
        case .warning: .orange
        case .error:   .red
        }
    }
}
