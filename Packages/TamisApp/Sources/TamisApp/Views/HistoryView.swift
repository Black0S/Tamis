import SwiftUI
import TamisHistory

/// What Tamis decided, with the recurring names first.
struct HistoryView: View {
    @Environment(HistoryModel.self) private var model
    @State private var isConfirmingErase = false

    var body: some View {
        @Bindable var model = model

        VStack(spacing: 0) {
            header
            Divider()
            if model.statistics.total == 0 { empty } else { content }
        }
        .navigationTitle("Historique")
        .toolbar { toolbar }
        .task { await model.reload() }
        .confirmationDialog(
            "Effacer tout l'historique ?", isPresented: $isConfirmingErase, titleVisibility: .visible
        ) {
            Button("Effacer", role: .destructive) { Task { await model.eraseAll() } }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Les décisions enregistrées seront supprimées définitivement. "
                 + "Le filtrage n'est pas affecté.")
        }
    }

    private var header: some View {
        @Bindable var model = model

        return VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(model.statistics.total.formatted()) décisions").font(.headline)
                        .monospacedDigit()
                    HStack(spacing: 6) {
                        Text("\(model.statistics.blocked.formatted()) bloquées")
                        Text("·")
                        Text("\(model.statistics.distinctDomains.formatted()) domaines")
                        Text("·")
                        Text(Formatting.bytes(Int(model.statistics.fileBytes)))
                        if let oldest = model.statistics.oldest {
                            Text("·")
                            Text("depuis \(oldest, format: .relative(presentation: .named))")
                        }
                    }
                    .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer()
                Picker("Portée", selection: $model.scope) {
                    ForEach(HistoryModel.Scope.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 320)
            }

            // A condition, not an event: it stays until the disk does.
            if let reason = model.loggingStoppedReason {
                Label(reason, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem {
            Menu {
                Picker("Conserver", selection: .init(
                    get: { model.retentionDays },
                    set: { days in
                        model.retentionDays = days
                        Task { await model.setRetention(days: days) }
                    }
                )) {
                    Text("1 jour").tag(1)
                    Text("7 jours").tag(7)
                    Text("30 jours").tag(30)
                }
                Divider()
                Button("Effacer l'historique…", role: .destructive) { isConfirmingErase = true }
            } label: {
                Label("Historique", systemImage: "ellipsis.circle")
            }
        }
    }

    /// Nothing recorded is the ordinary state before anything has run, so it says which
    /// of the two it is rather than looking like a failure.
    private var empty: some View {
        ContentUnavailableView {
            Label("Rien d'enregistré", systemImage: "clock.arrow.circlepath")
        } description: {
            Text("""
            Les décisions apparaîtront ici dès que le résolveur ou le proxy en prendra. \
            Rien n'est envoyé nulle part : ce journal ne quitte pas ce Mac.
            """)
        }
    }

    private var content: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if !model.topDomains.isEmpty { recurring }
                recent
            }
            .padding(20)
        }
    }

    /// The question the screen exists for.
    private var recurring: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Text("Domaines les plus fréquents").font(.headline)
                let maximum = model.topDomains.first?.count ?? 1
                ForEach(model.topDomains, id: \.domain) { entry in
                    HStack(spacing: 10) {
                        Text(entry.domain).font(.callout).lineLimit(1)
                        Spacer(minLength: 12)
                        // A bar, because a column of numbers hides the shape of the
                        // distribution and the shape is the whole point.
                        GeometryReader { geometry in
                            RoundedRectangle(cornerRadius: 2)
                                .fill(.tint.opacity(0.35))
                                .frame(width: geometry.size.width
                                       * CGFloat(entry.count) / CGFloat(max(maximum, 1)))
                        }
                        .frame(width: 180, height: 8)
                        Text(entry.count.formatted())
                            .font(.callout).monospacedDigit().foregroundStyle(.secondary)
                            .frame(width: 60, alignment: .trailing)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }

    private var recent: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                Text("Dernières décisions").font(.headline).padding(.bottom, 6)
                ForEach(model.records) { record in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Image(systemName: symbol(for: record.action))
                            .foregroundStyle(colour(for: record.action))
                            .frame(width: 16)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(record.domain).font(.callout)
                            if let rule = record.rule {
                                Text(rule).font(.caption).foregroundStyle(.tertiary)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                        }
                        Spacer()
                        Text(record.layer == .dns ? "DNS" : "proxy")
                            .font(.caption2).foregroundStyle(.tertiary)
                        Text(record.date, style: .time)
                            .font(.caption).foregroundStyle(.tertiary).monospacedDigit()
                    }
                    .padding(.vertical, 2)
                    .help(record.url ?? "")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }

    private func symbol(for action: EventStore.Action) -> String {
        switch action {
        case .blocked:   "hand.raised"
        case .allowed:   "arrow.right"
        case .tunnelled: "lock"
        }
    }

    private func colour(for action: EventStore.Action) -> Color {
        switch action {
        case .blocked:   .orange
        case .allowed:   .secondary
        case .tunnelled: .secondary
        }
    }
}
