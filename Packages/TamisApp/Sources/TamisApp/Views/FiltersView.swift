import SwiftUI
import TamisLists

/// The catalogue: 165 lists, none of them on until someone says so.
struct FiltersView: View {
    @Environment(FilterListsModel.self) private var model
    @State private var isAddingByURL = false

    var body: some View {
        @Bindable var model = model

        VStack(spacing: 0) {
            summary
            Divider()
            list
        }
        .navigationTitle("Filtres")
        .searchable(text: $model.search, placement: .toolbar, prompt: "Rechercher une liste")
        .toolbar { toolbar }
        .task { await model.reload() }
        .sheet(isPresented: $isAddingByURL) { AddListSheet() }
        .alert(
            "Cette liste n'a pas pu être activée",
            isPresented: .init(get: { model.lastError != nil },
                               set: { if !$0 { model.lastError = nil } })
        ) {
            Button("OK") { model.lastError = nil }
        } message: {
            Text(model.lastError ?? "")
        }
    }

    // MARK: Header

    private var summary: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                if model.enabledCount == 0 {
                    Text("Aucune liste activée").font(.headline)
                    Text("Tamis ne télécharge rien tant que vous n'avez pas choisi.")
                        .foregroundStyle(.secondary)
                } else {
                    Text("\(model.enabledCount) listes activées").font(.headline)
                    Text("\(model.totalEntryCount.formatted()) règles")
                        .foregroundStyle(.secondary).monospacedDigit()
                }
            }
            Spacer()
            if !model.isSuggestedSelectionApplied {
                Button("Sélection suggérée") {
                    Task { await model.applySuggestedSelection() }
                }
                .buttonStyle(.borderedProminent)
                .help("Active la configuration par défaut d'uBlock Origin, plus deux listes DNS.")
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem {
            Menu {
                Button("Toutes les catégories") { model.category = nil }
                Divider()
                ForEach(model.categorySummary, id: \.category) { summary in
                    Button {
                        model.category = summary.category
                    } label: {
                        Text(summary.enabled > 0
                             ? "\(summary.category.title) — \(summary.enabled)/\(summary.total)"
                             : "\(summary.category.title) — \(summary.total)")
                    }
                }
            } label: {
                Label(model.category?.title ?? "Toutes les catégories",
                      systemImage: "line.3.horizontal.decrease")
            }
        }
        ToolbarItem {
            Button {
                Task { await model.refreshAll() }
            } label: {
                Label("Mettre à jour", systemImage: "arrow.clockwise")
            }
            .disabled(model.enabledCount == 0)
        }
        ToolbarItem {
            Button {
                isAddingByURL = true
            } label: {
                Label("Ajouter par URL", systemImage: "plus")
            }
        }
    }

    // MARK: Rows

    @ViewBuilder
    private var list: some View {
        let rows = model.visibleRows
        if rows.isEmpty {
            ContentUnavailableView.search
        } else if model.category == nil && model.search.isEmpty {
            List {
                ForEach(model.categorySummary, id: \.category) { summary in
                    Section(summary.category.title) {
                        ForEach(rows.filter { $0.entry.category == summary.category }) { row in
                            FilterListRow(row: row)
                        }
                    }
                }
            }
        } else {
            List(rows) { FilterListRow(row: $0) }
        }
    }
}

struct FilterListRow: View {
    @Environment(FilterListsModel.self) private var model
    let row: FilterListsModel.Row

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(row.entry.name).fontWeight(.medium)
                    if row.entry.deprecated {
                        // Kept and marked rather than hidden: somebody may still hold
                        // this subscription, and only they can decide to drop it.
                        Tag("abandonnée", .orange)
                    }
                    if row.entry.recommendedByRegistry { Tag("recommandée", .secondary) }
                }

                if !row.entry.description.isEmpty {
                    Text(row.entry.description)
                        .font(.callout).foregroundStyle(.secondary)
                        .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                }

                HStack(spacing: 6) {
                    Text(row.entry.registry)
                    if let count = row.entryCount {
                        Text("·")
                        Text("\(count.formatted()) règles").monospacedDigit()
                    }
                    if let date = row.updatedAt {
                        Text("·")
                        Text(date, format: .relative(presentation: .named))
                    }
                }
                .font(.caption)
                .foregroundStyle(.tertiary)

                if let failure = row.failure {
                    Label(failure, systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Spacer(minLength: 0)

            if row.isBusy {
                ProgressView().controlSize(.small)
            } else {
                Toggle("Activer", isOn: .init(
                    get: { row.isEnabled },
                    set: { _ in Task { await model.toggle(row.id) } }
                ))
                .toggleStyle(.switch)
                .labelsHidden()
            }
        }
        .padding(.vertical, 4)
    }
}

private struct Tag: View {
    let text: String
    let colour: Color

    init(_ text: String, _ colour: Color) {
        self.text = text
        self.colour = colour
    }

    var body: some View {
        Text(text)
            .font(.caption2)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(colour.opacity(0.15), in: .capsule)
            .foregroundStyle(colour)
    }
}

/// "Ajouter par URL" — for a list the catalogue has never heard of.
struct AddListSheet: View {
    @Environment(FilterListsModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var address = ""
    @State private var name = ""
    @State private var isFetching = false

    private var url: URL? {
        guard let url = URL(string: address.trimmingCharacters(in: .whitespaces)),
              url.scheme == "https", url.host() != nil
        else { return nil }
        return url
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Ajouter une liste").font(.headline)

            Form {
                TextField("Nom", text: $name, prompt: Text("Ma liste"))
                TextField("Adresse", text: $address, prompt: Text("https://…"))
            }
            .formStyle(.grouped)

            // https only, and said plainly rather than enforced in silence.
            Text("L'adresse doit être en https. La liste est téléchargée puis vérifiée "
                 + "avant d'être activée.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Spacer()
                Button("Annuler") { dismiss() }
                Button("Ajouter") {
                    guard let url else { return }
                    isFetching = true
                    Task {
                        await model.addList(url: url, name: name.isEmpty ? url.host() ?? "Liste" : name)
                        isFetching = false
                        dismiss()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(url == nil || isFetching)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

#Preview("Filtres") {
    FiltersView()
        .environment(FilterListsModel.makeDefault())
        .frame(width: 900, height: 640)
}
