import AppKit
import SwiftUI
import TamisUserScripts

/// Scripts and styles — the tree on screen is the tree on disk.
struct ScriptsView: View {
    @Environment(ScriptsModel.self) private var model
    @State private var isAdding = false
    @State private var newFolderName = ""
    @State private var isNamingFolder = false

    var body: some View {
        @Bindable var model = model

        VStack(spacing: 0) {
            header
            Divider()
            if model.isEmpty { empty } else { tree }
        }
        .navigationTitle("Scripts")
        .toolbar { toolbar }
        .task { await model.reload() }
        .sheet(isPresented: $isAdding) { AddScriptSheet() }
        .sheet(isPresented: .init(get: { model.editing != nil },
                                  set: { if !$0 { model.editing = nil } })) {
            ScriptEditorSheet()
        }
        .alert("Rien n'a été fait",
               isPresented: .init(get: { model.lastError != nil },
                                  set: { if !$0 { model.lastError = nil } })) {
            Button("OK") { model.lastError = nil }
        } message: {
            Text(model.lastError ?? "")
        }
        .alert("Nouveau dossier", isPresented: $isNamingFolder) {
            TextField("Nom", text: $newFolderName)
            Button("Créer") {
                let name = newFolderName
                newFolderName = ""
                Task { await model.createFolder(named: name) }
            }
            Button("Annuler", role: .cancel) { newFolderName = "" }
        }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                if model.scriptCount == 0 {
                    Text("Aucun script").font(.headline)
                } else {
                    Text("^[\(model.scriptCount) fichier](inflect: true), "
                         + "^[\(model.enabledCount) actif](inflect: true)")
                        .font(.headline)
                }
                Text(model.store.root.path(percentEncoded: false))
                    .font(.caption).foregroundStyle(.tertiary)
                    .textSelection(.enabled).lineLimit(1).truncationMode(.head)
            }
            Spacer()
            Button("Révéler dans le Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([model.store.root])
            }
            .buttonStyle(.link)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem {
            Button { isNamingFolder = true } label: {
                Label("Nouveau dossier", systemImage: "folder.badge.plus")
            }
        }
        ToolbarItem {
            Button { isAdding = true } label: {
                Label("Ajouter", systemImage: "plus")
            }
        }
    }

    /// Said in terms of what the folder is for, since it is a real folder the user can
    /// also fill from the Finder.
    private var empty: some View {
        ContentUnavailableView {
            Label("Aucun script ni style", systemImage: "curlybraces")
        } description: {
            Text("""
            Ajoutez-en depuis une URL, ou déposez un fichier `.user.js` ou `.user.css` \
            directement dans le dossier. Tamis le retrouvera au prochain chargement.
            """)
        } actions: {
            Button("Ajouter depuis une URL…") { isAdding = true }
                .buttonStyle(.borderedProminent)
        }
    }

    private var tree: some View {
        List(model.nodes) { node in
            ScriptRow(node: node)
                .listRowInsets(.init(top: 4, leading: CGFloat(node.depth) * 18 + 8,
                                     bottom: 4, trailing: 8))
        }
    }
}

struct ScriptRow: View {
    @Environment(ScriptsModel.self) private var model
    let node: ScriptsModel.Node

    var body: some View {
        HStack(spacing: 10) {
            switch node.content {
            case .folder(let isEnabled):
                Image(systemName: "folder").foregroundStyle(.secondary)
                Text(node.name).fontWeight(.medium)
                Spacer()
                Toggle("Activer le dossier", isOn: .init(
                    get: { isEnabled },
                    set: { _ in Task { await model.toggle(node) } }
                ))
                .toggleStyle(.switch).labelsHidden()

            case .entry(let entry):
                Image(systemName: entry.kind == .script ? "curlybraces" : "paintbrush")
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(entry.name)
                        if entry.isLocallyModified {
                            Text("modifié").font(.caption2)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(.orange.opacity(0.15), in: .capsule)
                                .foregroundStyle(.orange)
                        }
                    }
                    // A script that is on but whose folder is off does not run, and the
                    // row has to say so — otherwise its own switch is a lie.
                    if entry.settings.isEnabled && !model.effectivelyEnabled.contains(entry.path) {
                        Text("désactivé par son dossier")
                            .font(.caption).foregroundStyle(.orange)
                    } else if !entry.settings.apps.isEmpty {
                        Text(entry.settings.apps.sorted().joined(separator: ", "))
                            .font(.caption).foregroundStyle(.tertiary)
                    }
                }
                Spacer()
                Toggle("Activer", isOn: .init(
                    get: { entry.settings.isEnabled },
                    set: { _ in Task { await model.toggle(node) } }
                ))
                .toggleStyle(.switch).labelsHidden()
            }
        }
        .contextMenu {
            if case .entry(let entry) = node.content {
                Button("Modifier…") { Task { await model.beginEditing(node.path) } }
                Button("Revenir à la version d'origine") {
                    Task { await model.revert(node.path) }
                }
                .disabled(!entry.isLocallyModified)
                Divider()
            }
            Button("Révéler dans le Finder") {
                NSWorkspace.shared.activateFileViewerSelecting(
                    [model.store.root.appending(path: node.path)]
                )
            }
            Button("Supprimer", role: .destructive) { Task { await model.delete(node.path) } }
        }
    }
}

/// Installing shows where the script came from and what it claims to match, before it
/// exists on disk — and it arrives switched off either way.
struct AddScriptSheet: View {
    @Environment(ScriptsModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var address = ""
    @State private var folder = ""
    @State private var isFetching = false

    private var url: URL? {
        guard let url = URL(string: address.trimmingCharacters(in: .whitespaces)),
              url.scheme == "https", url.host() != nil
        else { return nil }
        return url
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Ajouter un script ou un style").font(.headline)

            Form {
                TextField("Adresse", text: $address, prompt: Text("https://…/script.user.js"))
                TextField("Dossier", text: $folder, prompt: Text("racine"))
            }
            .formStyle(.grouped)

            Text("""
            Le fichier est téléchargé et installé **désactivé**. Lisez sa portée `@match` \
            avant de l'activer : un script s'exécute dans la page, sans isolation.
            """)
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            HStack {
                Spacer()
                Button("Annuler") { dismiss() }
                Button("Télécharger") {
                    guard let url else { return }
                    isFetching = true
                    Task {
                        await model.install(from: url, into: folder)
                        isFetching = false
                        dismiss()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(url == nil || isFetching)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}

struct ScriptEditorSheet: View {
    @Environment(ScriptsModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        @Bindable var model = model

        VStack(alignment: .leading, spacing: 12) {
            Text(model.editing?.path ?? "").font(.headline)

            TextEditor(text: .init(
                get: { model.editing?.text ?? "" },
                set: { model.editing?.text = $0 }
            ))
            .font(.system(.body, design: .monospaced))
            .frame(minWidth: 700, minHeight: 460)
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))

            if let problem = model.editorProblem {
                Label(
                    problem.line.map { "Ligne \($0) — \(problem.message)" } ?? problem.message,
                    systemImage: "exclamationmark.triangle"
                )
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Ouvrir dans un éditeur externe") {
                    guard let path = model.editing?.path else { return }
                    NSWorkspace.shared.open(model.store.root.appending(path: path))
                }
                .buttonStyle(.link)
                Spacer()
                Button("Annuler") { model.editing = nil; dismiss() }
                Button("Enregistrer") { Task { await model.saveEdit() } }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
    }
}
