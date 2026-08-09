import Foundation
import Observation
import TamisUserScripts

/// Drives the Scripts screen.
@MainActor
@Observable
final class ScriptsModel {

    /// One row of the tree. Folders and files share a list because they share a
    /// hierarchy and a switch, and splitting them would put the same folder in two
    /// places on screen.
    struct Node: Identifiable, Sendable {
        enum Content: Sendable {
            case folder(isEnabled: Bool)
            case entry(ScriptStore.Entry)
        }
        let path: String
        let name: String
        let depth: Int
        let content: Content

        var id: String { path }
        var isFolder: Bool { if case .folder = content { true } else { false } }
    }

    let store: ScriptStore
    private(set) var nodes: [Node] = []
    private(set) var effectivelyEnabled: Set<String> = []
    var lastError: String?

    /// The script being edited, if any. Held here rather than in the view so a failed
    /// save keeps the text the user typed instead of discarding it.
    var editing: (path: String, text: String)?
    var editorProblem: ScriptValidator.Problem?

    init(store: ScriptStore) {
        self.store = store
    }

    static func makeDefault() -> ScriptsModel {
        let root = ProcessInfo.processInfo.environment["TAMIS_SCRIPTS"].map(URL.init(fileURLWithPath:))
            ?? (try? ScriptStore.defaultRoot())
            ?? URL(fileURLWithPath: NSTemporaryDirectory()).appending(path: "Tamis/Scripts")
        return ScriptsModel(store: ScriptStore(root: root))
    }

    var isEmpty: Bool { nodes.isEmpty }
    var scriptCount: Int { nodes.count { if case .entry = $0.content { true } else { false } } }
    var enabledCount: Int { effectivelyEnabled.count }

    // MARK: Loading

    func reload() async {
        do {
            try await store.reload()
            let entries = await store.entries
            let folders = await store.folders

            var enabled: Set<String> = []
            for entry in entries where await store.isEffectivelyEnabled(entry.path) {
                enabled.insert(entry.path)
            }
            effectivelyEnabled = enabled
            nodes = Self.tree(entries: entries, folders: folders)
        } catch {
            lastError = "\(error)"
        }
    }

    /// Flattens the two lists into one ordered, indented tree.
    static func tree(entries: [ScriptStore.Entry], folders: [ScriptStore.Folder]) -> [Node] {
        var byParent: [String: [Node]] = [:]

        for folder in folders {
            let parent = folder.path.split(separator: "/").dropLast().joined(separator: "/")
            byParent[parent, default: []].append(Node(
                path: folder.path, name: folder.name,
                depth: folder.path.split(separator: "/").count - 1,
                content: .folder(isEnabled: folder.isEnabled)
            ))
        }
        for entry in entries {
            byParent[entry.folder, default: []].append(Node(
                path: entry.path, name: entry.name,
                depth: entry.path.split(separator: "/").count - 1,
                content: .entry(entry)
            ))
        }

        // Folders before files at each level, then alphabetical — the order the Finder
        // uses, because this is the Finder's tree.
        func children(of parent: String) -> [Node] {
            (byParent[parent] ?? [])
                .sorted { a, b in
                    a.isFolder == b.isFolder
                        ? a.name.localizedStandardCompare(b.name) == .orderedAscending
                        : a.isFolder
                }
                .flatMap { [$0] + ($0.isFolder ? children(of: $0.path) : []) }
        }
        return children(of: "")
    }

    // MARK: Acting

    func toggle(_ node: Node) async {
        do {
            switch node.content {
            case .folder(let isEnabled):
                try await store.setFolderEnabled(!isEnabled, at: node.path)
            case .entry(let entry):
                try await store.setEnabled(!entry.settings.isEnabled, at: node.path)
            }
            await reload()
        } catch {
            lastError = "\(error)"
        }
    }

    func createFolder(named name: String) async {
        do {
            try await store.createFolder(name)
            await reload()
        } catch {
            lastError = "\(error)"
        }
    }

    func delete(_ path: String) async {
        do {
            try await store.delete(path)
            await reload()
        } catch {
            lastError = "\(error)"
        }
    }

    func revert(_ path: String) async {
        do {
            try await store.revertToOriginal(at: path)
            await reload()
        } catch {
            lastError = "Aucune version d'origine conservée pour ce fichier."
        }
    }

    /// Downloads and installs, switched off. See ``ScriptStore/install(_:named:kind:in:sourceURL:now:)``.
    func install(from url: URL, into folder: String) async {
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                lastError = "Le serveur n'a pas renvoyé le fichier."
                return
            }
            guard let text = String(data: data, encoding: .utf8) else {
                lastError = "Le fichier n'est pas du texte UTF-8."
                return
            }
            let kind: ScriptStore.Kind = url.absoluteString.contains(".css") ? .style : .script
            let name = ScriptStore.name(
                of: text, kind: kind,
                fallback: url.deletingPathExtension().lastPathComponent
            )
            _ = try await store.install(text, named: name, kind: kind, in: folder, sourceURL: url)
            await reload()
        } catch {
            lastError = "\(error)"
        }
    }

    // MARK: Editing

    func beginEditing(_ path: String) async {
        do {
            editing = (path, try await store.text(at: path))
            editorProblem = nil
        } catch {
            lastError = "\(error)"
        }
    }

    /// Refuses to save a file that does not parse.
    ///
    /// A script with a syntax error is not a script that does less; it is a script that
    /// does nothing, silently, on every page it claims to match.
    func saveEdit() async {
        guard let editing else { return }
        let kind: ScriptStore.Kind = editing.path.hasSuffix(".user.js") ? .script : .style
        if let problem = ScriptValidator.validate(editing.text, kind: kind) {
            editorProblem = problem
            return
        }
        do {
            try await store.write(editing.text, at: editing.path)
            self.editing = nil
            editorProblem = nil
            await reload()
        } catch {
            lastError = "\(error)"
        }
    }
}
