import Foundation
import Testing
@testable import TamisUserScripts

@Suite("Script store")
struct ScriptStoreTests {

    private func makeStore() throws -> ScriptStore {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-scripts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return ScriptStore(root: root)
    }

    private let sample = """
    // ==UserScript==
    // @name         YouTube sans Shorts
    // @match        https://www.youtube.com/*
    // ==/UserScript==
    document.title = "x";
    """

    @Test("An installed script is a real file with a readable name")
    func install() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "YouTube sans Shorts", kind: .script)
        #expect(path == "YouTube sans Shorts.user.js")
        #expect(try await store.text(at: path) == sample)

        let entries = await store.entries
        #expect(entries.count == 1)
        #expect(entries[0].name == "YouTube sans Shorts")
        #expect(entries[0].kind == .script)
    }

    /// A script arriving from a URL and running before anyone has read its `@match` is
    /// the one thing this must not do.
    @Test("A freshly installed script is off")
    func installedDisabled() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        #expect(await store.isEffectivelyEnabled(path) == false)
        #expect(await store.enabledScripts().isEmpty)
    }

    @Test("Enabling makes it run")
    func enable() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        try await store.setEnabled(true, at: path)
        #expect(await store.isEffectivelyEnabled(path))
        #expect(await store.enabledScripts().count == 1)
    }

    /// The tree in the interface is the tree on disk, so a folder switch has to reach
    /// what is inside it.
    @Test("A folder switch cascades")
    func folderCascade() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        try await store.createFolder("YouTube")
        let path = try await store.install(sample, named: "Test", kind: .script, in: "YouTube")
        try await store.setEnabled(true, at: path)
        #expect(await store.isEffectivelyEnabled(path))

        try await store.setFolderEnabled(false, at: "YouTube")
        #expect(await store.isEffectivelyEnabled(path) == false)
        #expect(await store.enabledScripts().isEmpty)

        try await store.setFolderEnabled(true, at: "YouTube")
        #expect(await store.isEffectivelyEnabled(path))
    }

    @Test("A nested folder switch reaches the bottom")
    func nestedCascade() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        try await store.createFolder("A/B")
        let path = try await store.install(sample, named: "Test", kind: .script, in: "A/B")
        try await store.setEnabled(true, at: path)
        try await store.setFolderEnabled(false, at: "A")
        #expect(await store.isEffectivelyEnabled(path) == false)
    }

    /// Reading scope out of the file would let an update overwrite a restriction the
    /// user set, and run a script somewhere they had excluded.
    @Test("Scope by application is settings, not file content")
    func appsAreSettings() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        try await store.setApps(["com.apple.Safari"], at: path)
        try await store.setEnabled(true, at: path)

        // An update replaces the text; the restriction survives it.
        try await store.applyUpdate(sample + "\n// nouvelle version", at: path)
        #expect(await store.entries.first?.settings.apps == ["com.apple.Safari"])
        #expect(await store.enabledScripts().first?.apps == ["com.apple.Safari"])
    }

    @Test("A local edit is detected, and reverting is free")
    func localModification() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        #expect(await store.entries.first?.isLocallyModified == false)

        try await store.write(sample + "\nconsole.log('modifié');", at: path)
        #expect(await store.entries.first?.isLocallyModified == true)

        try await store.revertToOriginal(at: path)
        #expect(try await store.text(at: path) == sample)
        #expect(await store.entries.first?.isLocallyModified == false)
    }

    @Test("An update proposes rather than applies")
    func updateIsProposed() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        let pending = try await store.pendingUpdate(at: path, newText: "// v2")
        #expect(pending.current == sample)
        #expect(pending.proposed == "// v2")
        // Nothing was written.
        #expect(try await store.text(at: path) == sample)
    }

    /// The whole point of using the filesystem: someone reorganises in the Finder and
    /// Tamis has to still know what it is looking at.
    @Test("A file dropped in from the Finder is picked up")
    func reconcilesNewFile() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        try await store.reload()
        let dropped = store.root.appending(path: "Manuel.user.js")
        try Data("// ==UserScript==\n// @name Manuel\n// ==/UserScript==\n".utf8).write(to: dropped)
        try await store.reload()

        let entries = await store.entries
        #expect(entries.map(\.name).contains("Manuel"))
        #expect(await store.isEffectivelyEnabled("Manuel.user.js") == false)
    }

    /// Keeping the settings of a deleted file would mean a script silently re-enabling
    /// itself the day the same name came back.
    @Test("A file deleted in the Finder takes its settings with it")
    func reconcilesDeletion() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        try await store.setEnabled(true, at: path)
        try FileManager.default.removeItem(at: store.root.appending(path: path))
        try await store.reload()

        #expect(await store.entries.isEmpty)
        #expect(await store.isEffectivelyEnabled(path) == false)
    }

    @Test("Moving a script keeps its settings, because it is the same script")
    func moveKeepsSettings() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        try await store.setEnabled(true, at: path)
        try await store.setApps(["com.apple.Safari"], at: path)
        try await store.createFolder("Rangé")
        try await store.move(from: path, to: "Rangé/Test.user.js")

        #expect(await store.isEffectivelyEnabled("Rangé/Test.user.js"))
        #expect(await store.entries.first?.settings.apps == ["com.apple.Safari"])
        // And the original travels with it, so reverting still works.
        #expect(await store.originalText(at: "Rangé/Test.user.js") == sample)
    }

    @Test("Settings survive a restart")
    func settingsPersist() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let path = try await store.install(sample, named: "Test", kind: .script)
        try await store.setEnabled(true, at: path)

        let reopened = ScriptStore(root: store.root)
        try await reopened.reload()
        #expect(await reopened.isEffectivelyEnabled(path))
    }

    @Test("Styles and scripts are kept apart")
    func kinds() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        let script = try await store.install(sample, named: "S", kind: .script)
        let style = try await store.install("body { color: red }", named: "T", kind: .style)
        try await store.setEnabled(true, at: script)
        try await store.setEnabled(true, at: style)

        #expect(await store.enabledScripts().map(\.path) == [script])
        #expect(await store.enabledStyles().map(\.path) == [style])
    }

    @Test("Installing the same name twice is refused rather than silently overwriting")
    func duplicate() async throws {
        let store = try makeStore()
        defer { Task { try? FileManager.default.removeItem(at: store.root) } }

        _ = try await store.install(sample, named: "Test", kind: .script)
        await #expect(throws: ScriptStore.Failure.alreadyExists("Test.user.js")) {
            _ = try await store.install(sample, named: "Test", kind: .script)
        }
    }
}

@Suite("Script validation")
struct ScriptValidatorTests {

    /// Parsed, never run. If this compiled by executing, the expression below would
    /// throw and the test would still pass — so it is written to fail loudly instead.
    @Test("A valid script passes without executing")
    func validScript() {
        #expect(ScriptValidator.validate("const x = 1; document.title = x;", kind: .script) == nil)
        // `throw` at the top level of a function body parses fine and must not run.
        #expect(ScriptValidator.validate("throw new Error('ne doit pas s\\'exécuter')", kind: .script) == nil)
    }

    @Test("A syntax error is caught and described", arguments: [
        "const x = ;",
        "function () {",
        "if (true) { console.log('x'",
    ])
    func invalidScript(source: String) {
        let problem = ScriptValidator.validate(source, kind: .script)
        #expect(problem != nil)
        #expect(problem?.message.isEmpty == false)
    }

    @Test("Balanced CSS passes")
    func validCSS() {
        #expect(ScriptValidator.validate("body { color: red }", kind: .style) == nil)
        #expect(ScriptValidator.validate("@media (min-width: 1px) { a { b: c } }", kind: .style) == nil)
        // Braces inside strings and comments are not braces.
        #expect(ScriptValidator.validate("a { content: \"{\" } /* } */", kind: .style) == nil)
    }

    /// The mistake that actually happens by hand, and the one that silently swallows
    /// every rule after it.
    @Test("An unclosed brace is reported")
    func unbalancedCSS() {
        #expect(ScriptValidator.validate("body { color: red", kind: .style) != nil)
        #expect(ScriptValidator.validate("body { } }", kind: .style)?.line == 1)
    }
}
