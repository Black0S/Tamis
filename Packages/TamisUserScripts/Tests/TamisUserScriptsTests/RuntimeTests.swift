import Foundation
import JavaScriptCore
import Testing
@testable import TamisUserScripts

private func script(
    name: String = "X",
    runAt: String = "document-start",
    grants: [String] = [],
    requires: [String] = [],
    body: String = "console.log(1);"
) throws -> UserScript {
    var metadata = "// @name \(name)\n// @match *://example.com/*\n// @run-at \(runAt)\n"
    for grant in grants { metadata += "// @grant \(grant)\n" }
    for require in requires { metadata += "// @require \(require)\n" }
    return try UserScript.parse("// ==UserScript==\n\(metadata)// ==/UserScript==\n\(body)")
}

@Suite("User script runtime")
struct UserScriptRuntimeTests {

    private func parses(_ source: String) throws -> Bool {
        let context = try #require(JSContext())
        let function = try #require(context.objectForKeyedSubscript("Function"))
        _ = function.construct(withArguments: [source])
        return context.exception == nil
    }

    @Test("nothing matching produces nothing")
    func empty() {
        #expect(UserScriptRuntime.assemble(scripts: []) == nil)
    }

    /// The shim is JavaScript in a Swift string literal, where a typo would surface
    /// only in a browser on someone else's machine.
    @Test("the assembled payload is valid JavaScript")
    func payloadParses() throws {
        let assembly = try #require(UserScriptRuntime.assemble(scripts: [
            try script(name: "A", runAt: "document-start"),
            try script(name: "B", runAt: "document-idle", body: "GM_addStyle('.x{}');"),
        ]))
        #expect(try parses(assembly.source))
    }

    /// Injection happens once, at the top of the document, so later timings are
    /// reproduced with the matching event rather than by injecting again.
    @Test("run-at is honoured through events")
    func runAtWrapping() throws {
        let assembly = try #require(UserScriptRuntime.assemble(scripts: [
            try script(runAt: "document-end"),
        ]))
        #expect(assembly.source.contains("DOMContentLoaded"))
        #expect(assembly.source.contains("\"document-end\""))
    }

    /// No isolated world is the one real advantage of running from a proxy: scripts
    /// that manipulate the page's own globals work without ceremony.
    @Test("unsafeWindow is simply window")
    func unsafeWindowIsWindow() throws {
        let assembly = try #require(UserScriptRuntime.assemble(scripts: [try script()]))
        #expect(assembly.source.contains("body(api.info, window,"))
    }

    /// A user script that throws where the page can see it is, to the user,
    /// indistinguishable from Tamis breaking the site.
    @Test("each script is wrapped so one failure costs one script")
    func failuresAreContained() throws {
        let assembly = try #require(UserScriptRuntime.assemble(scripts: [try script()]))
        #expect(assembly.source.contains("try {"))
        #expect(assembly.source.contains("console.error(\"[Tamis] \""))
    }

    /// Its purpose is to bypass CORS, which needs the proxy to perform the request
    /// natively. Reporting beats a fetch that will simply be refused.
    @Test("an unimplemented grant is reported, not silently ignored")
    func unsupportedGrant() throws {
        let assembly = try #require(UserScriptRuntime.assemble(scripts: [
            try script(name: "Needs more", grants: ["GM_xmlhttpRequest", "GM_addStyle"]),
        ]))
        #expect(assembly.unsupportedGrants.map(\.grant) == ["GM_xmlhttpRequest"])
        #expect(assembly.unsupportedGrants.map(\.script) == ["Needs more"])
    }

    /// Running a script whose libraries are missing fails inside the page with an error
    /// nobody can attribute, so it is skipped instead.
    @Test("a script with unresolved requirements is skipped")
    func missingRequires() throws {
        let needy = try script(name: "Needy", requires: ["https://example.com/lib.js"])
        #expect(UserScriptRuntime.assemble(scripts: [needy]) == nil)

        let assembly = try #require(UserScriptRuntime.assemble(
            scripts: [needy],
            resolvedRequires: [URL(string: "https://example.com/lib.js")!: "var lib = 1;"]
        ))
        #expect(assembly.source.contains("var lib = 1;"))
    }

    /// A name carrying quotes or a closing script tag must not escape the payload.
    @Test("hostile script metadata cannot break out", arguments: [
        #"A");alert(1);//"#,
        "A</script><script>alert(1)</script>",
    ])
    func metadataIsEscaped(name: String) throws {
        let assembly = try #require(UserScriptRuntime.assemble(scripts: [try script(name: name)]))
        #expect(try parses(assembly.source))
    }

    @Test("stored values are namespaced per script")
    func storageIsNamespaced() throws {
        let assembly = try #require(UserScriptRuntime.assemble(scripts: [try script()]))
        #expect(assembly.source.contains("tamis.gm."))
        #expect(assembly.source.contains("STORAGE_PREFIX + id"))
    }
}
