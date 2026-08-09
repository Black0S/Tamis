import Foundation
import JavaScriptCore
import Testing
import TamisFilterEngine
@testable import TamisProxy

@Suite("Scriptlet parsing")
struct ScriptletParsingTests {

    @Test("name and arguments are separated")
    func basic() throws {
        let scriptlet = try #require(Scriptlet.parse("set-constant, adsShown, true"))
        #expect(scriptlet.name == "set-constant")
        #expect(scriptlet.arguments == ["adsShown", "true"])
    }

    /// Real rules pass regular expressions and JSON paths, where a comma belongs to the
    /// argument rather than separating it.
    @Test("a comma inside quotes does not split the arguments")
    func quotedCommas() throws {
        let scriptlet = try #require(Scriptlet.parse(#"json-prune, "a,b", 'c,d'"#))
        #expect(scriptlet.arguments == ["a,b", "c,d"])
    }

    @Test("aliases and the .js suffix normalise to one name", arguments: [
        ("aopr, x", "abort-on-property-read"),
        ("abort-on-property-read.js, x", "abort-on-property-read"),
        ("acs, x", "abort-current-script"),
        ("set, x, 1", "set-constant"),
        ("nostif, x", "prevent-settimeout"),
        ("ra, href, a", "remove-attr"),
    ])
    func aliases(body: String, expected: String) throws {
        let scriptlet = try #require(Scriptlet.parse(body))
        #expect(scriptlet.name == expected)
    }

    @Test("an empty invocation is refused")
    func empty() {
        #expect(Scriptlet.parse("") == nil)
        #expect(Scriptlet.parse("  ") == nil)
    }
}

@Suite("Scriptlet library")
struct ScriptletLibraryTests {

    private func parse(_ bodies: [String]) -> [Scriptlet] {
        bodies.compactMap(Scriptlet.parse)
    }

    /// The library is JavaScript in Swift string literals, where a typo surfaces only
    /// in a browser on someone else's machine.
    @Test("every implementation is valid JavaScript", arguments: ScriptletLibrary.supported.sorted())
    func implementationsParse(name: String) throws {
        let body = try #require(ScriptletLibrary.implementations[name])
        let context = try #require(JSContext())
        let function = try #require(context.objectForKeyedSubscript("Function"))
        _ = function.construct(withArguments: ["args", body])
        if let exception = context.exception {
            Issue.record("\(name) does not parse: \(exception)")
        }
    }

    @Test("the assembled script parses as a whole")
    func assembledScriptParses() throws {
        let result = try #require(ScriptletLibrary.script(for: parse([
            "abort-on-property-read, adsbygoogle",
            "set-constant, canRunAds, true",
            "nowebrtc",
            "remove-attr, onclick, a",
        ])))
        let context = try #require(JSContext())
        let function = try #require(context.objectForKeyedSubscript("Function"))
        _ = function.construct(withArguments: [result.source])
        #expect(context.exception == nil, "\(String(describing: context.exception))")
        #expect(result.skipped.isEmpty)
    }

    /// Running an approximation of a scriptlet is how a page breaks in a way nobody can
    /// attribute, so an unknown name is reported rather than guessed at.
    @Test("an unimplemented scriptlet is reported, not approximated")
    func unknownIsReported() throws {
        let result = try #require(ScriptletLibrary.script(for: parse([
            "set-constant, x, true",
            "some-scriptlet-we-do-not-have, y",
        ])))
        #expect(result.skipped == ["some-scriptlet-we-do-not-have"])
        #expect(result.source.contains("set-constant") == false)  // names are not emitted
        #expect(!result.source.isEmpty)
    }

    /// Arguments carrying quotes or a closing script tag must not escape the payload.
    @Test("hostile arguments cannot break out", arguments: [
        #"set-constant, x, ");alert(1);//"#,
        "set-constant, x, </script><script>alert(1)</script>",
    ])
    func argumentsAreEscaped(body: String) throws {
        let result = try #require(ScriptletLibrary.script(for: parse([body])))
        let context = try #require(JSContext())
        let function = try #require(context.objectForKeyedSubscript("Function"))
        _ = function.construct(withArguments: [result.source])
        #expect(context.exception == nil)
    }

    /// One scriptlet that throws must cost its own rule and nothing else.
    @Test("each scriptlet is wrapped independently")
    func failuresAreContained() throws {
        let result = try #require(ScriptletLibrary.script(for: parse([
            "set-constant, a, 1", "nowebrtc",
        ])))
        #expect(result.source.components(separatedBy: "try {").count - 1 >= 2)
    }

    @Test("nothing to run produces nothing")
    func nothingToRun() {
        #expect(ScriptletLibrary.script(for: []) == nil)
    }
}
