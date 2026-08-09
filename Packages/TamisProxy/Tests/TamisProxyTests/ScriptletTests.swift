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

@Suite("Scriptlet coverage")
struct ScriptletCoverageTests {

    /// The names EasyList and EasyPrivacy actually invoke, with the count of rules
    /// behind each. Kept here so a coverage regression fails a test rather than being
    /// noticed months later.
    static let demanded: [(name: String, rules: Int)] = [
        ("set-constant", 6), ("remove-node-text", 4), ("abort-current-script", 4),
        ("set-local-storage-item", 3), ("abort-on-stack-trace", 3), ("prevent-xhr", 2),
        ("set-cookie", 1), ("set-attr", 1), ("prevent-fetch", 1), ("cookie-remover", 1),
        ("json-edit", 1),
    ]

    @Test("everything the lists ask for is implemented, except what is documented")
    func coverage() {
        let unsupported = Self.demanded
            .filter { !ScriptletLibrary.supported.contains($0.name) }
            .map(\.name)
        // json-edit takes a JSONPath expression with recursive descent and a filter
        // predicate. A partial implementation would delete the wrong nodes from JSON
        // the page depends on, which is worse than not running it.
        #expect(unsupported == ["json-edit"])

        let total = Self.demanded.reduce(0) { $0 + $1.rules }
        let covered = Self.demanded
            .filter { ScriptletLibrary.supported.contains($0.name) }
            .reduce(0) { $0 + $1.rules }
        #expect(covered * 100 / total >= 96, "coverage fell to \(covered)/\(total)")
    }

    /// The alias table once routed "acs" to a name with no implementation, silently
    /// sending four rules down the unsupported path. Nothing but a check like this
    /// finds that.
    @Test("every alias resolves to something implemented", arguments: [
        "aopr", "aopw", "acs", "set", "nostif", "nosiif", "ra", "rc",
        "rmnt", "sls", "no-xhr-if", "aost", "no-fetch-if",
    ])
    func aliasesResolve(alias: String) throws {
        let scriptlet = try #require(Scriptlet.parse("\(alias), a, b"))
        #expect(
            ScriptletLibrary.supported.contains(scriptlet.name),
            "\(alias) resolves to \(scriptlet.name), which has no implementation"
        )
    }
}

/// The four scriptlets added after measuring what the enabled lists actually call.
///
/// Executed in JavaScriptCore rather than inspected: a scriptlet that parses and does
/// nothing is indistinguishable from a working one by reading it, and these run inside
/// the page where a mistake breaks the site rather than merely failing to block.
@Suite("Scriptlets that intercept")
struct InterceptingScriptletTests {

    /// Just enough browser for the scriptlets to have something to intercept.
    ///
    /// JavaScriptCore has no DOM: `window`, `document` and `EventTarget` do not exist,
    /// so a scriptlet that hooks them throws and the payload's own try/catch swallows
    /// it. That is exactly why the existing test — which only checks that each body
    /// *parses* — could pass while none of them did anything.
    private static let domShim = """
    // `window` is the global object here, so it already carries the real `eval`.
    // Shimming it would have the shim call itself.
    var window = this;
    function EventTarget() {}
    EventTarget.prototype.addEventListener = function () { this.__added = true; };
    window.EventTarget = EventTarget;
    var document = new EventTarget();
    window.document = document;
    window.open = function () { return { real: true }; };
    """

    private func evaluate(_ bodies: [String], then probe: String) throws -> JSValue? {
        let scriptlets = bodies.compactMap(Scriptlet.parse)
        let payload = try #require(ScriptletLibrary.script(for: scriptlets)?.source)

        let context = try #require(JSContext())
        context.evaluateScript(Self.domShim)
        context.evaluateScript(payload)
        if let exception = context.exception {
            Issue.record("le payload ne s'évalue pas : \(exception)")
        }
        return context.evaluateScript(probe)
    }

    /// The registration is swallowed, not the event. Removing the listener later would
    /// leave the page believing it had installed one.
    @Test("addEventListener-defuser stops the matching listener being added")
    func preventAddEventListener() throws {
        let value = try evaluate(
            ["aeld, click, badHandler"],
            then: """
            var calls = 0;
            document.addEventListener('click', function badHandler() { calls++; });
            document.addEventListener('click', function keepMe() { calls += 10; });
            [typeof document.addEventListener, calls].join(',');
            """
        )
        #expect(value?.toString() == "function,0")
    }

    /// A stub, not null. Pages routinely call methods on the window they think they
    /// opened, and null turns a blocked popup into a broken page.
    @Test("window.open returns a usable stub rather than null")
    func preventWindowOpen() throws {
        let value = try evaluate(
            ["nowoif, /ads/"],
            then: """
            var blocked = window.open('https://x.test/ads/1');
            var allowed = window.open('https://x.test/normal').real;
            blocked === null ? 'null' : [typeof blocked.close, blocked.closed, allowed].join(',');
            """
        )
        #expect(value?.toString().hasPrefix("function,true") == true)
    }

    @Test("noeval only swallows the matching source")
    func preventEval() throws {
        let value = try evaluate(
            ["noeval, tracker"],
            then: """
            var blocked = window.eval('1 + 1; // tracker');
            var kept = window.eval('2 + 3');
            [String(blocked), String(kept)].join(',');
            """
        )
        #expect(value?.toString() == "undefined,5")
    }

    /// Three forms, three meanings. Getting this right in one scriptlet and wrong in
    /// another is how a rule stops working on one site and not the next.
    @Test("The needle understands empty, regex and negation")
    func matcherForms() throws {
        // Empty matches everything.
        let all = try evaluate(
            ["noeval"],
            then: "String(window.eval('1 + 1'));"
        )
        #expect(all?.toString() == "undefined")

        // A leading ! inverts.
        let negated = try evaluate(
            ["noeval, !keep"],
            then: "[String(window.eval('1 + 1 /* keep */')), String(window.eval('2 + 2'))].join(',');"
        )
        #expect(negated?.toString() == "2,undefined")
    }
}
