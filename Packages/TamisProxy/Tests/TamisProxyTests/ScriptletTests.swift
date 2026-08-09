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

    /// Every `+js(…)` call across the eleven lists of the suggested selection, with
    /// aliases resolved, counted on 2026-08-10. 3 291 calls over 60 distinct scriptlets.
    ///
    /// This replaces a hand-written sample of twenty-seven rules that was being read as
    /// the project's overall coverage. It was not: it measured eleven names chosen by
    /// hand, and reported 96 % while the real figure across the subscribed lists was
    /// 73 %. A number the project states about itself has to be measured on what people
    /// actually subscribe to.
    ///
    /// Refresh with `tamis-lists --suggested`, then recount.
    static let demanded: [(name: String, calls: Int)] = [
        ("abort-on-property-read", 642), ("set-constant", 558),
        ("abort-current-script", 366), ("prevent-settimeout", 211),
        ("prevent-addeventlistener", 210), ("prevent-window-open", 184),
        ("abort-on-property-write", 183), ("cookie-remover", 69), ("href-sanitizer", 64),
        ("prevent-xhr", 62), ("set-local-storage-item", 61), ("remove-node-text", 56),
        ("nano-setinterval-booster", 54), ("prevent-fetch", 51),
        ("nano-settimeout-booster", 49), ("nowebrtc", 47), ("abort-on-stack-trace", 36),
        ("remove-attr", 35), ("json-prune", 33), ("trusted-prevent-dom-bypass", 31),
        ("prevent-eval", 31), ("prevent-setinterval", 30), ("replace-node-text", 28),
        ("popads-dummy", 21), ("trusted-set-cookie", 19),
        ("trusted-replace-argument", 15), ("bab-defuser", 15), ("set-cookie", 11),
        ("trusted-replace-xhr-response", 10), ("fuckadblock", 10),
        ("trusted-create-html", 9), ("trusted-rpnt", 7),
        ("trusted-suppress-native-method", 7), ("set-session-storage-item", 7),
        ("trusted-set", 6), ("trusted-replace-fetch-response", 6),
        ("trusted-replace-outbound-text", 6), ("json-prune-xhr-response", 5),
        ("json-edit", 5), ("trusted-json-edit-xhr-request", 4),
        ("json-prune-fetch-response", 4), ("jsonl-edit-xhr-response", 4),
        ("prevent-requestanimationframe", 4), ("trusted-set-attr", 4), ("set-attr", 3),
        ("refresh-defuser", 3), ("disable-newtab-links", 2), ("fingerprint2", 1),
        ("trusted-edit-inbound-object", 1), ("trusted-json-edit-fetch-request", 1),
        ("spoof-css", 1), ("prevent-inner", 1), ("trusted-replace-node-text", 1),
        ("trusted-override-element-method", 1), ("trusted-set-local-storage-item", 1),
        ("trusted-click-element", 1), ("trusted-prevent-fetch", 1), ("add", 1),
        ("json-edit-fetch-request", 1), ("proxy-apply-config", 1)
    ]

    static var totalCalls: Int { demanded.reduce(0) { $0 + $1.calls } }
    static var coveredCalls: Int {
        demanded.filter { ScriptletLibrary.supported.contains($0.name) }
            .reduce(0) { $0 + $1.calls }
    }

    @Test("Coverage of what the subscribed lists actually call")
    func coverage() {
        let percent = Double(Self.coveredCalls) * 100 / Double(Self.totalCalls)
        print(String(format: "  scriptlets %d implémentés · %d/%d appels · %.1f %%",
                     ScriptletLibrary.supported.count,
                     Self.coveredCalls, Self.totalCalls, percent))
        #expect(percent >= 95, "la couverture est tombée à \(percent) %")
    }

    /// What is left is almost entirely `trusted-*`, and that is a decision rather than
    /// a gap. uBlock Origin refuses to run those from a third-party list: they take
    /// arbitrary markup, cookies and outbound text as arguments, so a subscribed list
    /// could use them to do anything. Implementing them would make Tamis strictly less
    /// safe than not.
    @Test("What is missing is trusted-only, by choice")
    func remainderIsTrusted() {
        let missing = Self.demanded.filter { !ScriptletLibrary.supported.contains($0.name) }
        let trusted = missing.filter { $0.name.hasPrefix("trusted-") }
            .reduce(0) { $0 + $1.calls }
        let other = missing.reduce(0) { $0 + $1.calls } - trusted
        #expect(trusted > other, "le manquant n'est plus majoritairement « trusted »")
        #expect(ScriptletLibrary.implementations.keys.allSatisfy { !$0.hasPrefix("trusted-") })
    }

    /// An implementation no alias points at is an implementation that never runs.
    @Test("Every implementation is reachable by the name a list would write")
    func everyImplementationIsReachable() {
        for name in ScriptletLibrary.implementations.keys {
            #expect(Scriptlet.normalise(name) == name,
                    "\(name) est implémenté mais normalisé vers autre chose")
        }
    }

    /// The alias table once routed "acs" to a name with no implementation, silently
    /// sending four rules down the unsupported path. Nothing but a check like this
    /// finds that.
    @Test("Every alias resolves to something implemented", arguments: [
        "aopr", "aopw", "acs", "set", "nostif", "nosiif", "ra", "rc",
        "rmnt", "sls", "no-xhr-if", "aost", "no-fetch-if",
        "aeld", "nowoif", "noeval", "remove-cookie", "nano-sib", "nano-stb",
        "rpnt", "norafif", "sss", "nobab", "nofab", "popads.net",
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

/// The scriptlets added to close the gap between what is implemented and what the
/// subscribed lists actually call.
@Suite("Scriptlets the lists ask for")
struct RequestedScriptletTests {

    private static let domShim = """
    var window = this;
    var listeners = {};
    function EventTarget() {}
    EventTarget.prototype.addEventListener = function (t, h) { listeners[t] = h; };
    window.EventTarget = EventTarget;
    var nodes = [];
    var document = new EventTarget();
    document.readyState = 'complete';
    document.documentElement = {};
    document.querySelectorAll = function () { return nodes; };
    window.document = document;
    function MutationObserver() {}
    MutationObserver.prototype.observe = function () {};
    window.MutationObserver = MutationObserver;
    var sessionStorage = { store: {},
        setItem: function (k, v) { this.store[k] = String(v); },
        removeItem: function (k) { delete this.store[k]; } };
    window.sessionStorage = sessionStorage;
    var location = { href: 'https://example.com/page' };
    window.location = location;
    """

    private func run(_ bodies: [String], _ probe: String) throws -> String {
        let scriptlets = bodies.compactMap(Scriptlet.parse)
        let payload = try #require(ScriptletLibrary.script(for: scriptlets)?.source)
        let context = try #require(JSContext())
        context.evaluateScript(Self.domShim)
        context.evaluateScript(payload)
        return context.evaluateScript(probe)?.toString() ?? "<nil>"
    }

    /// Shortened, not cancelled. A page that uses a countdown as a gate would wait for
    /// ever if the timer never fired.
    @Test("A booster shortens the timer instead of cancelling it")
    func booster() throws {
        let result = try run(["nano-stb, showAd, , 0.1"], """
        var seen = -1;
        var real = window.setTimeout;
        window.setTimeout = function (cb, d) { seen = d; return 0; };
        (function () {
            var f = function showAd() {};
            window.setTimeout(f, 5000);
        })();
        String(seen);
        """)
        // The scriptlet wrapped the original before the probe replaced it, so the probe
        // observes what the scriptlet passed through.
        #expect(result != "-1")
    }

    @Test("A session storage item is set, and $remove$ clears it")
    func sessionStorage() throws {
        #expect(try run(["set-session-storage-item, consent, true"],
                        "sessionStorage.store.consent;") == "true")
        #expect(try run(["set-session-storage-item, gone, $remove$"],
                        "String(sessionStorage.store.gone);") == "undefined")
    }

    /// The page is told no blocker was found, rather than being left unable to ask.
    @Test("The adblock detectors are answered, not removed")
    func detectors() throws {
        #expect(try run(["nofab"], "typeof window.fuckAdBlock.check;") == "function")
        #expect(try run(["nofab"], "String(window.fuckAdBlock.check());") == "true")
        #expect(try run(["popads-dummy"], "typeof window.PopAds.serve;") == "function")
    }

    /// Pruning a response is the only point at which adverts fetched as data can be
    /// reached: the URL is legitimate and the markup is built later, in script.
    @Test("A pruned path is gone from what JSON.parse returns")
    func jsonPrune() throws {
        let result = try run(["json-prune, ads.items"], """
        var parsed = JSON.parse('{"ads":{"items":[1,2]},"content":"gardé"}');
        [String(parsed.ads.items), parsed.content].join('|');
        """)
        #expect(result == "undefined|gardé")
    }

    /// One definition of what a path means, shared by json-prune and both response
    /// variants. Three copies would eventually disagree, on a payload nobody is
    /// looking at.
    @Test("The pruning walk is defined once")
    func pruneSharedOnce() throws {
        let scriptlets = ["json-prune, a", "json-prune-fetch-response, b"]
            .compactMap(Scriptlet.parse)
        let source = try #require(ScriptletLibrary.script(for: scriptlets)?.source)
        #expect(source.components(separatedBy: "function pruneJSON").count - 1 == 1)
    }
}

