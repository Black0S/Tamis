import Foundation
import JavaScriptCore
import Testing
import TamisFilterEngine
@testable import TamisProxy

@Suite("Cosmetic runtime")
struct CosmeticRuntimeTests {

    private func selectors(_ raw: [String]) -> [ProceduralSelector] {
        raw.compactMap(ProceduralSelector.parse)
    }

    @Test("nothing to run produces no script")
    func emptyProducesNothing() {
        #expect(CosmeticRuntime.script(for: []) == nil)
    }

    /// The runtime is 150 lines of JavaScript living in a Swift string literal, where a
    /// typo would surface only in a browser, on a user's machine. JavaScriptCore is a
    /// system framework, so checking it costs nothing.
    @Test("the generated script is valid JavaScript")
    func scriptIsValidJavaScript() throws {
        let script = try #require(CosmeticRuntime.script(for: selectors([
            ".ad:has-text(Publicité)",
            ".item:upward(2)",
            "div:has(.sponsored)",
            ".x:matches-css(display: none)",
            ".y:xpath(//div[@class='ad'])",
            ".z:remove()",
        ])))

        let context = try #require(JSContext())
        // Wrapping in a Function constructor parses the source without running it —
        // there is no DOM here, and executing would prove nothing anyway.
        context.evaluateScript("(function () { return new Function(arguments[0]); })")
        let checker = try #require(context.objectForKeyedSubscript("Function"))
        _ = checker.construct(withArguments: [script])

        if let exception = context.exception {
            Issue.record("runtime does not parse: \(exception)")
        }
    }

    @Test("the rules are embedded as data, not as code to be parsed in the page")
    func rulesAreData() throws {
        let script = try #require(CosmeticRuntime.script(for: selectors([".ad:has-text(Soldes)"])))
        #expect(script.contains("[[\".ad\",[[\"t\",\"Soldes\"]]]]"))
        #expect(!script.contains("__TAMIS_RULES__"))
    }

    /// A selector carrying a quote or a backslash must not be able to close the JSON
    /// literal and continue as code.
    @Test("hostile selector text cannot escape the payload", arguments: [
        ".ad:has-text(\");alert(1);//)",
        ".ad:has-text(</script><script>alert(1)</script>)",
        ".ad:has-text(\\\")",
    ])
    func injectionIsEscaped(selector: String) throws {
        guard let parsed = ProceduralSelector.parse(selector) else { return }
        let script = try #require(CosmeticRuntime.script(for: [parsed]))

        let context = try #require(JSContext())
        let checker = try #require(context.objectForKeyedSubscript("Function"))
        _ = checker.construct(withArguments: [script])
        #expect(context.exception == nil, "payload broke out: \(script.prefix(200))")
    }

    /// Every step is wrapped so a bad selector costs one rule, not the runtime. A
    /// blocker that throws in the console is, to the user, a blocker that broke the
    /// site.
    @Test("the runtime guards each rule and each step")
    func failuresAreContained() throws {
        let script = try #require(CosmeticRuntime.script(for: selectors([".a:has-text(x)"])))
        #expect(script.contains("try {"))
        #expect(script.contains("catch (e)"))
        // Dynamic content is re-examined, but coalesced rather than on every mutation.
        #expect(script.contains("MutationObserver"))
        #expect(script.contains("requestIdleCallback"))
    }

    /// A generic base on a large document can match tens of thousands of nodes, and
    /// walking them on every mutation would cost more than the adverts ever did.
    @Test("the element budget is enforced in the script")
    func budgetIsPresent() throws {
        let script = try #require(CosmeticRuntime.script(for: selectors([":has-text(x)"])))
        #expect(script.contains("BUDGET"))
        #expect(script.contains("\(CosmeticRuntime.elementBudget)"))
    }

    @Test("the payload stays small enough to send on every page")
    func payloadSize() throws {
        // Fifty procedural rules is well beyond what any single site carries.
        let many = (0..<50).map { ".ad-\($0):has-text(Publicité \($0))" }
        let script = try #require(CosmeticRuntime.script(for: selectors(many)))
        #expect(script.utf8.count < 12_000, "payload is \(script.utf8.count) bytes")
    }
}
