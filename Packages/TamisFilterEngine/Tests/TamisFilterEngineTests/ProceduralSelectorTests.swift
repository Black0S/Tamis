import Testing
@testable import TamisFilterEngine

@Suite("Procedural selectors")
struct ProceduralSelectorTests {

    @Test("the plain CSS prefix is separated from the operations")
    func basicSplit() throws {
        let selector = try #require(ProceduralSelector.parse(".ad-slot:has-text(Publicité)"))
        #expect(selector.base == ".ad-slot")
        #expect(selector.operations == [.hasText("Publicité")])
    }

    @Test("an ordinary pseudo-class stays in the base selector")
    func pseudoClassesStay() throws {
        let selector = try #require(ProceduralSelector.parse("div:first-child:has-text(Ad)"))
        #expect(selector.base == "div:first-child")
        #expect(selector.operations == [.hasText("Ad")])
    }

    @Test("operations chain in order")
    func chaining() throws {
        let selector = try #require(
            ProceduralSelector.parse(".item:has-text(Sponsorisé):upward(2)")
        )
        #expect(selector.operations == [.hasText("Sponsorisé"), .upwardDepth(2)])
    }

    /// `:has(:not(.x))` is ordinary in real lists, and stopping at the first `)` would
    /// silently truncate the argument into something that matches the wrong elements.
    @Test("nested parentheses are matched, not truncated")
    func nestedParentheses() throws {
        let selector = try #require(ProceduralSelector.parse("div:has(:not(.keep))"))
        #expect(selector.operations == [.has(":not(.keep)")])
    }

    @Test("every supported operation parses", arguments: [
        (".a:has(.b)", ProceduralSelector.Operation.has(".b")),
        (".a:has-text(x)", .hasText("x")),
        (".a:contains(x)", .hasText("x")),
        (".a:matches-css(display: none)", .matchesCSS(property: "display", value: "none")),
        (".a:matches-attr(data-ad)", .matchesAttr(name: "data-ad", value: nil)),
        (".a:matches-attr(data-ad=\"1\")", .matchesAttr(name: "data-ad", value: "1")),
        (".a:min-text-length(20)", .minTextLength(20)),
        (".a:upward(3)", .upwardDepth(3)),
        (".a:upward(.card)", .upwardSelector(".card")),
        (".a:nth-ancestor(2)", .upwardDepth(2)),
        (".a:xpath(//div)", .xpath("//div")),
        (".a:remove()", .remove),
    ])
    func operations(selector: String, expected: ProceduralSelector.Operation) throws {
        let parsed = try #require(ProceduralSelector.parse(selector))
        #expect(parsed.operations == [expected])
    }

    @Test("a regular expression argument keeps its flags")
    func regexArgument() throws {
        let selector = try #require(ProceduralSelector.parse(".a:has-text(/spons?or/i)"))
        #expect(selector.operations == [.hasTextPattern(pattern: "spons?or", flags: "i")])
    }

    /// Refusing beats approximating: a selector we half-understand hides the wrong
    /// element, which reads as a broken site rather than as a missing filter.
    @Test("anything unsupported or malformed is refused", arguments: [
        ".ad",                              // no procedural part at all
        ".a:has-text(",                     // unterminated
        ".a:min-text-length(abc)",          // not a number
        ".a:upward(0)",                     // would not move
        ".a:upward(9999)",                  // would climb out of the document
        ".a:remove(x)",                     // takes no argument
        ".a:has()",                         // empty argument
        ".a:unknown-thing(x)",              // not an operation we implement
    ])
    func refusals(selector: String) {
        #expect(ProceduralSelector.parse(selector) == nil)
    }

    @Test(":remove() is recognised as deleting rather than hiding")
    func removal() throws {
        let selector = try #require(ProceduralSelector.parse(".ad:remove()"))
        #expect(selector.removesElement)
        let hiding = try #require(ProceduralSelector.parse(".ad:has-text(x)"))
        #expect(!hiding.removesElement)
    }

    /// The payload goes into every page, so the encoding is arrays rather than objects
    /// — shorter matters when it is measured in kilobytes per page load.
    @Test("the wire form is compact and ordered")
    func encoding() throws {
        let selector = try #require(ProceduralSelector.parse(".a:has-text(x):upward(2)"))
        let encoded = selector.encoded()
        #expect(encoded.count == 2)
        #expect(encoded[0] as? String == ".a")
        let steps = try #require(encoded[1] as? [[Any]])
        #expect(steps.count == 2)
        #expect(steps[0][0] as? String == "t")
        #expect(steps[1][0] as? String == "u")
    }

    @Test("an operation with no base selector is still usable")
    func noBase() throws {
        let selector = try #require(ProceduralSelector.parse(":has-text(Publicité)"))
        #expect(selector.base.isEmpty)
        #expect(selector.operations == [.hasText("Publicité")])
    }
}
