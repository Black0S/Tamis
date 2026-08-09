import Testing
@testable import TamisFilterEngine

@Suite("Cosmetic rule parsing")
struct CosmeticRuleTests {

    @Test("a generic hide rule applies everywhere")
    func genericHide() throws {
        let rule = try #require(CosmeticRule.parse("##.ad-banner"))
        #expect(rule.kind == .hide)
        #expect(rule.body == ".ad-banner")
        #expect(rule.isGeneric)
    }

    @Test("a domain-scoped rule records its domains")
    func scopedHide() throws {
        let rule = try #require(CosmeticRule.parse("example.com,other.org##.promo"))
        #expect(rule.includedDomains == ["example.com", "other.org"])
        #expect(!rule.isGeneric)
    }

    @Test("a negated domain is excluded, not included")
    func negatedDomain() throws {
        let rule = try #require(CosmeticRule.parse("example.com,~ads.example.com##.promo"))
        #expect(rule.includedDomains == ["example.com"])
        #expect(rule.excludedDomains == ["ads.example.com"])
    }

    /// The separators overlap: `#@#` contains `#`, and `#$#` would be read as `##` if
    /// the shorter marker were tried first.
    @Test("separators are recognised longest-first", arguments: [
        ("example.com#@#.ad", CosmeticRule.Kind.unhide),
        ("example.com#$#body { color: red; }", .style),
        ("example.com##.ad", .hide),
        ("example.com##+js(abort-on-property-read, adsbygoogle)", .scriptlet),
        ("example.com##^script:has-text(ads)", .htmlFilter),
    ])
    func separators(line: String, expected: CosmeticRule.Kind) throws {
        let rule = try #require(CosmeticRule.parse(line))
        #expect(rule.kind == expected)
    }

    @Test("network rules and comments are not cosmetic rules", arguments: [
        "||example.com^", "! a comment", "[Adblock Plus 2.0]", "", "example.com##",
    ])
    func notCosmetic(line: String) {
        #expect(CosmeticRule.parse(line) == nil)
    }

    /// A stylesheet cannot express "the element containing this text". Mixing these
    /// into the CSS would make the browser discard the entire rule, silently losing
    /// every selector alongside them.
    @Test("procedural selectors are recognised", arguments: [
        "example.com##.ad:has-text(Publicité)",
        "example.com##div:has(> .sponsored)",
        "example.com##.item:upward(2)",
        "example.com##a:matches-css(display: block)",
    ])
    func procedural(line: String) throws {
        let rule = try #require(CosmeticRule.parse(line))
        #expect(rule.isProcedural)
    }

    @Test("a plain selector is not procedural")
    func plainSelector() throws {
        let rule = try #require(CosmeticRule.parse("example.com##.ad > div[data-id]"))
        #expect(!rule.isProcedural)
    }
}

@Suite("Cosmetic engine")
struct CosmeticEngineTests {

    @Test("a scoped rule reaches its domain and its subdomains")
    func scoping() {
        let engine = CosmeticEngine(rules: "example.com##.promo")
        #expect(engine.set(forHostname: "example.com").specificSelectors == [".promo"])
        #expect(engine.set(forHostname: "www.example.com").specificSelectors == [".promo"])
        #expect(engine.set(forHostname: "other.com").specificSelectors.isEmpty)
        // A domain that merely ends with the same letters is a different site.
        #expect(engine.set(forHostname: "notexample.com").specificSelectors.isEmpty)
    }

    @Test("a negated subdomain is spared")
    func negation() {
        let engine = CosmeticEngine(rules: "example.com,~ads.example.com##.promo")
        #expect(engine.set(forHostname: "www.example.com").specificSelectors == [".promo"])
        #expect(engine.set(forHostname: "ads.example.com").specificSelectors.isEmpty)
    }

    /// Generic rules run to tens of thousands of selectors in real lists — far too
    /// many to inline into every page — so they are kept apart for the runtime.
    @Test("generic and specific selectors are kept apart")
    func genericAreSeparate() {
        let engine = CosmeticEngine(rules: """
        ##.generic-ad
        example.com##.specific-ad
        """)
        let set = engine.set(forHostname: "example.com")
        #expect(set.specificSelectors == [".specific-ad"])
        #expect(set.genericSelectors == [".generic-ad"])
        #expect(!set.inlineCSS().contains(".generic-ad"))
    }

    /// An exception exists because the hide broke that site, so the selector must not
    /// be collected at all.
    @Test("an exception cancels a hide on its domain only")
    func exceptions() {
        let engine = CosmeticEngine(rules: """
        ##.ad-banner
        example.com#@#.ad-banner
        """)
        #expect(engine.set(forHostname: "example.com").genericSelectors.isEmpty)
        #expect(engine.set(forHostname: "other.com").genericSelectors == [".ad-banner"])
    }

    @Test("#@#* cancels every cosmetic rule on that site")
    func blanketException() {
        let engine = CosmeticEngine(rules: """
        ##.ad-banner
        example.com##.promo
        example.com#@#*
        """)
        #expect(engine.set(forHostname: "example.com").isEmpty)
        #expect(!engine.set(forHostname: "other.com").isEmpty)
    }

    @Test("each rule kind lands in its own bucket")
    func kindsAreSorted() {
        let engine = CosmeticEngine(rules: """
        example.com##.plain
        example.com##.text:has-text(Ad)
        example.com#$#body { margin: 0; }
        example.com##+js(set-constant, x, true)
        example.com##^div[data-ad]
        """)
        let set = engine.set(forHostname: "example.com")
        #expect(set.specificSelectors == [".plain"])
        #expect(set.proceduralSelectors == [".text:has-text(Ad)"])
        #expect(set.styleRules == ["body { margin: 0; }"])
        #expect(set.scriptlets == ["set-constant, x, true"])
        #expect(set.htmlFilters == ["div[data-ad]"])
    }

    /// `display: none !important` removes the element from layout, which is what
    /// closes the hole a blocked advert leaves — and `!important` survives the inline
    /// styles ad frames set on themselves.
    @Test("the inline stylesheet hides rather than merely conceals")
    func inlineCSS() {
        let engine = CosmeticEngine(rules: "example.com##.promo")
        let css = engine.set(forHostname: "example.com").inlineCSS()
        #expect(css.contains(".promo"))
        #expect(css.contains("display: none !important"))
    }

    @Test("nothing to apply produces no stylesheet at all")
    func emptyProducesNothing() {
        let engine = CosmeticEngine(rules: "example.com##.promo")
        #expect(engine.set(forHostname: "other.com").inlineCSS().isEmpty)
    }

    @Test("statistics report what was absorbed")
    func stats() {
        let engine = CosmeticEngine(rules: """
        ! comment
        ##.generic
        example.com##.specific
        example.com#@#.specific
        example.com##.x:has-text(y)
        ||network.rule^
        """)
        #expect(engine.stats.rules == 4)
        #expect(engine.stats.generic == 1)
        #expect(engine.stats.specific == 2)
        #expect(engine.stats.exceptions == 1)
        #expect(engine.stats.procedural == 1)
    }
}
