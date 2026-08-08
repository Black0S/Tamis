import Testing
@testable import TamisFilterEngine

private func request(
    _ url: String,
    from source: String? = nil,
    type: RequestType = .script,
    method: String = "GET"
) -> Request {
    let host = url
        .replacingOccurrences(of: "https://", with: "")
        .replacingOccurrences(of: "http://", with: "")
        .split(separator: "/").first.map(String.init) ?? ""
    return Request(url: url, hostname: host, sourceHostname: source, type: type, method: method)
}

@Suite("Rule options")
struct RuleOptionsTests {

    @Test("positive types define the set exactly")
    func positiveTypes() {
        let o = RuleOptions.parse("script,image")
        #expect(o.types == [.script, .image])
        #expect(!o.types.contains(.font))
    }

    @Test("negated types carve out of the default set")
    func negatedTypes() {
        let o = RuleOptions.parse("~script")
        #expect(!o.types.contains(.script))
        #expect(o.types.contains(.image))
        // The default still excludes top-level navigation.
        #expect(!o.types.contains(.document))
    }

    @Test("party modifiers and their aliases", arguments: [
        ("third-party", true), ("3p", true),
        ("~third-party", false), ("first-party", false), ("1p", false),
        ("strict3p", true), ("strict1p", false),
    ])
    func party(modifier: String, expected: Bool) {
        #expect(RuleOptions.parse(modifier).thirdParty == expected)
    }

    @Test("$domain splits positives from negatives")
    func domains() {
        let o = RuleOptions.parse("domain=example.com|~ads.example.com|other.org")
        #expect(o.includedDomains == ["example.com", "other.org"])
        #expect(o.excludedDomains == ["ads.example.com"])
    }

    @Test("$method splits positives from negatives")
    func methods() {
        let o = RuleOptions.parse("method=get|~post")
        #expect(o.includedMethods == ["GET"])
        #expect(o.excludedMethods == ["POST"])
    }

    @Test("unknown modifiers are recorded, not dropped silently")
    func unsupportedAreCounted() {
        let o = RuleOptions.parse("script,inline-font,webrtc")
        #expect(o.types == .script)
        #expect(o.unsupported == ["inline-font", "webrtc"])
    }

    @Test("action modifiers are carried for the proxy to apply")
    func actionModifiers() {
        let o = RuleOptions.parse("redirect=noop.js,important")
        #expect(o.redirect == "noop.js")
        #expect(o.isImportant)
    }

    @Test("exclusions win over inclusions in $domain")
    func domainScope() {
        let o = RuleOptions.parse("domain=example.com|~ads.example.com")
        #expect(o.domainScopeAllows(hostname: "example.com"))
        #expect(o.domainScopeAllows(hostname: "www.example.com"))
        #expect(!o.domainScopeAllows(hostname: "ads.example.com"))
        #expect(!o.domainScopeAllows(hostname: "other.com"))
        // `notexample.com` must not be read as a subdomain of `example.com`.
        #expect(!o.domainScopeAllows(hostname: "notexample.com"))
    }
}

@Suite("Network rule parsing")
struct NetworkRuleParsingTests {

    @Test("comments and cosmetic rules are skipped, not errors", arguments: [
        "! a comment",
        "[Adblock Plus 2.0]",
        "example.com##.ad-banner",
        "example.com#@#.ad",
        "example.com#$#body { color: red; }",
    ])
    func nonNetworkLines(line: String) throws {
        #expect(try NetworkRule.parse(line) == nil)
    }

    @Test("@@ marks an exception")
    func exception() throws {
        let rule = try #require(try NetworkRule.parse("@@||example.com^$script"))
        #expect(rule.isException)
        #expect(rule.options.types == .script)
    }

    /// `$` is legal inside a pattern, so the modifier separator cannot simply be the
    /// first or last `$` in the line.
    @Test("the modifier separator is found even when the pattern contains $")
    func dollarInsidePattern() throws {
        let (pattern, options) = NetworkRule.splitPatternAndOptions("/ads\\$[0-9]/$script")
        #expect(pattern == "/ads\\$[0-9]/")
        #expect(options == "script")

        // A regex end anchor is not a modifier list.
        let (p2, o2) = NetworkRule.splitPatternAndOptions("/banner$/")
        #expect(p2 == "/banner$/")
        #expect(o2 == nil)
    }

    @Test("a rule made only of modifiers matches every URL")
    func modifiersOnly() throws {
        let rule = try #require(try NetworkRule.parse("$domain=example.com,script"))
        #expect(rule.matches(request("https://cdn.other.com/a.js", from: "example.com")))
    }
}

@Suite("Filter engine")
struct FilterEngineTests {

    @Test("a matching block rule blocks")
    func basicBlock() {
        let engine = FilterEngine(rules: "||doubleclick.net^")
        let result = engine.match(request("https://ads.doubleclick.net/pixel.gif"))
        #expect(result.action == .block)
        #expect(result.rule == "||doubleclick.net^")
    }

    @Test("an unmatched request is allowed with no rule attached")
    func noMatch() {
        let engine = FilterEngine(rules: "||doubleclick.net^")
        #expect(engine.match(request("https://example.com/app.js")) == .allowed)
    }

    @Test("an exception cancels a block")
    func exceptionWins() {
        let engine = FilterEngine(rules: """
        ||tracker.com^
        @@||tracker.com^$domain=example.com
        """)
        #expect(engine.match(request("https://tracker.com/t.js", from: "other.com")).action == .block)
        #expect(engine.match(request("https://tracker.com/t.js", from: "example.com")).action == .allow)
    }

    @Test("$important beats an exception")
    func importantWins() {
        let engine = FilterEngine(rules: """
        ||tracker.com^$important
        @@||tracker.com^
        """)
        let result = engine.match(request("https://tracker.com/t.js"))
        #expect(result.action == .block)
        #expect(result.rule == "||tracker.com^$important")
    }

    @Test("$badfilter removes the identical rule")
    func badFilter() {
        let engine = FilterEngine(rules: """
        ||tracker.com^
        ||tracker.com^$badfilter
        """)
        #expect(engine.match(request("https://tracker.com/t.js")) == .allowed)
        #expect(engine.stats.removedByBadFilter == 1)
        #expect(engine.stats.networkRules == 0)
    }

    @Test("type and party modifiers narrow the match")
    func modifiersNarrow() {
        let engine = FilterEngine(rules: "||cdn.com^$image,third-party")

        // Right type, right party.
        #expect(engine.match(request("https://cdn.com/a.png", from: "site.com", type: .image)).action == .block)
        // Wrong type.
        #expect(engine.match(request("https://cdn.com/a.js", from: "site.com", type: .script)).action == .allow)
        // First-party.
        #expect(engine.match(request("https://cdn.com/a.png", from: "cdn.com", type: .image)).action == .allow)
    }

    /// The regression test for the token-index soundness bug: an unanchored pattern
    /// whose first word is a *suffix* of the word in the URL. If the index only filed
    /// whole words, this rule would never be found and would silently block nothing.
    @Test("an unanchored pattern is found inside a longer word")
    func indexFindsSuffixMatches() {
        let engine = FilterEngine(rules: "banner-ad.png")
        #expect(engine.match(request("https://example.com/xbanner-ad.png", type: .image)).action == .block)
        #expect(engine.match(request("https://example.com/banner-ad.png", type: .image)).action == .block)
    }

    @Test("build statistics report what was actually absorbed")
    func stats() {
        let engine = FilterEngine(rules: """
        ! title: test list

        ||ads.com^
        example.com##.banner
        ||tracker.com^$webrtc
        @@||safe.com^
        """)
        #expect(engine.stats.lines == 6)
        #expect(engine.stats.comments == 1)
        #expect(engine.stats.cosmeticSkipped == 1)
        #expect(engine.stats.rulesWithUnsupportedModifiers == 1)
        // The `$webrtc` rule is *dropped*, not applied without its modifier — hence 2.
        #expect(engine.stats.networkRules == 2)
    }

    /// An unknown modifier almost always narrows a rule. Applying the rule anyway
    /// widens it far beyond its author's intent, which breaks sites rather than
    /// protecting them. Found by running the engine against EasyList, where
    /// `://ads.$popup` was blocking every URL containing `://ads.`.
    @Test("a rule with an unknown modifier is dropped, never widened")
    func unknownModifierDropsTheRule() {
        let engine = FilterEngine(rules: "://ads.$popup")
        #expect(engine.match(request("https://ads.example.com/page.html", type: .document)) == .allowed)
        #expect(engine.stats.rulesWithUnsupportedModifiers == 1)
        #expect(engine.stats.networkRules == 0)
    }
}
