import Testing
@testable import TamisFilterEngine

private func match(_ pattern: String, _ url: String) throws -> Bool {
    let p = try URLPattern(pattern)
    let bytes = Array(url.lowercased().utf8)
    let bounds = Request.hostBounds(in: bytes)
    return p.matches(url: bytes, urlString: url.lowercased(), hostStart: bounds.start, hostEnd: bounds.end)
}

@Suite("URL patterns")
struct URLPatternTests {

    @Test("a plain substring matches anywhere in the URL")
    func plainSubstring() throws {
        #expect(try match("/ads/", "https://example.com/ads/banner.png"))
        #expect(try match("banner", "https://example.com/ads/banner.png"))
        #expect(try !match("/ads/", "https://example.com/content/banner.png"))
    }

    @Test("|| anchors at the hostname or a subdomain boundary", arguments: [
        ("https://example.com/", true),
        ("https://sub.example.com/x", true),
        ("http://deep.sub.example.com/x", true),
        ("https://notexample.com/", false),          // the classic false positive
        ("https://evil.com/?u=example.com", false),  // must not match in the query
    ])
    func domainAnchor(url: String, expected: Bool) throws {
        #expect(try match("||example.com", url) == expected)
    }

    @Test("| anchors at the start and the end of the URL")
    func edgeAnchors() throws {
        #expect(try match("|https://example.com", "https://example.com/path"))
        #expect(try !match("|https://example.com", "http://x.com/?r=https://example.com"))
        #expect(try match("banner.png|", "https://example.com/banner.png"))
        #expect(try !match("banner.png|", "https://example.com/banner.png?v=2"))
    }

    @Test("* matches any gap, including an empty one")
    func wildcard() throws {
        #expect(try match("/ads/*/banner", "https://example.com/ads/2026/banner.png"))
        #expect(try match("/ads/*banner", "https://example.com/ads/banner.png"))
        #expect(try !match("/ads/*/banner", "https://example.com/ads/banner.png"))
        #expect(try match("*", "https://example.com/anything"))
    }

    @Test("^ matches one separator, or the end of the URL", arguments: [
        ("https://example.com/path", true),
        ("https://example.com?q=1", true),
        ("https://example.com", true),             // end of URL satisfies `^`
        ("https://example.com-evil.net/", false),  // `-` is not a separator
    ])
    func separator(url: String, expected: Bool) throws {
        #expect(try match("||example.com^", url) == expected)
    }

    @Test("/regex/ falls back to NSRegularExpression")
    func regexFallback() throws {
        #expect(try match("/ads?[0-9]+/", "https://example.com/ad42/x"))
        #expect(try match("/ads?[0-9]+/", "https://example.com/ads7/x"))
        #expect(try !match("/ads?[0-9]+/", "https://example.com/advert/x"))
    }

    @Test("the index token is the longest right-bounded alphanumeric run")
    func indexToken() throws {
        #expect(try URLPattern("||doubleclick.net^").indexToken == "doubleclick")
        #expect(try URLPattern("banner-ad.png").indexToken == "banner")
        // Nothing long enough to discriminate: the rule goes to the catch-all bucket.
        #expect(try URLPattern("/ad/").indexToken == nil)
        #expect(try URLPattern("*").indexToken == nil)
    }

    /// The soundness condition of the whole index. A run that ends the pattern without
    /// an end anchor can be a *prefix* of a longer word in the URL, so filing the rule
    /// under it would make the rule unreachable — it would silently block nothing.
    @Test("a run that is not right-bounded is never used as a token")
    func tokenMustBeRightBounded() throws {
        // `double` could be the start of `doubleclick` in a real URL.
        #expect(try URLPattern("||double").indexToken == nil)
        // The end anchor restores the boundary, so the run becomes usable.
        #expect(try URLPattern("||double|").indexToken == "double")
        // A `*` can absorb further alphanumerics, so it is not a boundary either.
        #expect(try URLPattern("/track*").indexToken == nil)
    }

    @Test("ubiquitous words are refused as tokens")
    func uselessTokensAreSkipped() throws {
        // `https` is right-bounded here but appears in essentially every URL; its
        // bucket would be no better than the catch-all.
        #expect(try URLPattern("|https://ads.example/").indexToken == "example")
        #expect(try URLPattern("/^https:.doubleclick/").indexToken == nil)
    }

    /// ABP treats *any* filter delimited by slashes as a regular expression, even when
    /// it looks like a plain path. Real lists rely on this, so it must not be
    /// "corrected" into a literal.
    @Test("slash-delimited filters are regexes, and stay indexable")
    func slashDelimitedFiltersAreRegexes() throws {
        let p = try URLPattern("/ads/banners/")
        #expect(p.regex != nil)
        // Matching is unaffected — a metacharacter-free regex is its own literal.
        #expect(try match("/ads/banners/", "https://example.com/ads/banners/x.png"))
        // …but it must still be indexable, or a large slice of real rules would end
        // up in the always-checked bucket. `banners` ends the regex with nothing
        // bounding it, so `ads` — followed by `/` — is the usable one.
        #expect(p.indexToken == "ads")
    }

    @Test("a regex whose literals can be made optional is not indexed")
    func regexWithMetacharacters() throws {
        // `?` can make the preceding run optional, so no token is provably mandatory.
        #expect(try URLPattern("/ads?[0-9]+/").indexToken == nil)
        #expect(try URLPattern("/(ads|track)/").indexToken == nil)
    }

    @Test("an invalid regex is reported, not swallowed")
    func invalidRegexIsReported() {
        #expect(throws: FilterParseError.invalidRegex("ads[")) {
            try URLPattern("/ads[/")
        }
    }
}
