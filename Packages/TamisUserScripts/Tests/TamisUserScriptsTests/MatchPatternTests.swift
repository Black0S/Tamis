import Foundation
import Testing
@testable import TamisUserScripts

@Suite("Match patterns")
struct MatchPatternTests {

    private func matches(_ pattern: String, _ url: String) -> Bool {
        guard let parsed = MatchPattern.parse(pattern), let target = URL(string: url) else {
            return false
        }
        return parsed.matches(url: target)
    }

    /// The distinction scripts are written against: `*.` covers subdomains, a bare host
    /// does not. Treating `*.` as a plain wildcard runs scripts on hosts their authors
    /// never chose.
    @Test("*. covers the domain and everything under it")
    func subdomainWildcard() {
        #expect(matches("*://*.example.com/*", "https://example.com/page"))
        #expect(matches("*://*.example.com/*", "https://www.example.com/page"))
        #expect(matches("*://*.example.com/*", "https://a.b.example.com/page"))
        // The dot matters.
        #expect(!matches("*://*.example.com/*", "https://notexample.com/page"))
    }

    @Test("a bare host is exact")
    func exactHost() {
        #expect(matches("*://example.com/*", "https://example.com/page"))
        #expect(!matches("*://example.com/*", "https://www.example.com/page"))
    }

    /// `*` as a scheme means http and https, not every scheme that exists.
    @Test("the scheme wildcard is http and https only")
    func schemeWildcard() {
        #expect(matches("*://example.com/*", "http://example.com/"))
        #expect(matches("*://example.com/*", "https://example.com/"))
        #expect(!matches("*://example.com/*", "ftp://example.com/"))
        #expect(!matches("*://example.com/*", "file://example.com/"))
    }

    @Test("an explicit scheme is honoured")
    func explicitScheme() {
        #expect(matches("https://example.com/*", "https://example.com/"))
        #expect(!matches("https://example.com/*", "http://example.com/"))
    }

    @Test("the path is a glob, and the query is part of it")
    func pathGlob() {
        #expect(matches("*://example.com/watch*", "https://example.com/watch?v=1"))
        #expect(!matches("*://example.com/watch*", "https://example.com/embed/1"))
        #expect(matches("*://example.com/*/edit", "https://example.com/docs/edit"))
    }

    @Test("<all_urls> matches every http and https page")
    func allURLs() {
        #expect(matches("<all_urls>", "https://anything.example/"))
        #expect(matches("<all_urls>", "http://other.test/x?y=1"))
    }

    /// A pattern we misread runs a script somewhere its author did not choose, which is
    /// a page break the user cannot attribute to anything.
    @Test("malformed patterns are refused rather than guessed at", arguments: [
        "", "example.com/*", "*://example.com", "javascript://*/*",
        "*://*.*.com/*", "*://ex*ample.com/*",
    ])
    func malformed(pattern: String) {
        #expect(MatchPattern.parse(pattern) == nil)
    }
}

@Suite("Include rules")
struct IncludeRuleTests {

    @Test("a glob matches the whole URL")
    func glob() throws {
        let rule = try #require(IncludeRule.parse("https://example.com/*/edit"))
        #expect(rule.matches(url: "https://example.com/docs/edit"))
        #expect(!rule.matches(url: "https://example.com/docs/view"))
    }

    @Test("a bare star means everywhere")
    func star() throws {
        let rule = try #require(IncludeRule.parse("*"))
        #expect(rule.matches(url: "https://anything.example/"))
    }

    @Test("a regular expression keeps its flags")
    func regex() throws {
        let rule = try #require(IncludeRule.parse("/^https://(www\\.)?EXAMPLE\\.com/i"))
        #expect(rule.matches(url: "https://www.example.com/page"))
        #expect(!rule.matches(url: "https://other.test/"))
    }

    @Test("an invalid regular expression matches nothing rather than everything")
    func invalidRegex() throws {
        let rule = try #require(IncludeRule.parse("/[unclosed/"))
        #expect(!rule.matches(url: "https://example.com/"))
    }
}

@Suite("Glob matching")
struct GlobTests {

    @Test("wildcards behave", arguments: [
        ("a*b", "ab", true), ("a*b", "axxxb", true), ("a*b", "ba", false),
        ("*", "anything", true), ("/watch*", "/watch?v=1", true),
        ("/watch*", "/embed", false),
    ])
    func semantics(pattern: String, text: String, expected: Bool) {
        #expect(Glob.matches(pattern: pattern, text: text) == expected)
    }

    /// Patterns arrive from downloaded scripts, so a recursive matcher would be a denial
    /// of service waiting to be published.
    @Test("a pathological pattern terminates")
    func pathological() {
        let pattern = String(repeating: "a*", count: 20) + "b"
        let text = String(repeating: "a", count: 60)
        #expect(!Glob.matches(pattern: pattern, text: text))
    }
}
