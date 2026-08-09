import Testing
@testable import TamisFilterEngine

@Suite("Document tokens")
struct DocumentTokensTests {

    private func scan(_ html: String) -> Set<String> {
        DocumentTokens.scan(Array(html.utf8))
    }

    /// This is what makes generic cosmetic filtering affordable from a proxy: only the
    /// rules naming something the markup carries can possibly match it.
    @Test("class and id names are collected")
    func collectsBoth() {
        let tokens = scan(#"<div class="ad-banner promo" id="header"><p class="text">x</p></div>"#)
        #expect(tokens == ["ad-banner", "promo", "header", "text"])
    }

    @Test("both quote styles and unquoted values are handled", arguments: [
        #"<div class="a b">"#,
        #"<div class='a b'>"#,
        #"<div class=a><span class=b>"#,
    ])
    func quoting(html: String) {
        let tokens = scan(html)
        #expect(tokens.contains("a"))
        #expect(tokens.contains("b"))
    }

    @Test("attribute names are matched whatever their case")
    func caseInsensitiveAttributes() {
        #expect(scan(#"<div CLASS="Ad" ID="Top">"#) == ["Ad", "Top"])
    }

    /// Other attributes must not contribute, or the token set inflates with values that
    /// can never appear in a selector.
    @Test("only class and id contribute")
    func otherAttributesIgnored() {
        let tokens = scan(#"<a href="/promo" data-id="ad" class="link">x</a>"#)
        #expect(tokens == ["link"])
    }

    @Test("whitespace around the equals sign is tolerated")
    func looseSpacing() {
        #expect(scan(#"<div class = "a" >"#).contains("a"))
    }

    /// An unbounded set on a hostile document is a memory amplifier.
    @Test("the token set is bounded")
    func bounded() {
        let many = (0..<30_000).map { "<div class=\"c\($0)\">" }.joined()
        #expect(scan(many).count <= DocumentTokens.maximumTokens)
    }

    @Test("markup with no classes yields nothing")
    func empty() {
        #expect(scan("<html><body><p>text</p></body></html>").isEmpty)
    }
}
