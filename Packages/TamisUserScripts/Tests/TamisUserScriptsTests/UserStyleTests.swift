import Foundation
import Testing
@testable import TamisUserScripts

private let sample = """
/* ==UserStyle==
@name         Dark example
@namespace    io.github.black0s
@version      1.2.0
@description  Assombrit le site
@var color    accent "Couleur d'accent" #ff0000
==/UserStyle== */

@-moz-document domain("example.com") {
  body { background: #111; color: var(--accent); }
}

@-moz-document url-prefix("https://other.test/docs") {
  .sidebar { display: none; }
}
"""

private func url(_ text: String) throws -> URL {
    try #require(URL(string: text))
}

@Suite("User style metadata")
struct UserStyleParsingTests {

    @Test("the metadata block is read, and variables with it")
    func metadata() throws {
        let style = try UserStyle.parse(sample)
        #expect(style.name == "Dark example")
        #expect(style.namespace == "io.github.black0s")
        #expect(style.version == "1.2.0")
        #expect(style.variables.count == 1)
        #expect(style.variables[0].name == "accent")
        #expect(style.variables[0].label == "Couleur d'accent")
        #expect(style.variables[0].defaultValue == "#ff0000")
    }

    @Test("each @-moz-document block becomes its own section")
    func sections() throws {
        let style = try UserStyle.parse(sample)
        #expect(style.sections.count == 2)
        #expect(style.sections[0].rules == [.domain("example.com")])
        #expect(style.sections[1].rules == [.urlPrefix("https://other.test/docs")])
    }

    /// Someone writing three lines to hide something should not have to learn a
    /// metadata format first. Such a sheet is scoped in the app instead.
    @Test("plain CSS with no metadata is accepted")
    func plainCSS() throws {
        let style = try UserStyle.parse(".ad { display: none; }", fallbackName: "Mon style")
        #expect(style.name == "Mon style")
        #expect(style.sections.count == 1)
        #expect(style.sections[0].rules.isEmpty)
        #expect(style.sections[0].css.contains(".ad"))
    }

    @Test("an empty sheet is refused")
    func empty() {
        #expect(throws: UserStyle.ParseError.empty) {
            try UserStyle.parse("   \n  ")
        }
    }

    @Test("several document functions in one condition are all kept")
    func multipleConditions() throws {
        let style = try UserStyle.parse("""
        @-moz-document domain("a.test"), url-prefix("https://b.test/x") {
          body { margin: 0; }
        }
        """, fallbackName: "X")
        #expect(style.sections[0].rules == [.domain("a.test"), .urlPrefix("https://b.test/x")])
    }
}

@Suite("Document rules")
struct DocumentRuleTests {

    @Test("domain covers subdomains, and only real ones")
    func domain() throws {
        let rule = DocumentRule.domain("example.com")
        #expect(rule.matches(url: try url("https://example.com/x")))
        #expect(rule.matches(url: try url("https://www.example.com/x")))
        // The dot matters.
        #expect(!rule.matches(url: try url("https://notexample.com/x")))
    }

    @Test("url is exact and url-prefix is not")
    func urlAndPrefix() throws {
        #expect(DocumentRule.url("https://a.test/page").matches(url: try url("https://a.test/page")))
        #expect(!DocumentRule.url("https://a.test/page").matches(url: try url("https://a.test/page?x=1")))
        #expect(DocumentRule.urlPrefix("https://a.test/docs").matches(url: try url("https://a.test/docs/intro")))
        #expect(!DocumentRule.urlPrefix("https://a.test/docs").matches(url: try url("https://a.test/blog")))
    }

    /// The detail most reimplementations miss: an unanchored pattern turns a style
    /// meant for one page into one that applies across a whole site.
    @Test("regexp must match the entire URL, not appear within it")
    func regexpIsAnchored() throws {
        let rule = DocumentRule.regexp("https://a\\.test/docs")
        #expect(rule.matches(url: try url("https://a.test/docs")))
        #expect(!rule.matches(url: try url("https://a.test/docs/deeper")))

        let open = DocumentRule.regexp("https://a\\.test/docs.*")
        #expect(open.matches(url: try url("https://a.test/docs/deeper")))
    }

    @Test("an invalid pattern matches nothing rather than everything")
    func invalidRegexp() throws {
        #expect(!DocumentRule.regexp("[unclosed").matches(url: try url("https://a.test/")))
    }
}

@Suite("User style rendering")
struct UserStyleRenderingTests {

    @Test("only the sections matching the page are emitted")
    func sectionSelection() throws {
        let style = try UserStyle.parse(sample)
        let css = try #require(style.css(for: try url("https://www.example.com/page")))
        #expect(css.contains("background: #111"))
        #expect(!css.contains(".sidebar"))

        #expect(style.css(for: try url("https://unrelated.test/")) == nil)
    }

    /// Two spellings coexist in the wild, and a sheet written either way should work
    /// without the user knowing which era it came from.
    @Test("variables are served as custom properties and as placeholders")
    func variables() throws {
        let style = try UserStyle.parse("""
        /* ==UserStyle==
        @name X
        @var color accent "Accent" #00ff00
        ==/UserStyle== */
        @-moz-document domain("a.test") {
          a { color: var(--accent); border-color: /*[[accent]]*/; }
        }
        """)
        let css = try #require(style.css(for: try url("https://a.test/")))
        #expect(css.contains(":root { --accent: #00ff00; }"))
        #expect(css.contains("border-color: #00ff00;"))
    }

    @Test("a value chosen in the app overrides the default")
    func overrides() throws {
        let style = try UserStyle.parse("""
        /* ==UserStyle==
        @name X
        @var color accent "Accent" #00ff00
        ==/UserStyle== */
        @-moz-document domain("a.test") { a { color: var(--accent); } }
        """)
        let css = try #require(style.css(for: try url("https://a.test/"), overrides: ["accent": "#123456"]))
        #expect(css.contains("--accent: #123456;"))
        #expect(!css.contains("#00ff00"))
    }

    @Test("an app-scoped style does not apply in an unidentified app")
    func appScope() throws {
        let style = try UserStyle.parse("""
        /* ==UserStyle==
        @name X
        @app com.apple.Safari
        ==/UserStyle== */
        body { margin: 0; }
        """)
        #expect(style.applies(toApp: "com.apple.Safari"))
        #expect(!style.applies(toApp: "com.google.Chrome"))
        #expect(!style.applies(toApp: nil))
    }
}
