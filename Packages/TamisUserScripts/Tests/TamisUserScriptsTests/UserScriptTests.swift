import Foundation
import Testing
@testable import TamisUserScripts

private let sample = """
// ==UserScript==
// @name         YouTube — Sans Shorts
// @namespace    io.github.black0s
// @version      1.4.1
// @description  Masque les Shorts
// @match        *://*.youtube.com/*
// @exclude      *://*.youtube.com/embed/*
// @run-at       document-start
// @grant        GM_addStyle
// @require      https://example.com/lib.js
// @downloadURL  https://example.com/script.user.js
// ==/UserScript==

(function () { "use strict"; console.log("hello"); })();
"""

@Suite("User script metadata")
struct UserScriptParsingTests {

    @Test("the metadata block is read whole")
    func parsesMetadata() throws {
        let script = try UserScript.parse(sample)
        #expect(script.name == "YouTube — Sans Shorts")
        #expect(script.namespace == "io.github.black0s")
        #expect(script.version == "1.4.1")
        #expect(script.runAt == .documentStart)
        #expect(script.grants == ["GM_addStyle"])
        #expect(script.requires.count == 1)
        #expect(script.downloadURL?.absoluteString == "https://example.com/script.user.js")
    }

    @Test("the body excludes the metadata block")
    func bodyIsSeparated() throws {
        let script = try UserScript.parse(sample)
        #expect(script.body.contains("console.log"))
        #expect(!script.body.contains("@match"))
        #expect(!script.body.contains("==UserScript=="))
    }

    /// A script with neither @match nor @include would run on every page ever loaded.
    /// Greasemonkey defaulted to that; refusing is safer than silently making it global.
    @Test("a script with no scope at all is refused")
    func unscopedIsRefused() {
        let unscoped = """
        // ==UserScript==
        // @name  Everywhere
        // ==/UserScript==
        console.log(1);
        """
        #expect(throws: UserScript.ParseError.unscoped) {
            try UserScript.parse(unscoped)
        }
    }

    @Test("a file with no metadata block or no name is refused")
    func malformed() {
        #expect(throws: UserScript.ParseError.noMetadataBlock) {
            try UserScript.parse("console.log(1);")
        }
        #expect(throws: UserScript.ParseError.noName) {
            try UserScript.parse("// ==UserScript==\n// @match *://*/*\n// ==/UserScript==\n")
        }
    }

    /// Tampermonkey's default when the key is absent.
    @Test("run-at defaults to document-idle")
    func runAtDefault() throws {
        let script = try UserScript.parse("""
        // ==UserScript==
        // @name  X
        // @match *://example.com/*
        // ==/UserScript==
        """)
        #expect(script.runAt == .documentIdle)
        #expect(script.runAt.needsWrapping)
    }

    /// Injection happens once, at the top of the document, so only document-start needs
    /// no wrapping — the rest are reproduced with the matching event.
    @Test("only document-start runs without wrapping")
    func wrapping() {
        #expect(!UserScript.RunAt.documentStart.needsWrapping)
        #expect(UserScript.RunAt.documentEnd.needsWrapping)
        #expect(UserScript.RunAt.documentIdle.needsWrapping)
    }

    @Test("several values for one key are all kept")
    func repeatedKeys() throws {
        let script = try UserScript.parse("""
        // ==UserScript==
        // @name  X
        // @match *://a.example/*
        // @match *://b.example/*
        // @exclude *://a.example/admin/*
        // ==/UserScript==
        """)
        #expect(script.matches.count == 2)
        #expect(script.excludes.count == 1)
    }
}

@Suite("User script matching")
struct UserScriptMatchingTests {

    private func script(_ metadata: String) throws -> UserScript {
        try UserScript.parse("// ==UserScript==\n// @name X\n\(metadata)\n// ==/UserScript==\n")
    }

    private func url(_ text: String) throws -> URL {
        try #require(URL(string: text))
    }

    @Test("a matching URL runs the script")
    func basicMatch() throws {
        let s = try script("// @match *://*.youtube.com/*")
        #expect(s.matches(url: try url("https://www.youtube.com/watch?v=1")))
        #expect(!s.matches(url: try url("https://vimeo.com/1")))
    }

    /// An @exclude exists because the script broke that page, so it must win outright.
    @Test("an exclusion beats a match")
    func exclusionWins() throws {
        let s = try script("""
        // @match *://*.youtube.com/*
        // @exclude *://*.youtube.com/embed/*
        """)
        #expect(s.matches(url: try url("https://www.youtube.com/watch")))
        #expect(!s.matches(url: try url("https://www.youtube.com/embed/abc")))
    }

    @Test("@include works alongside @match")
    func includes() throws {
        let s = try script("// @include /^https://.*\\.example\\.test/")
        #expect(s.matches(url: try url("https://a.example.test/page")))
        #expect(!s.matches(url: try url("https://example.org/page")))
    }

    /// Running arbitrary JavaScript in an application we could not identify is worse
    /// than not running it — deliberately stricter than how a missed attribution is
    /// treated for blocking.
    @Test("an app-scoped script does not run in an unidentified app")
    func appScope() throws {
        let s = try script("""
        // @match *://example.com/*
        // @app com.apple.Safari
        """)
        #expect(s.applies(toApp: "com.apple.Safari"))
        #expect(!s.applies(toApp: "com.google.Chrome"))
        #expect(!s.applies(toApp: nil))

        // With no restriction, anything goes — including an unidentified app.
        let open = try script("// @match *://example.com/*")
        #expect(open.applies(toApp: nil))
        #expect(open.applies(toApp: "com.google.Chrome"))
    }
}
