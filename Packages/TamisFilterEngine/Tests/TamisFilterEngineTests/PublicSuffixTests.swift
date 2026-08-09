import Foundation
import Testing
@testable import TamisFilterEngine

@Suite("Public Suffix List")
struct PublicSuffixTests {

    @Test("The real list is embedded, not a sample")
    func listIsReal() {
        #expect(PublicSuffix.ruleCount > 9_000, "\(PublicSuffix.ruleCount) rules")
        #expect(PublicSuffix.rules.wildcards.count > 200)
        #expect(!PublicSuffix.rules.exceptions.isEmpty)
    }

    /// The case the placeholder could never get right, and the reason it had to go.
    @Test("Two names under the same public suffix are different sites")
    func differentSitesUnderASuffix() {
        #expect(PublicSuffix.registrableDomain(of: "a.co.uk") == "a.co.uk")
        #expect(PublicSuffix.registrableDomain(of: "b.co.uk") == "b.co.uk")
        #expect(PublicSuffix.registrableDomain(of: "www.a.co.uk") == "a.co.uk")
    }

    /// The private section matters as much as the ICANN one: two projects on
    /// github.io are not first-party to each other, which is exactly what it records.
    @Test("Private suffixes count too", arguments: [
        ("alice.github.io", "alice.github.io"),
        ("www.alice.github.io", "alice.github.io"),
        ("app.herokuapp.com", "app.herokuapp.com"),
        ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
    ])
    func privateSection(host: String, expected: String) {
        #expect(PublicSuffix.registrableDomain(of: host) == expected)
    }

    /// Punycode, because a host name on the wire never carries the Unicode form.
    @Test("Internationalised suffixes resolve")
    func internationalised() {
        // xn--p1ai is .рф — a real public suffix with real registrations under it.
        #expect(PublicSuffix.registrableDomain(of: "www.example.xn--p1ai") == "example.xn--p1ai")
    }

    @Test("IP literals are their own identity")
    func ipLiterals() {
        #expect(PublicSuffix.registrableDomain(of: "192.168.1.1") == "192.168.1.1")
        #expect(PublicSuffix.registrableDomain(of: "[::1]") == "[::1]")
    }

    @Test("A trailing dot changes nothing")
    func trailingDot() {
        #expect(PublicSuffix.registrableDomain(of: "www.example.com.") == "example.com")
    }

    /// publicsuffix.org publishes its own conformance suite. Running it is the whole
    /// argument for embedding the real list rather than approximating it: the claim
    /// becomes checkable by someone else's tests instead of by mine.
    @Test("The official conformance suite passes")
    func officialSuite() throws {
        let url = try #require(
            Bundle.module.url(forResource: "psl_tests", withExtension: "txt",
                              subdirectory: "Resources")
                ?? Bundle.module.url(forResource: "psl_tests", withExtension: "txt")
        )
        let text = try String(contentsOf: url, encoding: .utf8)

        var checked = 0
        var failures: [String] = []

        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("checkPublicSuffix(") else { continue }

            let inner = trimmed
                .dropFirst("checkPublicSuffix(".count)
                .drop(while: { $0 == " " })
            guard let close = inner.lastIndex(of: ")") else { continue }
            let arguments = inner[..<close].split(separator: ",", maxSplits: 1)
            guard arguments.count == 2 else { continue }

            func unquote(_ value: some StringProtocol) -> String? {
                let value = value.trimmingCharacters(in: .whitespaces)
                guard value != "null" else { return nil }
                return String(value.dropFirst().dropLast())
            }

            // A null input, or one the suite expects to have no registrable domain.
            guard let input = unquote(arguments[0]) else { continue }
            let expected = unquote(arguments[1])

            // The suite lowercases and expects Unicode input handled as Unicode; the
            // rules here are Punycode, and IDNA lives in a package this one cannot
            // depend on. Those cases are exercised in `internationalised` instead.
            guard input.allSatisfy(\.isASCII) else { continue }

            checked += 1
            let actual = PublicSuffix.registrableDomain(of: input.lowercased())

            if let expected {
                if actual != expected { failures.append("\(input) → \(actual), attendu \(expected)") }
            } else {
                // No registrable domain: the input is itself a public suffix, and this
                // implementation returns the host unchanged rather than nil.
                if actual != input.lowercased() {
                    failures.append("\(input) → \(actual), attendu aucun domaine enregistrable")
                }
            }
        }

        #expect(checked > 50, "only \(checked) cases parsed from the suite")
        let report = "\(failures.count) échecs :\n" + failures.prefix(10).joined(separator: "\n")
        #expect(failures.isEmpty, "\(report)")
    }
}
