import Testing
@testable import TamisLists

@Suite("IDNA")
struct IDNATests {

    @Test("ASCII hosts are only lowercased", arguments: [
        ("Synology.me", "synology.me"),
        ("EXAMPLE.COM", "example.com"),
        ("sub.example.com.", "sub.example.com"),
        ("  example.com  ", "example.com"),
    ])
    func ascii(input: String, expected: String) {
        #expect(IDNA.normalize(host: input) == expected)
    }

    /// Reference values from Python's `idna` codec, which encodes the same way for
    /// every character here — the deviations are covered separately below.
    @Test("Unicode hosts become Punycode", arguments: [
        ("onlinebanking-hüttenberger-bank.de", "xn--onlinebanking-httenberger-bank-jfd.de"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("日本.jp", "xn--wgv71a.jp"),
    ])
    func unicode(input: String, expected: String) {
        #expect(IDNA.normalize(host: input) == expected)
    }

    /// Non-transitional processing, which is what browsers do: ß stays ß rather than
    /// becoming `ss`. Getting this backwards would send Tamis looking for a host that
    /// resolves to somebody else.
    @Test("ß is not folded to ss")
    func deviation() {
        #expect(IDNA.normalize(host: "faß.de") == "xn--fa-hia.de")
    }

    @Test("Already-encoded labels pass through")
    func alreadyEncoded() {
        #expect(IDNA.normalize(host: "xn--bcher-kva.de") == "xn--bcher-kva.de")
    }

    @Test("Empty input has no host")
    func empty() {
        #expect(IDNA.normalize(host: "") == nil)
        #expect(IDNA.normalize(host: ".") == nil)
    }

    /// RFC 3492 §7.1, the sample the specification itself provides.
    @Test("RFC 3492 sample")
    func rfcSample() {
        #expect(IDNA.punycode("bücher") == "bcher-kva")
    }
}
