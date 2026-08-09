import Foundation
import Testing
import X509
import SwiftASN1
import TamisTLS
@testable import TamisProxy

private func der(_ certificate: Certificate) throws -> [UInt8] {
    var serializer = DER.Serializer()
    try serializer.serialize(certificate)
    return serializer.serializedBytes
}

@Suite("System trust verification")
struct SystemTrustVerifierTests {

    /// The point of the whole component: when Tamis intercepts, the client stops
    /// checking the origin and trusts us instead. Accepting a chain the system would
    /// refuse silently lowers the user's security while the padlock stays shut.
    @Test("a self-signed chain is refused by the system store")
    func selfSignedIsRejected() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let leaf = try LeafIssuer(authority: ca).issue(for: "example.com")

        let result = SystemTrustVerifier.evaluate(
            chain: [try der(leaf), try der(ca.certificate)],
            hostname: "example.com"
        )
        #expect(result != .trusted)
    }

    /// The same chain must pass once its authority is trusted — this is what makes a
    /// developer's `mkcert` or Caddy local CA keep working, which a bundled root list
    /// would break.
    @Test("the same chain is accepted when its authority is an anchor")
    func trustedAnchorIsAccepted() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let leaf = try LeafIssuer(authority: ca).issue(for: "local.test")

        let result = SystemTrustVerifier.evaluate(
            chain: [try der(leaf)],
            hostname: "local.test",
            anchors: [try der(ca.certificate)]
        )
        #expect(result == .trusted, "\(result)")
    }

    @Test("a certificate for another name is refused, and reported as a name mismatch")
    func hostnameMismatch() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let leaf = try LeafIssuer(authority: ca).issue(for: "one.test")

        let result = SystemTrustVerifier.evaluate(
            chain: [try der(leaf)],
            hostname: "two.test",
            anchors: [try der(ca.certificate)]
        )
        guard case .rejected(_, let isNameMismatch) = result else {
            Issue.record("a certificate for another host was accepted")
            return
        }
        #expect(isNameMismatch)
    }

    @Test("an expired certificate is refused even from a trusted authority")
    func expiredIsRejected() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let longAgo = Date().addingTimeInterval(-60 * 24 * 3600)
        let leaf = try LeafIssuer(authority: ca).issue(for: "local.test", now: longAgo)

        let result = SystemTrustVerifier.evaluate(
            chain: [try der(leaf)],
            hostname: "local.test",
            anchors: [try der(ca.certificate)]
        )
        #expect(result != .trusted)
    }

    @Test("an empty or malformed chain is refused rather than skipped")
    func malformedChain() {
        #expect(SystemTrustVerifier.evaluate(chain: [], hostname: "example.com") != .trusted)
        #expect(SystemTrustVerifier.evaluate(chain: [[0x00, 0x01]], hostname: "example.com") != .trusted)
    }
}

@Suite("Leaf cache")
struct LeafCacheTests {

    private func makeCache(capacity: Int = 2_000, lifetime: TimeInterval = 24 * 3600) throws -> LeafCache {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        return LeafCache(issuer: LeafIssuer(authority: ca), capacity: capacity, lifetime: lifetime)
    }

    /// A client that sees a different certificate for the same host mid-session may
    /// treat it as an attack, so the same target must always get the same certificate.
    @Test("the same target gets the same certificate")
    func stability() throws {
        let cache = try makeCache()
        let first = try cache.certificate(for: "example.com")
        let second = try cache.certificate(for: "example.com")
        #expect(first.serialNumber == second.serialNumber)
        #expect(cache.statistics.hits == 1)
        #expect(cache.statistics.misses == 1)
    }

    @Test("lookup is case-insensitive, as hostnames are")
    func caseInsensitive() throws {
        let cache = try makeCache()
        let lower = try cache.certificate(for: "example.com")
        let mixed = try cache.certificate(for: "Example.COM")
        #expect(lower.serialNumber == mixed.serialNumber)
    }

    @Test("different targets get different certificates")
    func distinctTargets() throws {
        let cache = try makeCache()
        let a = try cache.certificate(for: "one.example")
        let b = try cache.certificate(for: "two.example")
        #expect(a.serialNumber != b.serialNumber)
        #expect(cache.count == 2)
    }

    /// Entries expire long before the certificates do. If the two matched, an entry
    /// could be served with no validity left and break the connection for no visible
    /// reason.
    @Test("an entry past its lifetime is reissued")
    func expiry() throws {
        let cache = try makeCache(lifetime: 60)
        let now = Date()
        let first = try cache.certificate(for: "example.com", now: now)
        let later = try cache.certificate(for: "example.com", now: now.addingTimeInterval(120))
        #expect(first.serialNumber != later.serialNumber)
    }

    @Test("the cache stays within capacity")
    func eviction() throws {
        let cache = try makeCache(capacity: 50)
        for i in 0..<80 {
            _ = try cache.certificate(for: "host\(i).example")
        }
        #expect(cache.count <= 50)
        #expect(cache.statistics.evictions > 0)
    }

    /// Renewing the authority invalidates every cached leaf: each was signed by the
    /// outgoing root and fails the moment it leaves the trust store.
    @Test("clearing the cache is possible for authority renewal")
    func clearing() throws {
        let cache = try makeCache()
        _ = try cache.certificate(for: "example.com")
        cache.removeAll()
        #expect(cache.count == 0)
    }

    @Test("an address target is certified too, for a CONNECT with no SNI")
    func addressTarget() throws {
        let cache = try makeCache()
        let certificate = try cache.certificate(for: "93.184.216.34")
        let san = try #require(try certificate.extensions.subjectAlternativeNames)
        let hasIP = san.contains { if case .ipAddress = $0 { return true } else { return false } }
        #expect(hasIP)
    }
}
