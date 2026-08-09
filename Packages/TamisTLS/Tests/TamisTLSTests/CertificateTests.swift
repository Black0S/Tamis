import Foundation
import Testing
import X509
import SwiftASN1
@testable import TamisTLS

@Suite("Certificate authority")
struct CertificateAuthorityTests {

    @Test("the root is a CA that cannot mint another CA")
    func rootConstraints() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let basic = try #require(try ca.certificate.extensions.basicConstraints)
        // maxPathLength 0: even a leaked key cannot produce an intermediate.
        #expect(basic == .isCertificateAuthority(maxPathLength: 0))

        let usage = try #require(try ca.certificate.extensions.keyUsage)
        #expect(usage.keyCertSign)
        #expect(!usage.digitalSignature)
    }

    @Test("the machine name is in the common name, so uninstall can target it")
    func commonNameCarriesMachine() throws {
        let ca = try CertificateAuthority.generate(machineName: "MacBook-de-Tao")
        #expect(ca.commonName.contains("Tamis Local CA"))
        #expect(ca.commonName.contains("MacBook-de-Tao"))
    }

    /// A root that expires breaks every site at once, so it is generated with a long
    /// life and handled by warning and renewal instead.
    @Test("validity is ten years, backdated an hour for clock skew")
    func validity() throws {
        let now = Date()
        let ca = try CertificateAuthority.generate(machineName: "TestMac", now: now)
        #expect(ca.certificate.notValidBefore < now)
        #expect(ca.certificate.notValidBefore > now.addingTimeInterval(-7200))

        let years = ca.expiresAt.timeIntervalSince(now) / (365 * 24 * 3600)
        #expect(years > 9.9 && years < 10.1)
        #expect(!ca.needsRenewal(now: now))
    }

    @Test("renewal is flagged ninety days out, not on the day")
    func renewalWarning() throws {
        let now = Date()
        let ca = try CertificateAuthority.generate(machineName: "TestMac", now: now)
        let almostExpired = ca.expiresAt.addingTimeInterval(-80 * 24 * 3600)
        #expect(ca.needsRenewal(now: almostExpired))
    }

    @Test("the certificate serialises to DER for the trust store")
    func derEncoding() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let der = try ca.certificateDER()
        #expect(der.count > 200)
        #expect(der.first == 0x30)   // SEQUENCE — a well-formed certificate
        // And it round-trips.
        let parsed = try Certificate(derEncoded: der)
        #expect(parsed.subject == ca.certificate.subject)
    }

    @Test("each authority is distinct")
    func uniqueness() throws {
        let a = try CertificateAuthority.generate(machineName: "TestMac")
        let b = try CertificateAuthority.generate(machineName: "TestMac")
        #expect(a.certificate.serialNumber != b.certificate.serialNumber)
        #expect(a.certificate.publicKey != b.certificate.publicKey)
    }
}

@Suite("Leaf issuance")
struct LeafIssuerTests {

    @Test("a leaf is a server certificate, never a CA")
    func leafConstraints() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let leaf = try LeafIssuer(authority: ca).issue(for: "example.com")

        #expect(try leaf.extensions.basicConstraints == .notCertificateAuthority)
        let eku = try #require(try leaf.extensions.extendedKeyUsage)
        #expect(eku.contains(.serverAuth))
        #expect(!eku.contains(.clientAuth))
    }

    @Test("a hostname lands in the SAN as a DNS name")
    func dnsSAN() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let leaf = try LeafIssuer(authority: ca).issue(for: "sub.example.com")
        let san = try #require(try leaf.extensions.subjectAlternativeNames)
        #expect(san.contains(.dnsName("sub.example.com")))
    }

    /// `CONNECT 93.184.216.34:443` carries no SNI. A certificate that put the address
    /// in a DNS name would be rejected by every client.
    @Test("an address lands in the SAN as an IP, not a DNS name")
    func ipSAN() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let issuer = LeafIssuer(authority: ca)

        let v4 = try issuer.issue(for: "93.184.216.34")
        let v4SAN = try #require(try v4.extensions.subjectAlternativeNames)
        #expect(v4SAN.contains(.ipAddress(ASN1OctetString(contentBytes: [93, 184, 216, 34][...]))))
        #expect(!v4SAN.contains(.dnsName("93.184.216.34")))

        let v6 = try issuer.issue(for: "[2606:4700:4700::1111]")
        let v6SAN = try #require(try v6.extensions.subjectAlternativeNames)
        let hasIP = v6SAN.contains { if case .ipAddress = $0 { return true } else { return false } }
        #expect(hasIP)
    }

    @Test("nonsense targets are refused rather than certified", arguments: [
        "", ".", "..", "example..com", "sub.*.example.com", "-", String(repeating: "a", count: 300),
    ])
    func invalidHostnames(target: String) throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let issuer = LeafIssuer(authority: ca)
        #expect(throws: TLSError.self) {
            _ = try issuer.issue(for: target)
        }
    }

    @Test("a wildcard is accepted in the leftmost label only")
    func wildcards() throws {
        #expect(LeafIssuer.isPlausibleHostname("*.example.com"))
        #expect(!LeafIssuer.isPlausibleHostname("sub.*.example.com"))
    }

    /// Generating a key is the expensive half of making a certificate; signing is the
    /// cheap half. Sharing one key across every leaf is what turns a new domain from
    /// milliseconds into microseconds.
    @Test("every leaf shares one key pair")
    func sharedKey() throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let issuer = LeafIssuer(authority: ca)
        let a = try issuer.issue(for: "one.example")
        let b = try issuer.issue(for: "two.example")
        #expect(a.publicKey == b.publicKey)
        #expect(a.serialNumber != b.serialNumber)
    }

    @Test("leaves live seven days, backdated for clock skew")
    func leafValidity() throws {
        let now = Date()
        let ca = try CertificateAuthority.generate(machineName: "TestMac", now: now)
        let leaf = try LeafIssuer(authority: ca).issue(for: "example.com", now: now)
        #expect(leaf.notValidBefore < now)
        let days = leaf.notValidAfter.timeIntervalSince(now) / 86_400
        #expect(days > 6.9 && days < 7.1)
    }
}

@Suite("Chain verification")
struct ChainVerificationTests {

    /// The only test that proves the whole thing works: a client presented with this
    /// leaf, trusting this root, must accept it.
    @Test("a leaf validates against the authority that issued it")
    func chainIsValid() async throws {
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let leaf = try LeafIssuer(authority: ca).issue(for: "example.com")

        var verifier = Verifier(rootCertificates: CertificateStore([ca.certificate])) {
            RFC5280Policy(validationTime: Date())
        }
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore())

        guard case .validCertificate = result else {
            Issue.record("chain did not validate: \(result)")
            return
        }
    }

    @Test("a leaf does not validate against a different authority")
    func foreignRootIsRejected() async throws {
        let ours = try CertificateAuthority.generate(machineName: "TestMac")
        let theirs = try CertificateAuthority.generate(machineName: "OtherMac")
        let leaf = try LeafIssuer(authority: ours).issue(for: "example.com")

        var verifier = Verifier(rootCertificates: CertificateStore([theirs.certificate])) {
            RFC5280Policy(validationTime: Date())
        }
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore())

        guard case .couldNotValidate = result else {
            Issue.record("a foreign root accepted our leaf")
            return
        }
    }

    @Test("an expired leaf is rejected")
    func expiredLeafIsRejected() async throws {
        let longAgo = Date().addingTimeInterval(-30 * 24 * 3600)
        let ca = try CertificateAuthority.generate(machineName: "TestMac")
        let leaf = try LeafIssuer(authority: ca).issue(for: "example.com", now: longAgo)

        var verifier = Verifier(rootCertificates: CertificateStore([ca.certificate])) {
            RFC5280Policy(validationTime: Date())
        }
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore())

        guard case .couldNotValidate = result else {
            Issue.record("an expired leaf was accepted")
            return
        }
    }
}
