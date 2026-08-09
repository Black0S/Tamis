import Foundation
import Crypto
import X509
import SwiftASN1

/// Mints the short-lived certificates the proxy presents to clients.
///
/// One key pair is shared by every leaf. Generating a key is the expensive half of
/// making a certificate and signing is the cheap half, so reusing it turns each new
/// domain from milliseconds into microseconds. This is what mitmproxy does, and it
/// costs nothing in security: the leaf key is not a secret worth protecting — it
/// authenticates nothing on its own, and only the authority's signature gives it
/// meaning.
///
/// It also fits the process split. The proxy can hold this key; only the daemon holds
/// the authority's.
public struct LeafIssuer: Sendable {

    /// Seven days. Short enough to bound the damage of a leak, long enough that the
    /// cache is not constantly re-minting.
    public static let validity: TimeInterval = 7 * 24 * 3600
    public static let backdating: TimeInterval = 3600

    private let authority: CertificateAuthority
    /// Shared across every leaf — see the note above.
    private let leafKey: Certificate.PrivateKey

    public init(authority: CertificateAuthority) {
        self.authority = authority
        self.leafKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
    }

    public var publicKey: Certificate.PublicKey { leafKey.publicKey }
    public var privateKey: Certificate.PrivateKey { leafKey }

    /// Issues a certificate for one connection target.
    ///
    /// `target` is normally the SNI. When a client opens `CONNECT 93.184.216.34:443`
    /// there is no SNI at all, so the address itself is used and lands in the SAN as an
    /// IP rather than a DNS name — a certificate carrying an address as a DNS name is
    /// rejected by every client.
    public func issue(for target: String, now: Date = Date()) throws -> Certificate {
        let subjectAlternativeName = try Self.alternativeName(for: target)

        let subject = try DistinguishedName {
            CommonName(target)
        }

        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: leafKey.publicKey,
            notValidBefore: now.addingTimeInterval(-Self.backdating),
            notValidAfter: now.addingTimeInterval(Self.validity),
            issuer: authority.certificate.subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true, keyEncipherment: true))
                try ExtendedKeyUsage([.serverAuth])
                subjectAlternativeName
                SubjectKeyIdentifier(hash: leafKey.publicKey)
                AuthorityKeyIdentifier(
                    keyIdentifier: try? authority.certificate.extensions.subjectKeyIdentifier?.keyIdentifier
                )
            },
            issuerPrivateKey: authority.privateKey
        )
    }

    /// Builds the SAN, choosing between a DNS name and an IP address.
    static func alternativeName(for target: String) throws -> SubjectAlternativeNames {
        let bare = target.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))

        if let address = IPv4Address(bare) {
            return SubjectAlternativeNames([.ipAddress(ASN1OctetString(contentBytes: address.bytes[...]))])
        }
        if let address = IPv6Address(bare) {
            return SubjectAlternativeNames([.ipAddress(ASN1OctetString(contentBytes: address.bytes[...]))])
        }
        guard Self.isPlausibleHostname(bare) else { throw TLSError.invalidHostname(target) }
        return SubjectAlternativeNames([.dnsName(bare)])
    }

    static func isPlausibleHostname(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 253, !host.hasPrefix("."), !host.hasSuffix(".") else {
            return false
        }
        // A wildcard is legal in the leftmost label only.
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 1 else { return false }
        for (index, label) in labels.enumerated() {
            guard !label.isEmpty, label.count <= 63 else { return false }
            if label.contains("*") && index != 0 { return false }
            let allowed = label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "*" || $0 == "_" }
            guard allowed else { return false }
            // RFC 1123: a label may not begin or end with a hyphen, and must carry at
            // least one alphanumeric — otherwise `-` alone would earn a certificate.
            guard label.first != "-", label.last != "-" else { return false }
            guard label.contains(where: { $0.isLetter || $0.isNumber || $0 == "*" }) else { return false }
        }
        return true
    }
}

// MARK: - Address parsing

/// Minimal address parsers, so a certificate for `CONNECT 1.2.3.4:443` carries the
/// address in the form clients actually check.
struct IPv4Address {
    let bytes: [UInt8]

    init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 3, part.allSatisfy(\.isNumber),
                  let value = UInt8(part) else { return nil }
            out.append(value)
        }
        bytes = out
    }
}

struct IPv6Address {
    let bytes: [UInt8]

    init?(_ text: String) {
        guard text.contains(":") else { return nil }
        var storage = [UInt8](repeating: 0, count: 16)
        let parsed = storage.withUnsafeMutableBytes { raw -> Bool in
            text.withCString { cString in
                inet_pton(AF_INET6, cString, raw.baseAddress) == 1
            }
        }
        guard parsed else { return nil }
        bytes = storage
    }
}
