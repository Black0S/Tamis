import Foundation
import Crypto
import X509
import SwiftASN1

public enum TLSError: Error, Sendable, Equatable {
    case invalidHostname(String)
    case notACertificateAuthority
    case expired
}

/// The local root that makes HTTPS filtering possible.
///
/// This is the most privileged thing Tamis ever creates: anything holding this key can
/// impersonate every site on the machine. Two consequences shape the design.
///
/// - The private key is generated here but **kept by the daemon**, which never sends it
///   anywhere. The proxy — tens of thousands of lines exposed to hostile TLS, HTML and
///   downloaded rules — asks for a signed leaf and never sees the key. A complete
///   compromise of the proxy therefore cannot exfiltrate the authority.
/// - Ten years of validity, because a root that expires breaks every site at once. The
///   answer to a compromised key is uninstalling, not waiting for it to lapse.
public struct CertificateAuthority: Sendable {
    public let certificate: Certificate
    public let privateKey: Certificate.PrivateKey

    /// Ten years. Expiry is handled by warning and renewal (see SPEC §7.5), never by
    /// letting it lapse under a running installation.
    public static let validity: TimeInterval = 10 * 365 * 24 * 3600

    /// Backdated an hour so a machine whose clock is slightly behind does not reject a
    /// certificate the moment it is created.
    public static let backdating: TimeInterval = 3600

    public init(certificate: Certificate, privateKey: Certificate.PrivateKey) {
        self.certificate = certificate
        self.privateKey = privateKey
    }

    /// Generates a fresh authority.
    ///
    /// - Parameter machineName: included in the common name, which makes uninstall
    ///   able to target the right certificate and keeps several machines' roots
    ///   distinguishable if a backup ever mixes them.
    public static func generate(
        machineName: String = Host.current().localizedName ?? "Mac",
        now: Date = Date()
    ) throws -> CertificateAuthority {
        let key = P256.Signing.PrivateKey()
        let privateKey = Certificate.PrivateKey(key)

        let name = try DistinguishedName {
            CommonName("Tamis Local CA (\(machineName))")
            OrganizationName("Tamis")
        }

        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: privateKey.publicKey,
            notValidBefore: now.addingTimeInterval(-backdating),
            notValidAfter: now.addingTimeInterval(validity),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                // maxPathLength 0: this root may sign leaves, never another CA. If the
                // key ever leaked, it still cannot mint an intermediate.
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(hash: privateKey.publicKey)
            },
            issuerPrivateKey: privateKey
        )

        return CertificateAuthority(certificate: certificate, privateKey: privateKey)
    }

    public var commonName: String {
        certificate.subject.description
    }

    /// DER bytes, for installing into the system trust store.
    public func certificateDER() throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }

    public var expiresAt: Date { certificate.notValidAfter }

    /// Whether renewal should already be under way (SPEC §7.5: warn at T-90 days).
    public func needsRenewal(now: Date = Date(), warningWindow: TimeInterval = 90 * 24 * 3600) -> Bool {
        expiresAt.timeIntervalSince(now) < warningWindow
    }
}
