import Foundation
import Security
import X509
import SwiftASN1

/// Validates an origin's certificate chain the way the operating system would.
///
/// When Tamis intercepts a connection, the client stops checking the origin and trusts
/// us instead. Whatever rigour it would have applied is now our responsibility: a lax
/// check here silently *lowers* the user's security, and the browser shows a padlock
/// either way.
///
/// The evaluation deliberately goes through `SecTrust` rather than a bundled root list.
/// BoringSSL, which backs swift-nio-ssl, does not read the macOS keychain — so a
/// bundled list would reject every locally trusted authority. On a developer's machine
/// that means `mkcert`, Caddy's local CA and any corporate root, and the failure would
/// look like a network fault rather than a policy decision.
public enum SystemTrustVerifier {

    public enum Result: Sendable, Equatable {
        case trusted
        /// The chain did not validate. `isNameMismatch` separates "wrong certificate
        /// for this host" from "untrusted issuer", which the UI reports differently.
        case rejected(reason: String, isNameMismatch: Bool)
    }

    /// Evaluates a DER-encoded chain, leaf first, against the system trust store.
    ///
    /// - Parameter hostname: checked against the certificate's names. Pass `nil` only
    ///   when there is genuinely no name to check — never to skip the check.
    public static func evaluate(chain derChain: [[UInt8]], hostname: String?) -> Result {
        guard !derChain.isEmpty else {
            return .rejected(reason: "empty certificate chain", isNameMismatch: false)
        }

        let certificates = derChain.compactMap { der -> SecCertificate? in
            SecCertificateCreateWithData(nil, Data(der) as CFData)
        }
        guard certificates.count == derChain.count else {
            return .rejected(reason: "malformed certificate in chain", isNameMismatch: false)
        }

        // SecPolicyCreateSSL(true, host) performs the full server policy: chain
        // building, validity dates, key usage, revocation where available, and the
        // name check.
        let policy = SecPolicyCreateSSL(true, hostname as CFString?)

        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else {
            return .rejected(reason: "could not build trust object (\(status))", isNameMismatch: false)
        }

        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            return .trusted
        }

        let message = (error as Error?)?.localizedDescription ?? "certificate not trusted"
        return .rejected(reason: message, isNameMismatch: Self.looksLikeNameMismatch(error))
    }

    /// Evaluates against an explicit anchor instead of the system store.
    ///
    /// Only used by tests and by the local test harness — production always evaluates
    /// against what the machine actually trusts.
    public static func evaluate(
        chain derChain: [[UInt8]],
        hostname: String?,
        anchors: [[UInt8]]
    ) -> Result {
        guard !derChain.isEmpty else {
            return .rejected(reason: "empty certificate chain", isNameMismatch: false)
        }
        let certificates = derChain.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        let anchorCertificates = anchors.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        guard certificates.count == derChain.count, anchorCertificates.count == anchors.count else {
            return .rejected(reason: "malformed certificate", isNameMismatch: false)
        }

        let policy = SecPolicyCreateSSL(true, hostname as CFString?)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust) == errSecSuccess,
              let trust else {
            return .rejected(reason: "could not build trust object", isNameMismatch: false)
        }
        SecTrustSetAnchorCertificates(trust, anchorCertificates as CFArray)
        // Without this the system roots are still consulted, and the test would not be
        // proving what it claims to.
        SecTrustSetAnchorCertificatesOnly(trust, true)

        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) { return .trusted }
        let message = (error as Error?)?.localizedDescription ?? "certificate not trusted"
        return .rejected(reason: message, isNameMismatch: Self.looksLikeNameMismatch(error))
    }

    /// `SecTrust` reports the specific failure inside the error's underlying details.
    /// A name mismatch means the origin is serving someone else's certificate, which is
    /// a different conversation from an unknown issuer.
    static func looksLikeNameMismatch(_ error: CFError?) -> Bool {
        guard let error = error as Error? else { return false }
        let description = error.localizedDescription.lowercased()
        return description.contains("hostname mismatch")
            || description.contains("does not match")
            || description.contains("not valid for the name")
    }
}
