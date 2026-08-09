import CryptoKit
import Foundation

/// Where Tamis keeps its certificate authority.
///
/// **The key is the whole security question of this project.** Whoever holds it can
/// mint a certificate for any site, so it lives in `tamisd` — root-owned, 0600 — and
/// the proxy asks for leaves over XPC without ever seeing it.
///
/// This type is what remains for the unprivileged side: reading the certificate, which
/// is public by nature. It writes a key only in the development path, where the proxy
/// tool generates its own throwaway authority and no daemon is installed.
public struct AuthorityStore: Sendable {

    public enum Failure: Error, Sendable, Equatable {
        case notWritable(String)
        case missing
    }

    /// Stated in one place so the onboarding and the settings screen cannot drift.
    public static let keyProtectionCaveat = """
    La clé de l'autorité ne quitte jamais le service privilégié : il signe les \
    certificats sur demande et n'expose aucun moyen de la lire. Une compromission du \
    proxy donnerait des certificats le temps de la compromission, pas la capacité d'en \
    fabriquer ensuite.
    """

    public let directory: URL

    public init(directory: URL? = nil) {
        self.directory = directory ?? Installation.supportDirectory.appending(path: "Authority")
    }

    public var certificateURL: URL { directory.appending(path: "ca.pem") }
    public var privateKeyURL: URL { directory.appending(path: "ca.key") }

    public var exists: Bool {
        FileManager.default.fileExists(atPath: certificateURL.path(percentEncoded: false))
            && FileManager.default.fileExists(atPath: privateKeyURL.path(percentEncoded: false))
    }

    /// Writes the pair, with the key readable only by its owner.
    ///
    /// The certificate is public by nature — it goes into the system trust store — so
    /// only the key is restricted. Writing both at 0600 would be theatre that hides
    /// which of the two actually matters.
    public func store(certificatePEM: String, privateKeyDER: [UInt8]) throws {
        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try Data(certificatePEM.utf8).write(to: certificateURL, options: .atomic)
            try Data(privateKeyDER).write(to: privateKeyURL, options: [.atomic, .completeFileProtection])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: privateKeyURL.path(percentEncoded: false)
            )
        } catch {
            throw Failure.notWritable("\(error)")
        }
    }

    public func certificatePEM() throws -> String {
        guard let text = try? String(contentsOf: certificateURL, encoding: .utf8), !text.isEmpty
        else { throw Failure.missing }
        return text
    }

    public func privateKeyDER() throws -> [UInt8] {
        guard let data = try? Data(contentsOf: privateKeyURL), !data.isEmpty
        else { throw Failure.missing }
        return Array(data)
    }

    /// Removes both. Called by the uninstall, and the reason the authority in the
    /// keychain is removed at the same time: a trusted root whose key is gone is a root
    /// nobody can use and everybody still trusts.
    public func remove() {
        try? FileManager.default.removeItem(at: directory)
    }

    /// DER to PEM, since that is what `security add-trusted-cert` reads.
    public static func pem(fromDER der: [UInt8]) -> String {
        "-----BEGIN CERTIFICATE-----\n"
            + Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            + "\n-----END CERTIFICATE-----\n"
    }
}
