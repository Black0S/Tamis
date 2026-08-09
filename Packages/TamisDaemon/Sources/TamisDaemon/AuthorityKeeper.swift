import Foundation
import TamisTLS

/// Holds the authority, and is the only thing that ever reads its key.
///
/// Kept separate from the XPC plumbing so the part that matters can be tested without a
/// daemon, a launchd job or a privileged installation.
public final class AuthorityKeeper: @unchecked Sendable {

    public enum Failure: Error, Equatable {
        case noAuthority
        case unreadable(String)
        case refusedHost(String)
    }

    /// Where the key lives when the daemon runs for real: root-owned, 0600, outside
    /// any bundle the user can write to.
    public static let defaultDirectory = URL(
        fileURLWithPath: "/Library/Application Support/Tamis/Authority"
    )

    private let directory: URL
    private let lock = NSLock()
    private var authority: CertificateAuthority?
    private var issuer: LeafIssuer?

    public init(directory: URL = AuthorityKeeper.defaultDirectory) {
        self.directory = directory
    }

    private var certificateURL: URL { directory.appending(path: "ca.der") }
    private var keyURL: URL { directory.appending(path: "ca.key") }

    // MARK: Lifecycle

    /// Creates the authority if there is none, and loads it either way.
    @discardableResult
    public func prepare(machineName: String = Host.current().localizedName ?? "Mac") throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        if authority != nil { return false }

        if let loaded = try? loadLocked() {
            authority = loaded
            issuer = LeafIssuer(authority: loaded)
            return false
        }

        let created = try CertificateAuthority.generate(machineName: machineName)
        guard let keyDER = created.signingKeyDER() else {
            throw Failure.unreadable("l'autorité créée n'expose pas sa clé")
        }
        try write(certificateDER: try created.certificateDER(), keyDER: keyDER)
        authority = created
        issuer = LeafIssuer(authority: created)
        return true
    }

    private func loadLocked() throws -> CertificateAuthority {
        guard let certificate = try? Data(contentsOf: certificateURL),
              let key = try? Data(contentsOf: keyURL)
        else { throw Failure.noAuthority }
        do {
            return try CertificateAuthority(
                certificateDER: Array(certificate), signingKeyDER: Array(key)
            )
        } catch {
            throw Failure.unreadable("\(error)")
        }
    }

    /// The key at 0600, the certificate not — locking both would hide which of the two
    /// the security actually rests on.
    private func write(certificateDER: [UInt8], keyDER: [UInt8]) throws {
        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try Data(certificateDER).write(to: certificateURL, options: .atomic)
            try Data(keyDER).write(to: keyURL, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: keyURL.path(percentEncoded: false)
            )
        } catch {
            throw Failure.unreadable("\(error)")
        }
    }

    // MARK: What the proxy may ask for

    /// The certificate and the shared leaf key. Never the signing key.
    public func materials() throws -> (certificateDER: [UInt8], leafKeyDER: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        guard let authority, let issuer else { throw Failure.noAuthority }
        return (try authority.certificateDER(), issuer.privateKeyDER)
    }

    /// Signs a leaf for one host.
    ///
    /// The host is checked before it reaches the certificate builder. This is the one
    /// input the daemon takes from a less privileged process, so it is also the only
    /// place a malformed value could do anything — and a certificate is a document
    /// somebody else will trust.
    public func issue(host: String) throws -> [UInt8] {
        guard Self.isPlausibleHost(host) else { throw Failure.refusedHost(host) }
        lock.lock(); defer { lock.unlock() }
        guard let issuer else { throw Failure.noAuthority }
        do {
            var serializer = DERSerializerBox()
            return try serializer.der(of: try issuer.issue(for: host))
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure.unreadable("\(error)")
        }
    }

    public var hasAuthority: Bool {
        lock.lock(); defer { lock.unlock() }
        return authority != nil
    }

    /// A host name, or an address. Anything else is refused rather than certified.
    static func isPlausibleHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 253 else { return false }
        if host.hasPrefix("[") && host.hasSuffix("]") { return host.count <= 47 }
        // Letters, digits, dots, hyphens and colons for an address. No spaces, no
        // slashes, nothing that could be read as a second name.
        return host.allSatisfy { character in
            character.isLetter || character.isNumber
                || character == "." || character == "-" || character == ":"
                || character == "_" || character == "*"
        }
    }
}
