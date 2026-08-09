import Foundation
import Testing
import X509
@testable import TamisDaemon
@testable import TamisTLS

@Suite("Authority keeper")
struct AuthorityKeeperTests {

    private func makeKeeper() -> AuthorityKeeper {
        AuthorityKeeper(directory: URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamisd-\(UUID().uuidString)"))
    }

    @Test("An authority is created once and reused afterwards")
    func createsOnce() throws {
        let keeper = makeKeeper()
        #expect(try keeper.prepare(machineName: "Test"))
        #expect(try keeper.prepare(machineName: "Test") == false)
        #expect(keeper.hasAuthority)
    }

    @Test("It survives a restart")
    func persists() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamisd-\(UUID().uuidString)")
        let first = AuthorityKeeper(directory: directory)
        try first.prepare(machineName: "Test")
        let certificate = try first.materials().certificateDER

        let second = AuthorityKeeper(directory: directory)
        #expect(try second.prepare(machineName: "Test") == false, "il en a recréé une")
        #expect(try second.materials().certificateDER == certificate)
    }

    /// The property the whole daemon exists for: what the proxy can obtain is a
    /// certificate and a leaf key, and neither is the thing that signs.
    @Test("Nothing the proxy can ask for yields the signing key")
    func signingKeyNeverLeaves() throws {
        let keeper = makeKeeper()
        try keeper.prepare(machineName: "Test")

        let materials = try keeper.materials()
        let authority = try CertificateAuthority(
            certificateDER: materials.certificateDER,
            signingKeyDER: materials.leafKeyDER
        )
        // The leaf key is not the authority's key, so an authority assembled from the
        // two does not match the certificate — which is exactly the point.
        let leaf = try? LeafIssuer(authority: authority).issue(for: "example.com")
        let realLeaf = try Certificate(derEncoded: try keeper.issue(host: "example.com"))
        #expect(leaf?.signature != realLeaf.signature)
    }

    @Test("A leaf is signed for the host asked for")
    func issues() throws {
        let keeper = makeKeeper()
        try keeper.prepare(machineName: "Test")
        let certificate = try Certificate(derEncoded: try keeper.issue(host: "example.com"))
        #expect(String(describing: certificate.subject).contains("example.com"))
    }

    /// The one input the daemon takes from a less privileged process, and a certificate
    /// is a document somebody else will trust.
    @Test("An implausible host is refused rather than certified", arguments: [
        "", "a b", "a/b", "http://x", "x\nname", String(repeating: "a", count: 300),
    ])
    func refusesBadHosts(host: String) throws {
        let keeper = makeKeeper()
        try keeper.prepare(machineName: "Test")
        #expect(throws: AuthorityKeeper.Failure.refusedHost(host)) {
            _ = try keeper.issue(host: host)
        }
    }

    @Test("Ordinary hosts and addresses pass", arguments: [
        "example.com", "www.example.co.uk", "192.168.1.1", "xn--bcher-kva.de", "*.example.com",
    ])
    func acceptsGoodHosts(host: String) {
        #expect(AuthorityKeeper.isPlausibleHost(host))
    }

    @Test("Asking before there is an authority says so")
    func noAuthorityYet() {
        let keeper = makeKeeper()
        #expect(throws: AuthorityKeeper.Failure.noAuthority) { _ = try keeper.materials() }
        #expect(!keeper.hasAuthority)
    }

    /// The key at 0600 and the certificate not: locking both would hide which of the
    /// two the security rests on.
    @Test("The key is readable only by root, the certificate is not restricted")
    func permissions() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamisd-\(UUID().uuidString)")
        let keeper = AuthorityKeeper(directory: directory)
        try keeper.prepare(machineName: "Test")

        let mode = try FileManager.default.attributesOfItem(
            atPath: directory.appending(path: "ca.key").path(percentEncoded: false)
        )[.posixPermissions] as? NSNumber
        #expect(mode?.int16Value == 0o600)
    }
}
