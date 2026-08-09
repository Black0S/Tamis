import Darwin
import Foundation
import Testing
@testable import TamisSystem

@Suite("Preflight")
struct PreflightTests {

    private func makeBundle(at path: String) throws -> Bundle {
        let url = URL(fileURLWithPath: path)
        let contents = url.appending(path: "Contents")
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        try (["CFBundleIdentifier": "io.github.black0s.tamis.test"] as NSDictionary)
            .write(to: contents.appending(path: "Info.plist"))
        return try #require(Bundle(url: url))
    }

    /// A downloaded app is run from a randomised read-only copy, so anything it
    /// installs would point at a path that stops existing the moment it quits.
    @Test("Running from app translocation blocks installation")
    func translocated() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "AppTranslocation/\(UUID().uuidString)/d")
        let bundle = try makeBundle(at: root.appending(path: "Tamis.app")
            .path(percentEncoded: false))
        defer { try? FileManager.default.removeItem(at: root) }

        let findings = Preflight.checkLocation(bundle: bundle)
        #expect(findings.first?.severity == .blocking)
        #expect(findings.first?.remedy?.contains("Applications") == true)
    }

    @Test("Running from somewhere unusual warns without blocking")
    func unusualLocation() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-preflight-\(UUID().uuidString)")
        let bundle = try makeBundle(at: root.appending(path: "Tamis.app")
            .path(percentEncoded: false))
        defer { try? FileManager.default.removeItem(at: root) }

        let findings = Preflight.checkLocation(bundle: bundle)
        #expect(findings.first?.severity == .warning)
        // The path is quoted, because "somewhere unusual" is not actionable on its own.
        #expect(findings.first?.detail.contains(root.lastPathComponent) == true)
    }

    /// The test bundle is not an `.app` at all, and a check that fired on that would
    /// fire on every `swift test` run.
    @Test("A non-bundled build is not a location problem")
    func unbundled() {
        #expect(Preflight.checkLocation(bundle: .main).isEmpty)
    }

    @Test("A blocking finding stops installation, a warning does not")
    func canProceed() {
        let warning = Preflight.Finding(
            id: "w", severity: .warning, title: "t", detail: "d"
        )
        let blocking = Preflight.Finding(
            id: "b", severity: .blocking, title: "t", detail: "d"
        )
        #expect(Preflight.Report(findings: [warning]).canProceed)
        #expect(Preflight.Report(findings: [warning]).needsAttention)
        #expect(Preflight.Report(findings: [blocking]).canProceed == false)
        #expect(Preflight.Report(findings: []).needsAttention == false)
    }

    /// A port somebody holds must read as taken. This is the one check that binds, so
    /// it is the one worth proving rather than trusting.
    @Test("An occupied port reads as occupied, a free one as free")
    func portProbe() throws {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = 0
        _ = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        var bound = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length)
            }
        }
        let port = UInt16(bigEndian: bound.sin_port)

        #expect(Preflight.probeUDP(port: port) == .inUse)
        close(descriptor)
        #expect(Preflight.probeUDP(port: port) == .free)
    }

    /// Below 1024 an unprivileged process is refused whether or not anyone is listening,
    /// so the answer must be "unknown" and never "free" — otherwise the DNS check would
    /// clear a port it never actually tested.
    @Test("A privileged port reads as unknown, not as free")
    func privilegedPort() {
        #expect(Preflight.probeUDP(port: 53) == .needsPrivileges)
    }

    @Test("Tunnel interfaces are recognised by name", arguments: [
        ("utun0", true), ("ppp0", true), ("ipsec0", true), ("tun3", true),
        ("en0", false), ("lo0", false), ("bridge100", false), ("awdl0", false),
    ])
    func tunnelNames(name: String, expected: Bool) {
        #expect(Preflight.isTunnel(name) == expected)
    }

    /// macOS keeps eight `utun` interfaces up permanently, each with nothing but an
    /// IPv6 link-local address. Counting those as a VPN would put a warning on the
    /// first screen of every installation, and a warning that is always there is a
    /// warning nobody reads. Checked against this Mac, whatever it happens to be.
    @Test("The kernel's permanent tunnels are not mistaken for a VPN")
    func linkLocalTunnelsIgnored() {
        let routable = Preflight.routableTunnelInterfaces()
        let primary = Preflight.primaryInterface()

        // Either the machine really is on a VPN, in which case the primary interface is
        // a tunnel and saying so is correct; or it is not, and no tunnel may be
        // reported on link-local addresses alone.
        if let primary, Preflight.isTunnel(primary) {
            #expect(!routable.isEmpty, "l'interface principale est un tunnel sans adresse routable")
        } else {
            let findings = Preflight.checkVPN()
            #expect(findings.allSatisfy { $0.severity == .note },
                    "un tunnel lien-local ne doit pas produire d'avertissement")
        }
    }

    /// The whole report has to run without writing anything, on whatever machine it
    /// finds itself.
    @Test("The full report runs and answers")
    func fullReport() {
        let report = Preflight.run()
        #expect(Set(report.findings.map(\.id)).count == report.findings.count,
                "deux constats partagent un identifiant")
        for finding in report.findings {
            #expect(!finding.title.isEmpty)
            #expect(finding.detail.count > 20, "\(finding.id) n'explique rien")
        }
    }
}
