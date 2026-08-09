import Darwin
import Foundation
import Security
import SystemConfiguration

/// What the Mac looks like before Tamis changes anything.
///
/// Every check here reads and nothing writes. That ordering is the point: the first
/// onboarding screen runs this *before asking for anything*, because the answers change
/// what there is to ask. A Mac already running another intercepting proxy does not need
/// a consent dialog, it needs to be told that two of them cannot share the system proxy
/// setting.
///
/// The one apparent exception is the port 53 check, which binds a socket and closes it
/// again. There is no read-only way to ask whether a port is free, and the alternative
/// — parsing `lsof` — is slower, needs a subprocess, and answers a different question.
public enum Preflight {

    public struct Finding: Sendable, Equatable, Identifiable {
        public enum Severity: Sendable, Equatable, Comparable {
            /// Worth knowing. Installation can proceed.
            case note
            /// Installation will work but something will not behave as expected.
            case warning
            /// Installing on top of this produces a broken machine.
            case blocking
        }

        public let id: String
        public let severity: Severity
        public let title: String
        public let detail: String
        /// What the user can do about it, in their own hands. Absent when there is
        /// nothing to do but know.
        public let remedy: String?

        public init(
            id: String, severity: Severity, title: String,
            detail: String, remedy: String? = nil
        ) {
            self.id = id
            self.severity = severity
            self.title = title
            self.detail = detail
            self.remedy = remedy
        }
    }

    public struct Report: Sendable, Equatable {
        public var findings: [Finding]

        public init(findings: [Finding] = []) { self.findings = findings }
        public var canProceed: Bool { !findings.contains { $0.severity == .blocking } }
        public var needsAttention: Bool { findings.contains { $0.severity != .note } }
    }

    /// Runs every check. Ordered by how early the answer changes what happens next.
    public static func run(bundle: Bundle = .main) -> Report {
        var findings: [Finding] = []
        findings.append(contentsOf: checkLocation(bundle: bundle))
        findings.append(contentsOf: checkExistingProxy())
        findings.append(contentsOf: checkInterceptingAuthorities())
        findings.append(contentsOf: checkResidualTamis())
        findings.append(contentsOf: checkPort53())
        findings.append(contentsOf: checkVPN())
        return Report(findings: findings.sorted { $0.severity > $1.severity })
    }

    // MARK: Where the app is

    /// An app run from the Downloads folder or from a mounted image is quarantined and
    /// path-randomised, so anything it installs points at a path that will not exist
    /// tomorrow.
    static func checkLocation(bundle: Bundle) -> [Finding] {
        // `pathExtension`, not a string suffix: a directory URL carries a trailing
        // slash, so `hasSuffix(".app")` is false for every real bundle.
        let url = bundle.bundleURL.standardizedFileURL
        guard url.pathExtension == "app" else { return [] }   // not a bundled build
        let path = url.path(percentEncoded: false)

        if path.contains("/AppTranslocation/") {
            return [Finding(
                id: "location.translocated", severity: .blocking,
                title: "Tamis s'exécute depuis un emplacement temporaire",
                detail: "macOS a déplacé l'application dans un dossier éphémère parce "
                      + "qu'elle vient d'être téléchargée. Tout ce qui serait installé "
                      + "pointerait vers un chemin qui n'existera plus.",
                remedy: "Déplacez Tamis dans le dossier Applications, puis relancez-le."
            )]
        }
        guard path.hasPrefix("/Applications/") || path.contains("/Applications/") else {
            return [Finding(
                id: "location.unusual", severity: .warning,
                title: "Tamis n'est pas dans le dossier Applications",
                detail: "Le service installé référencera \(path). Si l'application est "
                      + "déplacée ensuite, le filtrage s'arrêtera sans explication.",
                remedy: "Déplacez Tamis dans Applications avant l'installation."
            )]
        }
        return []
    }

    // MARK: Another proxy

    /// Read through SystemConfiguration rather than by running `scutil`: it is the same
    /// data, without a subprocess, and it cannot accidentally write.
    static func checkExistingProxy() -> [Finding] {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return [] }

        var configured: [String] = []
        if proxies[kSCPropNetProxiesHTTPEnable as String] as? Int == 1 {
            let host = proxies[kSCPropNetProxiesHTTPProxy as String] as? String ?? "?"
            let port = proxies[kSCPropNetProxiesHTTPPort as String] as? Int ?? 0
            configured.append("HTTP → \(host):\(port)")
        }
        if proxies[kSCPropNetProxiesHTTPSEnable as String] as? Int == 1 {
            let host = proxies[kSCPropNetProxiesHTTPSProxy as String] as? String ?? "?"
            let port = proxies[kSCPropNetProxiesHTTPSPort as String] as? Int ?? 0
            configured.append("HTTPS → \(host):\(port)")
        }
        if proxies[kSCPropNetProxiesProxyAutoConfigEnable as String] as? Int == 1 {
            let url = proxies[kSCPropNetProxiesProxyAutoConfigURLString as String] as? String ?? "?"
            configured.append("PAC → \(url)")
        }
        guard !configured.isEmpty else { return [] }

        return [Finding(
            id: "proxy.existing", severity: .blocking,
            title: "Un proxy est déjà configuré sur ce Mac",
            detail: configured.joined(separator: "  ·  ")
                  + ". Le réglage proxy du système n'a qu'une valeur : installer Tamis "
                  + "l'écraserait, et ce qui l'utilisait cesserait de fonctionner.",
            remedy: "Désactivez l'autre proxy, ou installez Tamis en sachant qu'il "
                  + "prendra sa place."
        )]
    }

    // MARK: Certificate authorities that intercept

    /// Root authorities belonging to other intercepting proxies.
    ///
    /// Their presence is not a fault — several can coexist in the keychain — but it
    /// tells the user something they may not know: another program has, or has had, the
    /// ability to read their HTTPS traffic.
    static func checkInterceptingAuthorities() -> [Finding] {
        let known = [
            "Charles Proxy", "Proxyman", "mitmproxy", "Fiddler",
            "Zen", "AdGuard", "Burp Suite", "Little Snitch",
        ]
        let found = installedAuthorities().filter { name in
            known.contains { name.localizedCaseInsensitiveContains($0) }
        }
        guard !found.isEmpty else { return [] }

        return [Finding(
            id: "ca.other", severity: .warning,
            title: "D'autres autorités d'interception sont installées",
            detail: found.sorted().joined(separator: ", ")
                  + ". Chacune peut déchiffrer votre trafic HTTPS. Tamis n'y touche pas.",
            remedy: "Si vous ne les utilisez plus, retirez-les depuis Trousseaux d'accès."
        )]
    }

    /// A Tamis authority left over from a previous installation.
    ///
    /// Worth its own check: a stale root that no running Tamis holds the key for is
    /// dead weight in the trust store, and the honest thing is to say so rather than
    /// quietly add a second one next to it.
    static func checkResidualTamis() -> [Finding] {
        let residual = installedAuthorities().filter { $0.contains("Tamis Local CA") }
        guard !residual.isEmpty else { return [] }

        return [Finding(
            id: "ca.residual", severity: .warning,
            title: residual.count == 1
                ? "Une autorité Tamis est déjà installée"
                : "\(residual.count) autorités Tamis sont déjà installées",
            detail: residual.sorted().joined(separator: ", ")
                  + ". Elle vient d'une installation précédente. Tamis en créerait une "
                  + "nouvelle à côté.",
            remedy: "La désinstallation les retire toutes."
        )]
    }

    /// Common names of every root the user trusts, read from the keychain.
    static func installedAuthorities() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let certificates = result as? [SecCertificate]
        else { return [] }

        return certificates.compactMap { certificate in
            var name: CFString?
            guard SecCertificateCopyCommonName(certificate, &name) == errSecSuccess else {
                return nil
            }
            return name as String?
        }
    }

    // MARK: Port 53

    /// Whether anything already answers DNS locally.
    ///
    /// Binding is the only way to ask. The socket is closed immediately and nothing on
    /// the machine observes it — but it is the one check here that is not purely a read,
    /// and that is worth saying rather than hiding.
    static func checkPort53() -> [Finding] {
        switch probeUDP(port: 53) {
        case .free, .needsPrivileges:
            return []
        case .inUse:
            return [Finding(
                id: "dns.occupied", severity: .blocking,
                title: "Le port 53 est déjà utilisé",
                detail: "Un autre résolveur écoute déjà — dnscrypt-proxy, AdGuard Home "
                      + "ou Pi-hole, par exemple. Deux résolveurs ne peuvent pas "
                      + "partager le port.",
                remedy: "Arrêtez l'autre résolveur, ou laissez Tamis filtrer uniquement "
                      + "via le proxy."
            )]
        }
    }

    enum PortState: Sendable, Equatable { case free, inUse, needsPrivileges }

    static func probeUDP(port: UInt16) -> PortState {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { return .free }
        defer { close(descriptor) }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = port.bigEndian

        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result != 0 else { return .free }
        // Below 1024 an unprivileged process is refused whether or not anyone is there,
        // so this answers "unknown", never "free".
        return errno == EADDRINUSE ? .inUse : .needsPrivileges
    }

    // MARK: VPN

    /// A VPN is not a problem, but it decides who resolves names.
    ///
    /// The test is the default route, not the existence of a tunnel interface. macOS
    /// keeps eight `utun` interfaces up at all times — for Private Relay, Handoff and
    /// the rest — each with an IPv6 link-local address and nothing else. Counting those
    /// as a VPN would put a warning on the first screen of every installation, and a
    /// warning that is always there is a warning nobody reads.
    ///
    /// So: if traffic leaves through a tunnel, say so. If a tunnel merely carries a
    /// routable address, that is a split tunnel and worth a smaller note.
    static func checkVPN() -> [Finding] {
        let primary = primaryInterface()
        if let primary, isTunnel(primary) {
            return [Finding(
                id: "vpn.default-route", severity: .warning,
                title: "Tout le trafic passe par un VPN",
                detail: "L'interface principale est \(primary). Beaucoup de VPN imposent "
                      + "leur propre résolveur : tant que le tunnel est ouvert, le "
                      + "filtrage DNS de Tamis peut être contourné. Le filtrage par le "
                      + "proxy, lui, continue.",
                remedy: nil
            )]
        }

        let routable = routableTunnelInterfaces()
        guard !routable.isEmpty else { return [] }
        return [Finding(
            id: "vpn.split", severity: .note,
            title: "Un VPN est connecté",
            detail: "Interface \(routable.sorted().joined(separator: ", ")), mais le "
                  + "trafic sort par \(primary ?? "une autre interface"). Seul ce qui "
                  + "passe par le tunnel échappe éventuellement au résolveur de Tamis.",
            remedy: nil
        )]
    }

    static func isTunnel(_ name: String) -> Bool {
        name.hasPrefix("utun") || name.hasPrefix("ppp") || name.hasPrefix("ipsec")
            || name.hasPrefix("tun")
    }

    /// The interface the default route uses, read from SystemConfiguration rather than
    /// by parsing `route` or the raw routing table.
    static func primaryInterface() -> String? {
        guard let store = SCDynamicStoreCreate(nil, "io.github.black0s.tamis.preflight" as CFString, nil, nil),
              let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString)
                  as? [String: Any]
        else { return nil }
        return global["PrimaryInterface"] as? String
    }

    /// Tunnels carrying an address something could actually be routed to — which is to
    /// say, not the link-local placeholders macOS keeps permanently.
    static func routableTunnelInterfaces() -> [String] {
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0, let first = addresses else { return [] }
        defer { freeifaddrs(addresses) }

        var found: Set<String> = []
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let name = String(cString: pointer.pointee.ifa_name)
            guard isTunnel(name), pointer.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  let address = pointer.pointee.ifa_addr
            else { continue }

            switch address.pointee.sa_family {
            case UInt8(AF_INET):
                found.insert(name)
            case UInt8(AF_INET6):
                // fe80::/10 is link-local: assigned by the kernel, routed nowhere.
                let isLinkLocal = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    let bytes = $0.pointee.sin6_addr.__u6_addr.__u6_addr8
                    return bytes.0 == 0xfe && (bytes.1 & 0xc0) == 0x80
                }
                if !isLinkLocal { found.insert(name) }
            default:
                continue
            }
        }
        return Array(found)
    }
}
