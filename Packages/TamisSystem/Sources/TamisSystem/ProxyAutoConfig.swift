import Foundation

/// The proxy auto-configuration script macOS hands to every application.
///
/// Three constraints shape it, and each one rules out the obvious implementation.
///
/// **No `dnsResolve`.** The function exists and is tempting — it would let the script
/// decide on an address rather than a name. But a PAC is evaluated for every request,
/// by every application, and `dnsResolve` performs a lookup: the script that decides
/// where DNS traffic goes would itself be generating DNS traffic, through a resolver it
/// is in the middle of configuring. Only string matching here.
///
/// **No linear scan.** The exclusion list holds around four and a half thousand hosts,
/// and a PAC runs on the request path. Testing them one by one would put thousands of
/// comparisons in front of every connection. The hosts go into an object and the script
/// walks up the labels instead: `mabanque.bnpparibas` costs two lookups, not four
/// thousand comparisons.
///
/// **Fail open.** If Tamis is not answering, the script must say `DIRECT` rather than
/// point at a dead port. A machine whose owner closed the app should browse normally,
/// not stop browsing.
public enum ProxyAutoConfig {

    /// Networks and suffixes that never go through the proxy, whatever else is
    /// configured.
    ///
    /// Without these, a development server on `localhost:3000`, a Docker stack, or
    /// anything on the local network crosses the proxy for nothing: pure overhead, and
    /// a real risk of breaking local WebSocket or non-standard HTTP. Neither Zen nor
    /// AdGuard does this, and it shows.
    public static let localSuffixes = [".local", ".internal", ".test", ".localhost"]
    public static let localHosts = [
        "localhost", "host.docker.internal", "docker.internal",
    ]

    /// Builds the script.
    ///
    /// - Parameters:
    ///   - proxyPort: where Tamis listens on the loopback.
    ///   - directHosts: hosts that must never reach the proxy — the HTTPS exclusions.
    ///     Passing them here rather than letting the proxy tunnel them means banking
    ///     traffic never enters the process at all.
    public static func script(proxyPort: UInt16, directHosts: [String]) -> String {
        // Sorted so the file is stable: an unchanged configuration must produce an
        // identical script, or every rebuild looks like a change to the system.
        let entries = Set(directHosts.map { $0.lowercased() }).sorted()
        let table = entries.map { "\"\($0)\":1" }.joined(separator: ",")

        return """
        // Généré par Tamis. Ne pas modifier : ce fichier est réécrit à chaque
        // changement de configuration.
        //
        // Aucun appel à dnsResolve : un PAC est évalué à chaque requête, et résoudre un
        // nom ici ferait générer du trafic DNS au script qui décide où va le DNS.
        var TAMIS_DIRECT = {\(table)};
        var TAMIS_PROXY = "PROXY 127.0.0.1:\(proxyPort)";

        function FindProxyForURL(url, host) {
            host = host.toLowerCase();

            // Un nom sans point ne sort pas de cette machine ni de ce réseau.
            if (host.indexOf(".") === -1) return "DIRECT";

            \(localHosts.map { "if (host === \"\($0)\") return \"DIRECT\";" }
                .joined(separator: "\n            "))

            \(localSuffixes.map {
                "if (host.length > \($0.count) && host.slice(-\($0.count)) === \"\($0)\") return \"DIRECT\";"
            }.joined(separator: "\n            "))

            // Adresses littérales : plages privées et bouclage, sans résolution.
            if (isPrivateAddress(host)) return "DIRECT";

            // Exclusions HTTPS. On remonte les étiquettes plutôt que de parcourir la
            // table : deux recherches pour mabanque.bnpparibas, pas quatre mille
            // comparaisons.
            var candidate = host;
            while (candidate.length > 0) {
                if (TAMIS_DIRECT[candidate] === 1) return "DIRECT";
                var dot = candidate.indexOf(".");
                if (dot === -1) break;
                candidate = candidate.substring(dot + 1);
            }

            return TAMIS_PROXY;
        }

        function isPrivateAddress(host) {
            if (host.charAt(0) === "[") return host === "[::1]" || isPrivateIPv6(host);
            var parts = host.split(".");
            if (parts.length !== 4) return isPrivateIPv6(host);
            for (var i = 0; i < 4; i++) {
                if (parts[i].length === 0 || parts[i].length > 3) return false;
                for (var j = 0; j < parts[i].length; j++) {
                    var c = parts[i].charCodeAt(j);
                    if (c < 48 || c > 57) return false;
                }
            }
            var a = parseInt(parts[0], 10), b = parseInt(parts[1], 10);
            if (a === 127) return true;                       // 127.0.0.0/8
            if (a === 10) return true;                        // 10.0.0.0/8
            if (a === 192 && b === 168) return true;          // 192.168.0.0/16
            if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
            if (a === 169 && b === 254) return true;          // lien-local
            return false;
        }

        function isPrivateIPv6(host) {
            var h = host.charAt(0) === "[" ? host.substring(1, host.length - 1) : host;
            h = h.toLowerCase();
            if (h === "::1") return true;
            // fc00::/7 — adresses locales uniques.
            var first = h.split(":")[0];
            if (first.length === 0) return false;
            var value = parseInt(first, 16);
            return value >= 0xfc00 && value <= 0xfdff;
        }
        """
    }

    /// What the helper serves when Tamis is not answering.
    ///
    /// Not an empty file and not a stale script pointing at a closed port: an explicit
    /// `DIRECT` for everything. Somebody who quit the application should find their
    /// browsing unchanged, not broken.
    public static let failOpen = """
    // Tamis ne répond pas. Tout passe en direct — fermer l'application ne doit pas
    // couper la navigation.
    function FindProxyForURL(url, host) { return "DIRECT"; }
    """
}
