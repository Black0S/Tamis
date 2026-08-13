import Foundation
import JavaScriptCore
import Security

/// Five things Tamis claims, checked against the running machine.
///
/// The onboarding used to end on a screen that said these checks "will run at the first
/// real installation". They never ran. That was the worst kind of placeholder — a
/// promise of verification is *more* reassuring than no promise at all, so an unkept one
/// leaves somebody more confident than if it had said nothing.
///
/// Every check here contacts something real. None of them reads a flag Tamis set about
/// itself, because a program asserting its own success is exactly what the failed
/// rollback did.
///
/// **The first check is not decorative.** A resolver that never answers, while the
/// system DNS points at it, is a Mac that cannot resolve anything — including after a
/// reboot, because network settings survive one. That happened. The install script now
/// refuses to redirect DNS until the resolver replies, and this screen is where the
/// owner can see it for themselves afterwards.
public enum Verification {

    public struct Check: Sendable, Identifiable {
        public let id: String
        public let title: String
        /// What a failure would mean, in the user's terms rather than the system's.
        public let matters: String
        public let passed: Bool
        public let detail: String
    }

    /// Runs all five. Never throws: a check that cannot run is a check that failed, and
    /// saying so beats an empty row.
    public static func run(pacPort: UInt16 = 7655, proxyPort: UInt16 = 7654) async -> [Check] {
        var checks: [Check] = []
        checks.append(resolverAnswers())
        checks.append(await pacIsServed(port: pacPort))
        checks.append(await bankingIsExcluded(port: pacPort, proxyPort: proxyPort))
        checks.append(authorityIsTrusted())
        checks.append(signingKeyIsOutOfReach())
        return checks
    }

    // MARK: 1 — the one that took a Mac offline

    static func resolverAnswers() -> Check {
        let answer = shell("/usr/bin/dig", ["+short", "+time=2", "+tries=1",
                                            "@127.0.0.1", "example.com"])
        // An answer, not merely an exit code: a resolver that accepts the connection and
        // returns nothing is still a resolver that cannot be trusted with the machine's
        // DNS.
        let resolved = (answer?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false)
        return Check(
            id: "resolver",
            title: "Le résolveur DNS répond",
            matters: "Si ce point échoue alors que le DNS du système pointe vers Tamis, "
                   + "ce Mac ne peut plus résoudre aucun nom — y compris après "
                   + "redémarrage, car les réglages réseau y survivent.",
            passed: resolved,
            detail: resolved
                ? "127.0.0.1:53 a répondu pour example.com"
                : "127.0.0.1:53 n'a rien renvoyé"
        )
    }

    // MARK: 2 — the file macOS asks for on every connection

    static func pacIsServed(port: UInt16) async -> Check {
        let text = await fetch(Installation.pacURL(port: port))
        // `new Function` parses without executing: a PAC that macOS cannot parse is a
        // PAC macOS silently ignores.
        let parses = text.map { JSContext()?.evaluateScript("new Function(\($0.asJSString)))") != nil } ?? false
        let usable = (text?.contains("FindProxyForURL") == true) && parses
        return Check(
            id: "pac",
            title: "La configuration proxy est servie et lisible",
            matters: "macOS demande ce fichier à chaque connexion. S'il ne répond pas, "
                   + "le système peut cesser de router quoi que ce soit.",
            passed: usable,
            detail: usable
                ? "\(Installation.pacURL(port: port)) — \((text?.count ?? 0).formatted()) octets"
                : "aucune réponse utilisable sur le port \(port)"
        )
    }

    // MARK: 3 — the claim the whole exclusion list exists for

    /// Runs the served PAC over a banking host and requires the answer to be `DIRECT`.
    ///
    /// This is the promise that matters most and the only one that can be checked
    /// without asking anybody to trust Tamis: the script macOS will actually evaluate
    /// is fetched, evaluated here the same way, and asked about a bank.
    static func bankingIsExcluded(port: UInt16, proxyPort: UInt16) async -> Check {
        guard let script = await fetch(Installation.pacURL(port: port)),
              let context = JSContext()
        else {
            return Check(
                id: "banking", title: "Les sites bancaires ne passent pas par Tamis",
                matters: bankingMatters, passed: false,
                detail: "la configuration proxy n'a pas pu être lue"
            )
        }

        context.evaluateScript(script)
        let host = "www.bnpparibas"
        let verdict = context
            .objectForKeyedSubscript("FindProxyForURL")?
            .call(withArguments: ["https://\(host)/", host])?
            .toString()

        let direct = verdict?.uppercased().contains("DIRECT") == true
        return Check(
            id: "banking",
            title: "Les sites bancaires ne passent pas par Tamis",
            matters: bankingMatters,
            passed: direct,
            detail: direct
                ? "\(host) → DIRECT (le proxy sur \(proxyPort) n'est jamais contacté)"
                : "\(host) → \(verdict ?? "aucune réponse")"
        )
    }

    private static let bankingMatters =
        "Ces connexions ne doivent jamais être déchiffrées. La liste est verrouillée et "
      + "l'exclusion est appliquée par macOS lui-même, avant que la requête n'atteigne "
      + "Tamis."

    // MARK: 4 — trusted, and only for what was announced

    static func authorityIsTrusted() -> Check {
        var certificates: CFArray?
        let status = SecTrustSettingsCopyCertificates(.user, &certificates)
        let names = ((certificates as? [SecCertificate]) ?? []).compactMap { certificate -> String? in
            var common: CFString?
            SecCertificateCopyCommonName(certificate, &common)
            return common as String?
        }
        let ours = names.filter { $0.hasPrefix(Installation.authorityCommonNamePrefix) }
        let trusted = status == errSecSuccess && !ours.isEmpty

        return Check(
            id: "authority",
            title: "L'autorité est de confiance, pour votre compte seul",
            matters: "Sans elle, tout site en HTTPS s'affiche en erreur. Elle vaut pour "
                   + "votre session : les autres comptes de ce Mac ne la voient pas.",
            passed: trusted,
            detail: trusted
                ? ours.joined(separator: ", ")
                : "aucune autorité Tamis dans les réglages de confiance de votre session"
        )
    }

    // MARK: 5 — the security claim, checked rather than repeated

    /// The onboarding states that the signing key never leaves the privileged service.
    /// This is that sentence, asked of the filesystem.
    ///
    /// Deliberately inverted: the check passes when the app **cannot** read the file.
    /// Everything else here confirms something works; this one confirms something is
    /// impossible, which is the only kind of security claim worth printing.
    static func signingKeyIsOutOfReach() -> Check {
        let key = Installation.privilegedDirectory.appending(path: "Authority/ca.key")
            .path(percentEncoded: false)
        let exists = FileManager.default.fileExists(atPath: key)
        let readable = FileManager.default.isReadableFile(atPath: key)

        return Check(
            id: "key",
            title: "La clé de l'autorité est hors de portée de l'application",
            matters: "Qui détient cette clé peut fabriquer un certificat pour n'importe "
                   + "quel site. Elle appartient à root et le proxy — le seul composant "
                   + "qui lit du contenu hostile — ne peut pas la lire.",
            passed: exists && !readable,
            detail: !exists ? "aucune clé à cet emplacement"
                  : readable ? "LISIBLE par cette application — ce ne devrait pas être le cas"
                  : "présente, illisible sans privilège (root, 0600)"
        )
    }

    // MARK: Plumbing

    /// A session that does not go through Tamis's own proxy.
    ///
    /// Without this the check would be routed by the very PAC it is trying to verify,
    /// and a broken proxy would make its own verification unreachable.
    private static func fetch(_ url: String) async -> String? {
        guard let url = URL(string: url) else { return nil }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.timeoutIntervalForRequest = 5
        guard let (data, response) = try? await URLSession(configuration: configuration).data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    private static func shell(_ executable: String, _ arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
}

private extension String {
    /// Quoted for embedding in a JavaScript source string.
    var asJSString: String {
        let escaped = replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "\"\(escaped)\""
    }
}
