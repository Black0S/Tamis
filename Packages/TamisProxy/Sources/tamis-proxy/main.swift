import Foundation
import TamisFilterEngine
import TamisLists
import TamisProxy
import TamisTLS
import TamisApps
import TamisUserScripts

// Runs the proxy against real lists, on a port, changing nothing on the machine.
//
//   swift run -c release tamis-proxy --root /tmp/tamis --port 18080 [--scripts <dir>]
//
// Then, from another terminal — no system proxy setting, no keychain, no root:
//
//   curl -x http://127.0.0.1:18080 --cacert /tmp/tamis/ca.pem https://example.com/
//
// The authority is written next to the lists so `--cacert` can point at it. That is the
// whole reason this tool exists: it is the only way to put real traffic through the
// real engines without asking the machine to trust anything.

setvbuf(stdout, nil, _IOLBF, 0)

let arguments = Array(CommandLine.arguments.dropFirst())
func value(after flag: String) -> String? {
    guard let i = arguments.firstIndex(of: flag), i + 1 < arguments.count else { return nil }
    return arguments[i + 1]
}

let root = URL(fileURLWithPath: value(after: "--root")
    ?? NSTemporaryDirectory() + "tamis-proxy")
let port = Int(value(after: "--port") ?? "18080") ?? 18080
try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

// MARK: Lists

let manager = ListManager(store: ListStore(root: root))
let adblock = await manager.enabledTexts(format: .adblock)
let hosts = await manager.enabledTexts(format: .hosts)
// Only the Adblock-syntax lists. Feeding a hosts file to the network engine turns
// `0.0.0.0 ads.example` into a hundred thousand patterns containing a space, which no
// URL can ever match — harmless, but it inflates every count that follows and makes
// the engine look larger than it is.
let lines = adblock.flatMap { $0.text.split(separator: "\n").map(String.init) }

print("Listes            \(adblock.count) adblock + \(hosts.count) hosts")
let engine = FilterEngine(lines: lines)
let cosmetic = CosmeticEngine(rules: lines)
print("Règles réseau     \(engine.stats.networkRules)")
print("Règles cosmétiques \(cosmetic.stats.rules)")

// MARK: Scripts and styles

// The store hands over what is enabled; parsing happens here because a file that no
// longer parses must be reported and skipped, not silently injected half-formed.
var userScripts: [UserScript] = []
var userStyles: [UserStyle] = []

if let scriptsPath = value(after: "--scripts") {
    let store = ScriptStore(root: URL(fileURLWithPath: scriptsPath))
    try await store.reload()

    for (path, text, _) in await store.enabledScripts() {
        do { userScripts.append(try UserScript.parse(text)) }
        catch { print("  script ignoré  \(path) — \(error)") }
    }
    for (path, text, _) in await store.enabledStyles() {
        do { userStyles.append(try UserStyle.parse(text, fallbackName: path)) }
        catch { print("  style ignoré   \(path) — \(error)") }
    }
    print("Scripts           \(userScripts.count) actifs, \(userStyles.count) styles")
}

// MARK: Authority

// Regenerated on each run unless one is already sitting here. Seven-day leaves make a
// stale authority cheap to throw away.
let authorityURL = root.appending(path: "ca.pem")
let authority = try CertificateAuthority.generate()
let der = try authority.certificateDER()
let pem = "-----BEGIN CERTIFICATE-----\n"
    + Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    + "\n-----END CERTIFICATE-----\n"
try pem.write(to: authorityURL, atomically: true, encoding: .utf8)

let issuer = LeafIssuer(authority: authority)
let materials = try TLSInterception.Materials(
    authority: authority,
    cache: LeafCache(issuer: issuer),
    leafPrivateKeyDER: issuer.privateKeyDER
)
print("Autorité          \(authorityURL.path(percentEncoded: false))")

// MARK: Exclusions

let exclusions = BundledExclusions.makeSet()
print("Exclusions HTTPS  \(exclusions.distinctPatternCount) hôtes jamais déchiffrés")

// MARK: Events

let events = EventSink { event in
    switch event {
    case .requestBlocked(let url, let rule):
        print("  BLOQUÉ    \(url.prefix(88))\n            ← \(rule.prefix(88))")
    case .attributed(let host, let process, let bundleID):
        print("  APP       \(host)  ← \(process)\(bundleID.map { " [\($0)]" } ?? " [sans bundle]")")
    case .tunnelled(let host, let reason):
        print("  TUNNEL    \(host)  (\(reason))")
    case .intercepted(let host, let negotiated):
        print("  INTERCEPT \(host)  [\(negotiated)]")
    case .injected(let host, let selectors, let bytes):
        print("  INJECTÉ   \(host)  \(selectors) sélecteurs, \(bytes) octets")
    case .injectionAbandoned(let host, let reason):
        print("  PAS INJECTÉ \(host)  — \(reason)")
    case .scriptletsSkipped(let host, let names):
        print("  SCRIPTLETS NON IMPLÉMENTÉS \(host)  \(names.joined(separator: ", "))")
    case .upstreamCertificateRejected(let host, let reason, _):
        print("  CERT REFUSÉ \(host)  — \(reason)")
    case .userScriptsInjected(let host, let names):
        print("  SCRIPTS   \(host)  \(names.joined(separator: ", "))")
    case .userStylesApplied(let host, let names):
        print("  STYLES    \(host)  \(names.joined(separator: ", "))")
    case .userScriptGrantUnavailable(let script, let grant):
        print("  GRANT NON FOURNI \(script) — \(grant)")
    case .failed(let host, let message):
        print("  ÉCHEC     \(host)  — \(message)")
    default:
        break
    }
}

let server = ProxyServer(
    configuration: .init(
        host: "127.0.0.1",
        port: port,
        policy: InterceptionPolicy(exclusions: exclusions),
        interception: materials,
        engine: engine,
        cosmetic: cosmetic,
        userScripts: userScripts,
        userStyles: userStyles,
        attributor: ProcessAttributor()
    ),
    events: events
)

try await server.start()
print("""

Proxy sur 127.0.0.1:\(server.boundPort ?? port)

  curl -x http://127.0.0.1:\(server.boundPort ?? port) \\
       --cacert \(authorityURL.path(percentEncoded: false)) \\
       https://example.com/

Ctrl-C pour arrêter. Rien n'a été modifié sur la machine.

""")

while true { try await Task.sleep(for: .seconds(3600)) }
