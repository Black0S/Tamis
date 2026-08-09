import Foundation
import TamisDNS
import TamisFilterEngine
import TamisLists

// Drives the whole list chain from the terminal, against the real registries and the
// real mirrors: subscribe, download, judge, store, then compile what came back into the
// two engines that will use it.
//
// The compile step is the one worth having. Everything upstream can be right while the
// file that arrives still fails to become a working engine, and that is exactly the
// failure a unit test with a fixture cannot show.
//
//   swift run tamis-lists --root /tmp/tamis --suggested
//   swift run tamis-lists --root /tmp/tamis --compile
//   swift run tamis-lists --root /tmp/tamis --refresh

setvbuf(stdout, nil, _IOLBF, 0)

let arguments = Array(CommandLine.arguments.dropFirst())

func value(after flag: String) -> String? {
    guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else { return nil }
    return arguments[index + 1]
}

let root = value(after: "--root").map { URL(fileURLWithPath: $0) }
    ?? URL(fileURLWithPath: NSTemporaryDirectory()).appending(path: "tamis-lists")
let catalog = FilterListCatalog.bundled
let manager = ListManager(catalog: catalog, store: ListStore(root: root))

print("Racine  \(root.path(percentEncoded: false))")
print("Catalogue  \(catalog.entries.count) listes, généré le \(catalog.generatedAt)\n")

func report(_ id: String, _ outcome: UpdateOutcome, name: String, seconds: Double, bytes: Int) {
    let marker: String
    switch outcome {
    case .routine:                          marker = "  "
    case .awaitingValidation:               marker = "🔔"
    case .anomaly(let rejection):           marker = "🚨 \(rejection.summary)"
    }
    let size = ByteCountFormatStyle(style: .file).format(Int64(bytes))
    print(String(format: "  %@ %-46@ %10@  %5.2f s", marker, name, size, seconds))
}

if arguments.contains("--suggested") {
    print("Sélection suggérée — \(catalog.suggestedSelection.count) listes\n")
    for entry in catalog.suggestedSelection {
        let start = Date()
        do {
            let outcome = try await manager.enable(entry.id)
            let bytes = (try? await manager.text(for: entry.id))??.utf8.count ?? 0
            report(entry.id, outcome, name: entry.name,
                   seconds: Date().timeIntervalSince(start), bytes: bytes)
        } catch {
            print("  🚨 \(entry.name) — \(error)")
        }
    }
    print("")
}

if arguments.contains("--refresh") {
    let start = Date()
    let results = await manager.refreshAll()
    print("Rafraîchissement — \(results.count) listes en "
          + String(format: "%.1f s\n", Date().timeIntervalSince(start)))
    for (id, outcome) in results.sorted(by: { $0.key < $1.key }) {
        let bytes = (try? await manager.text(for: id))??.utf8.count ?? 0
        report(id, outcome, name: await manager.displayName(for: id), seconds: 0, bytes: bytes)
    }
    print("")
}

let enabled = await manager.enabled
guard !enabled.isEmpty else {
    print("Aucune liste activée. `--suggested` pour installer la sélection suggérée.")
    exit(0)
}

print("Activées — \(enabled.count)")
for subscription in enabled {
    let metadata = await manager.metadata(for: subscription.id)
    let name = await manager.displayName(for: subscription.id)
    let count = metadata.current?.entryCount ?? 0
    print("  \(name.padding(toLength: max(name.count, 46), withPad: " ", startingAt: 0))"
          + "\(count) entrées")
}
print("")

guard arguments.contains("--compile") else { exit(0) }

// The claim being checked: what came down the wire compiles into something that blocks.
let adblockTexts = await manager.enabledTexts(format: .adblock)
let hostsTexts = await manager.enabledTexts(format: .hosts)

let adblockLines = adblockTexts.flatMap { $0.text.split(separator: "\n").map(String.init) }
// The DNS layer takes both formats, and every enabled list feeds it: a hosts file it
// reads directly, an Adblock list for the `||domain^` rules it can honour.
let dnsLines = (hostsTexts + adblockTexts)
    .flatMap { $0.text.split(separator: "\n").map(String.init) }

var started = Date()
let engine = FilterEngine(lines: adblockLines)
let engineSeconds = Date().timeIntervalSince(started)

started = Date()
let cosmetic = CosmeticEngine(rules: adblockLines)
let cosmeticSeconds = Date().timeIntervalSince(started)

started = Date()
let blocklist = DomainBlocklist(lines: dnsLines)
let dnsSeconds = Date().timeIntervalSince(started)

print("Moteur de filtres")
print("  Listes                \(adblockTexts.count)")
print("  Lignes                \(engine.stats.lines)")
print("  Règles réseau         \(engine.stats.networkRules)")
print("  Erreurs de parsing    \(engine.stats.parseErrors)")
print("  Modificateurs inconnus \(engine.stats.rulesWithUnsupportedModifiers)")
print("  Règles non bloquantes \(engine.stats.rulesThatChangeRatherThanBlock)")
print(String(format: "  Compilation           %.2f s", engineSeconds))

print("\nMoteur cosmétique")
print("  Règles                \(cosmetic.stats.rules)")
print("  Génériques            \(cosmetic.stats.generic)")
print("  Spécifiques           \(cosmetic.stats.specific)")
print("  Scriptlets            \(cosmetic.stats.scriptlets)")
print(String(format: "  Compilation           %.2f s", cosmeticSeconds))

print("\nBlocklist DNS")
print("  Listes                \(hostsTexts.count) hosts + \(adblockTexts.count) adblock")
print("  Domaines              \(blocklist.count)")
print("  Non applicable au DNS \(blocklist.stats.notApplicableToDNS)")
print("  Ignorées              \(blocklist.stats.skipped)")
print(String(format: "  Compilation           %.2f s", dnsSeconds))

// Whether it actually blocks, on names that are in these lists by definition.
// Two that every one of these lists blocks, and three that none of them may touch.
// The second group is the one worth having: an engine that blocks everything passes
// the first group perfectly.
let probes = [
    ("ads.doubleclick.net", "https://ads.doubleclick.net/ad.js"),
    ("pagead2.googlesyndication.com", "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"),
    ("www.google-analytics.com", "https://www.google-analytics.com/analytics.js"),
    ("example.com", "https://example.com/app.js"),
    ("www.lemonde.fr", "https://www.lemonde.fr/static/main.js"),
    ("cdn.jsdelivr.net", "https://cdn.jsdelivr.net/npm/vue/dist/vue.js"),
    ("www.wikipedia.org", "https://www.wikipedia.org/portal/wikipedia.org/assets/js/index.js"),
    ("github.com", "https://github.com/assets/app.js"),
    ("www.leboncoin.fr", "https://www.leboncoin.fr/_next/static/chunk.js"),
    ("www.bbc.co.uk", "https://www.bbc.co.uk/static/js/main.js"),
    ("stackoverflow.com", "https://stackoverflow.com/Content/js/full.js"),
    ("www.reddit.com", "https://www.reddit.com/static/bundle.js"),
]
print("\nVérification")
for (host, url) in probes {
    let requestHost = URL(string: url)?.host() ?? host
    let request = Request(url: url, hostname: requestHost,
                          sourceHostname: "lemonde.fr", type: .script)
    let result = engine.match(request)
    let proxyVerdict = result.action == .block ? "bloque" : "passe "
    let dnsVerdict: String
    switch blocklist.decision(for: host) {
    case .block(let matched): dnsVerdict = "bloque (\(matched))"
    case .allow(let matched): dnsVerdict = "autorise (\(matched))"
    case .noMatch: dnsVerdict = "passe"
    }
    print("  \(host.padding(toLength: max(host.count, 30), withPad: " ", startingAt: 0))"
          + "proxy \(proxyVerdict)   DNS \(dnsVerdict)"
          + (result.rule.map { "    \($0.prefix(70))" } ?? ""))
}
