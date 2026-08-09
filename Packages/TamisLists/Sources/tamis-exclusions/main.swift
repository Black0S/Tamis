import Foundation
import TamisLists

// Answers, from the terminal, the two questions the exclusion screen will answer in the
// interface: what is shipped, and is a given host protected — by which list.
//
//   swift run --package-path Packages/TamisLists tamis-exclusions
//   swift run --package-path Packages/TamisLists tamis-exclusions mabanque.bnpparibas

setvbuf(stdout, nil, _IOLBF, 0)

let set = BundledExclusions.makeSet()
var hosts = Array(CommandLine.arguments.dropFirst())

// The allowlist has to be readable by anyone who wants to check it. A hard-coded,
// invisible allowlist inside software that intercepts all traffic has the shape of a
// back door, so it gets a view of its own before the interface exists.
if hosts.first == "--allowlist" {
    let allowlist = InternalAllowlist.shared
    print("Domaines système de Tamis — jamais bloqués, sans exception\n")
    for purpose in [InternalAllowlist.Entry.Purpose.encryptedDNS, .filterListSource, .appUpdate] {
        let entries = allowlist.entries(for: purpose)
        guard !entries.isEmpty else { continue }
        print("\(purpose.title) (\(entries.count))")
        for entry in entries {
            print("  \(entry.host)")
            print("      \(entry.justification)")
        }
        print("")
    }
    print("  Total  \(allowlist.entries.count) hôtes")
    exit(0)
}

guard hosts.isEmpty else {
    for host in hosts {
        let matches = set.allMatches(host: host)
        guard !matches.isEmpty else {
            print("\(host)\n  non exclu — cet hôte serait déchiffré\n")
            continue
        }
        print(host)
        for match in matches {
            let scope: String
            switch match.entry.scope {
            case .exact:               scope = "exact"
            case .domainAndSubdomains: scope = "domaine + sous-domaines"
            case .wildcard:            scope = "motif"
            }
            let apps = match.entry.apps.isEmpty
                ? ""
                : "  [\(match.entry.apps.sorted().joined(separator: ", "))]"
            print("  \(match.sourceName) — \(match.entry.pattern) (\(scope))\(apps)")
        }
        print("")
    }
    exit(0)
}

print("Exclusions HTTPS embarquées\n")
var total = 0
var notApplicable = 0
for source in BundledExclusions.sources {
    let report = BundledExclusions.reports[source.id]
    let lock: String
    switch source.lock {
    case .hard:                lock = "verrouillée"
    case .entriesOverridable:  lock = "surchargeable"
    case .editable:            lock = "éditable"
    }
    let title = source.provider + " · " + source.name
    let count = String(source.entries.count)
    print("  " + title.padding(toLength: max(title.count, 42), withPad: " ", startingAt: 0)
          + String(repeating: " ", count: max(0, 6 - count.count)) + count
          + "  " + lock.padding(toLength: max(lock.count, 15), withPad: " ", startingAt: 0)
          + source.licence)
    total += source.entries.count
    notApplicable += report?.notApplicableToMacOS ?? 0
}

print("")
print("  Total avant dédoublonnage      \(total)")
print("  Hôtes distincts                \(set.distinctPatternCount)")
print("  Écartées (Windows uniquement)  \(notApplicable)")

let unparsed = BundledExclusions.reports.values.flatMap(\.unparsed)
print("  Lignes non comprises           \(unparsed.count)")
for line in unparsed.prefix(10) { print("      \(line)") }

// Cost per connection, since this runs before every CONNECT.
let probes = ["mabanque.bnpparibas", "www.google.com", "doubleclick.net",
              "login.microsoftonline.com", "cdn.example.co.uk"]
var sink = 0
let start = DispatchTime.now()
for _ in 0..<200_000 {
    for host in probes where set.match(host: host) != nil { sink += 1 }
}
let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds)
print(String(format: "\n  Décision                       %.2f µs  (%d correspondances)",
             elapsed / 1_000 / Double(200_000 * probes.count), sink))
