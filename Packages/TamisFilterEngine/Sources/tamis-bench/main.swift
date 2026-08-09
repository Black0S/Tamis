import Foundation
import TamisFilterEngine

// Benchmark harness for the filter engine.
//
//   swift run -c release tamis-bench <list.txt> [more-lists.txt …]
//
// Reports what the spec's performance targets are stated in: build time, memory
// pressure proxies (rule counts, bucket occupancy) and per-request latency. The
// catch-all count is the number to watch — rules that land there are evaluated on
// every single request.

let arguments = Array(CommandLine.arguments.dropFirst())
guard !arguments.isEmpty else {
    FileHandle.standardError.write(Data("usage: tamis-bench <list.txt> [...]\n".utf8))
    exit(2)
}

var allLines: [String] = []
for path in arguments {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        FileHandle.standardError.write(Data("cannot read \(path)\n".utf8))
        exit(1)
    }
    allLines.append(contentsOf: text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init))
    print("loaded \(path)")
}

func measure<T>(_ label: String, _ body: () -> T) -> T {
    let start = DispatchTime.now().uptimeNanoseconds
    let result = body()
    let ms = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    print(String(format: "%-24s %8.1f ms", (label as NSString).utf8String!, ms))
    return result
}

print("")
let engine = measure("build") { FilterEngine(lines: allLines) }
let s = engine.stats

print("")
print("lines                  \(s.lines)")
print("comments               \(s.comments)")
print("cosmetic (skipped)     \(s.cosmeticSkipped)")
print("network rules          \(s.networkRules)")
print("  unindexed            \(s.unindexedRules)  (\(percent(s.unindexedRules, s.networkRules)) of rules)")
print("  unsupported modifier \(s.rulesWithUnsupportedModifiers)")
print("badfilter              \(s.badFilters) → removed \(s.removedByBadFilter)")
print("parse errors           \(s.parseErrors)")
print("regex rules            \(s.regexRules)  (unindexed: \(s.unindexedRegexRules))")

func percent(_ n: Int, _ total: Int) -> String {
    guard total > 0 else { return "0%" }
    return String(format: "%.1f%%", Double(n) * 100 / Double(total))
}

// Cosmetic rules are parsed by a separate engine; the network engine counts them as
// skipped, so the two numbers together account for every line.
let cosmetic = measure("cosmetic build") { CosmeticEngine(rules: allLines) }
let c = cosmetic.stats
print("")
print("cosmetic rules         \(c.rules)")
print("  generic              \(c.generic)")
print("  site-specific        \(c.specific)")
print("  exceptions           \(c.exceptions)")
print("  procedural           \(c.procedural)")
print("  scriptlets           \(c.scriptlets)")
print("  html filters         \(c.htmlFilters)")

for site in ["lemonde.fr", "youtube.com", "reddit.com", "example.org"] {
    let set = cosmetic.set(forHostname: "www." + site)
    print(String(
        format: "  %-14s specific %4d · procedural %3d · scriptlets %2d · css %5d bytes",
        (site as NSString).utf8String!,
        set.specificSelectors.count, set.proceduralSelectors.count,
        set.scriptlets.count, set.inlineCSS().utf8.count
    ))
}

// The number behind the specific/generic split: inlining the generic set into every
// page instead of handing it to the runtime.
let genericBytes = cosmetic.set(forHostname: "example.invalid").genericSelectors
    .reduce(0) { $0 + $1.utf8.count + 2 }
print(String(format: "  generic set if inlined: %.0f KB per page", Double(genericBytes) / 1024))

// A spread of realistic requests: things that should block, things that should not,
// short URLs and long ones.
let samples: [(String, String, RequestType)] = [
    ("https://ads.doubleclick.net/pixel.gif?id=123", "www.lemonde.fr", .image),
    ("https://www.google-analytics.com/analytics.js", "www.lemonde.fr", .script),
    ("https://static.lemonde.fr/assets/main.9f2a1c.css", "www.lemonde.fr", .stylesheet),
    ("https://cdn.jsdelivr.net/npm/vue@3/dist/vue.js", "example.org", .script),
    ("https://example.org/api/v1/users?page=2&sort=desc", "example.org", .xmlHTTPRequest),
    ("https://fonts.gstatic.com/s/roboto/v30/abc.woff2", "example.org", .font),
    ("https://track.adform.net/serving/cookie/match?party=1", "www.lefigaro.fr", .image),
    ("https://s0.2mdn.net/ads/richmedia/banner.js", "www.lefigaro.fr", .script),
]

let requests = samples.map { url, source, type -> Request in
    let host = url.replacingOccurrences(of: "https://", with: "")
        .split(separator: "/").first.map(String.init) ?? ""
    return Request(url: url, hostname: host, sourceHostname: source, type: type)
}

print("")
for (i, r) in requests.enumerated() {
    let result = engine.match(r)
    let mark = result.action == .block ? "BLOCK" : "allow"
    let rule = result.rule.map { " ← \($0)" } ?? ""
    print("  \(mark)  \(samples[i].0.prefix(58))\(rule)")
}

// Warm up, then time a large number of matches.
for r in requests { _ = engine.match(r) }

let iterations = 20_000
let start = DispatchTime.now().uptimeNanoseconds
var blocked = 0
for i in 0..<iterations {
    if engine.match(requests[i % requests.count]).action == .block { blocked += 1 }
}
let elapsedNs = DispatchTime.now().uptimeNanoseconds - start
let perMatchUs = Double(elapsedNs) / Double(iterations) / 1_000

print("")
print(String(format: "match  %d requests in %.0f ms  →  %.1f µs each", iterations, Double(elapsedNs) / 1_000_000, perMatchUs))
print(String(format: "       %.0f requests/second", 1_000_000 / perMatchUs))
