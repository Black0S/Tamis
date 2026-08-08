import Foundation
import TamisDNS

// Benchmark and sanity harness for the DNS layer.
//
//   swift run -c release tamis-dnsbench <list.txt> [more-lists.txt …]

let arguments = Array(CommandLine.arguments.dropFirst())
guard !arguments.isEmpty else {
    FileHandle.standardError.write(Data("usage: tamis-dnsbench <list.txt> [...]\n".utf8))
    exit(2)
}

var lines: [String] = []
for path in arguments {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        FileHandle.standardError.write(Data("cannot read \(path)\n".utf8))
        exit(1)
    }
    let fileLines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    print("loaded \(URL(fileURLWithPath: path).lastPathComponent)  (\(fileLines.count) lines)")
    lines.append(contentsOf: fileLines)
}

let buildStart = DispatchTime.now().uptimeNanoseconds
let list = DomainBlocklist(lines: lines)
let buildMs = Double(DispatchTime.now().uptimeNanoseconds - buildStart) / 1_000_000
let policy = ResolverPolicy(blocklist: list)

let s = list.stats
print("")
print(String(format: "build                  %.0f ms", buildMs))
print("lines                  \(s.lines)")
print("comments               \(s.comments)")
print("block entries          \(s.blockEntries)")
print("allow entries          \(s.allowEntries)")
print("skipped                \(s.skipped)")

let samples = [
    "ads.doubleclick.net",
    "www.google-analytics.com",
    "graph.facebook.com",
    "telemetry.mozilla.org",
    "www.lemonde.fr",
    "github.com",
    "raw.githubusercontent.com",
    "use-application-dns.net",
    "api.openai.com",
    "cdn.jsdelivr.net",
]

print("")
for name in samples {
    switch policy.outcome(forName: name) {
    case .block(.blocklist(let matched)):
        print("  BLOCK    \(name.padding(toLength: 28, withPad: " ", startingAt: 0)) ← \(matched)")
    case .block(.firefoxCanary):
        print("  BLOCK    \(name.padding(toLength: 28, withPad: " ", startingAt: 0)) ← Firefox canary")
    case .forward:
        print("  forward  \(name)")
    }
}

// Deep subdomain: the worst case for label-walking.
let deep = "a.b.c.d.e.f.g.tracking.example.com"
let iterations = 200_000
for name in samples { _ = policy.outcome(forName: name) }

let start = DispatchTime.now().uptimeNanoseconds
for i in 0..<iterations {
    _ = policy.outcome(forName: i % 10 == 0 ? deep : samples[i % samples.count])
}
let ns = Double(DispatchTime.now().uptimeNanoseconds - start) / Double(iterations)

print("")
print(String(format: "decision  %.2f µs each  →  %.0f queries/second", ns / 1000, 1_000_000_000 / ns))
