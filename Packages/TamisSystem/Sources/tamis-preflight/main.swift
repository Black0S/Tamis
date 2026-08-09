import Foundation
import TamisSystem

// What this Mac looks like before Tamis changes anything.
//
//   swift run --package-path Packages/TamisSystem tamis-preflight
//
// Every check reads. The single exception is the port 53 probe, which binds a socket
// and closes it immediately — there is no read-only way to ask whether a port is free.

setvbuf(stdout, nil, _IOLBF, 0)

let report = Preflight.run()

print("Vérification préalable\n")
if report.findings.isEmpty {
    print("  Rien à signaler. Ce Mac est prêt pour une installation.")
} else {
    for finding in report.findings {
        let mark = switch finding.severity {
        case .blocking: "⛔"
        case .warning:  "⚠️ "
        case .note:     "ℹ️ "
        }
        print("  \(mark) \(finding.title)")
        print("      \(finding.detail)")
        if let remedy = finding.remedy { print("      → \(remedy)") }
        print("")
    }
}

print(report.canProceed
      ? "  Installation possible."
      : "  Installation impossible en l'état.")
