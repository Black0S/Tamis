import Foundation
import TamisApps

// Prints what Tamis would do with every browser on this Mac, and why.
//
//   swift run --package-path Packages/TamisApps tamis-apps
//
// Reads nothing but the application registry and each bundle's own structure. No
// history, no cookies, no bookmarks, no passwords — see SPEC §10.6.

setvbuf(stdout, nil, _IOLBF, 0)

let browsers = BrowserDiscovery.installed()
let byDefault = BrowserDiscovery.defaultBrowser()

print("Navigateurs installés — \(browsers.count)\n")
for browser in browsers {
    let policy = AppPolicy.recommended(for: browser)
    let mark = browser.bundleID == byDefault?.bundleID ? "★" : " "
    let lock = policy.isLocked ? " 🔒" : ""
    print("\(mark) \(browser.name)")
    print("    \(browser.bundleID)  ·  \(browser.engine.title)")
    print("    → \(policy.treatment.title)\(lock)")
    print("      \(policy.rationale.text)")
    print("")
}

print("Applications pré-exclues — \(BrowserKnowledge.pinnedApplications.count)")
for (bundleID, reason) in BrowserKnowledge.pinnedApplications.sorted(by: { $0.key < $1.key }) {
    print("  \(bundleID)")
    print("      \(reason)")
}
