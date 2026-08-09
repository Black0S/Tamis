import Foundation
import Observation
import TamisApps

/// Drives the Applications screen.
@MainActor
@Observable
final class ApplicationsModel {

    struct Row: Identifiable, Sendable {
        let browser: Browser
        var policy: AppPolicy
        let isDefaultBrowser: Bool
        var id: String { browser.bundleID }
    }

    private(set) var rows: [Row] = []
    private(set) var set = AppPolicySet()
    /// Applications that are not browsers but must never be decrypted.
    private(set) var pinned: [(bundleID: String, reason: String)] = []

    private let stateURL: URL

    init(stateURL: URL? = nil) {
        self.stateURL = stateURL ?? Self.defaultStateURL()
    }

    private static func defaultStateURL() -> URL {
        let support = (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )) ?? URL(fileURLWithPath: NSTemporaryDirectory())
        return support.appending(path: "Tamis/applications.json")
    }

    func reload() {
        let browsers = BrowserDiscovery.installed()
        let defaultBundleID = BrowserDiscovery.defaultBrowser()?.bundleID
        let chosen = loadChoices()

        var policies = AppPolicySet()
        var rows: [Row] = []

        for browser in browsers {
            var policy = AppPolicy.recommended(for: browser)
            // A stored choice wins, unless the recommendation was a refusal rather than
            // a suggestion — a locked browser has no stored choice to honour.
            if !policy.isLocked, let treatment = chosen[browser.bundleID] {
                policy.treatment = treatment
            }
            policies.add(policy)
            rows.append(Row(
                browser: browser, policy: policy,
                isDefaultBrowser: browser.bundleID == defaultBundleID
            ))
        }

        for (bundleID, reason) in BrowserKnowledge.pinnedApplications.sorted(by: { $0.key < $1.key }) {
            if let policy = AppPolicy.recommended(forApplication: bundleID, name: bundleID) {
                policies.add(policy)
            }
            pinned.append((bundleID, reason))
        }

        self.set = policies
        self.rows = rows
    }

    func setTreatment(_ treatment: AppPolicy.Treatment, for bundleID: String) {
        guard set.set(treatment, for: bundleID) else { return }
        guard let index = rows.firstIndex(where: { $0.id == bundleID }) else { return }
        rows[index].policy.treatment = treatment
        saveChoices()
    }

    /// Only what the user changed is stored. Recommendations are recomputed every time,
    /// so a browser that gains or loses a built-in blocker is re-judged rather than
    /// frozen at whatever was true the day it was first seen.
    private func loadChoices() -> [String: AppPolicy.Treatment] {
        guard let data = try? Data(contentsOf: stateURL),
              let decoded = try? JSONDecoder().decode([String: AppPolicy.Treatment].self, from: data)
        else { return [:] }
        return decoded
    }

    private func saveChoices() {
        var chosen: [String: AppPolicy.Treatment] = [:]
        for row in rows where !row.policy.isLocked {
            let recommended = AppPolicy.recommended(for: row.browser).treatment
            if row.policy.treatment != recommended { chosen[row.id] = row.policy.treatment }
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try? FileManager.default.createDirectory(
            at: stateURL.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try? encoder.encode(chosen).write(to: stateURL, options: .atomic)
    }
}
