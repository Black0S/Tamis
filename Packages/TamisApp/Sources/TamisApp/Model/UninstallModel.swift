import Foundation
import Observation
import TamisSystem

/// Taking Tamis back off this Mac.
///
/// **Why this screen has to exist.** The first run installs a certificate authority:
/// after that, a program on this machine can decrypt HTTPS. Software that takes a power
/// like that should make giving it back at least as easy as handing it over. Until this
/// screen, the removal machinery was written and tested and reachable from nowhere —
/// the exit existed in the code and not in the application, which is the same as an exit
/// that is locked.
///
/// **Two decisions, not one.** Removing the software and discarding the filter lists
/// and scripts somebody wrote are different choices, and one checkbox for both takes the
/// second by surprise. They are separate here, and the data is kept by default.
///
/// **It verifies.** The rollback in the first-run flow used to append "the Mac is back
/// to its initial state" unconditionally, swallowing its own failure — and it was wrong:
/// root-owned binaries stayed behind while the screen reported success. So this reads
/// the machine again afterwards and reports what it actually finds, including the
/// commands for anything it could not remove.
@MainActor
@Observable
final class UninstallModel {

    struct Step: Identifiable, Sendable {
        let id = UUID()
        let description: String
        let succeeded: Bool
    }

    /// What is in place right now, read from the machine rather than remembered.
    private(set) var applied: [SystemChange] = []
    /// The user's own files, listed apart because removing them is another decision.
    private(set) var userData: [URL] = []

    private(set) var steps: [Step] = []
    private(set) var isWorking = false
    private(set) var finished = false
    /// What survived the removal. Empty is the expected outcome.
    private(set) var residue: [SystemChange] = []
    private(set) var failure: String?

    /// Off by default, and it stays off unless somebody says otherwise.
    var alsoRemoveUserData = false

    private let installer: Installer

    init(applicationURL: URL = Bundle.main.bundleURL) {
        self.installer = Installer(applicationURL: applicationURL, isDryRun: true)
        refresh()
    }

    func refresh() {
        applied = Installation.applied()
        userData = Installation.userData()
    }

    var isInstalled: Bool { !applied.isEmpty }

    /// The exact commands, shown before they run — the same contract as the install.
    /// Somebody should be able to do this without Tamis, including after deleting it.
    var script: String {
        let privileged = installer.uninstallScript(for: applied)
        let user = applied.filter { $0.scope != .administrator }
            .map { "# \($0.title)\n\($0.undoCommand)" }
            .joined(separator: "\n\n")
        return [privileged, user].filter { !$0.isEmpty }.joined(separator: "\n\n")
    }

    // MARK: Doing it

    func uninstall() async {
        isWorking = true
        failure = nil
        steps = []
        residue = []
        defer { isWorking = false }

        var live = installer
        live.isDryRun = false

        // The user's half first: it needs no password, so a refused prompt later
        // leaves less behind rather than more. This also removes the authority from
        // the keychain, which is the one removal that matters for security.
        let userOutcomes = (try? live.removeUserFiles()) ?? []
        record("Fichiers de session et autorité retirés", userOutcomes)

        let privileged = live.uninstallScript(for: applied)
        if !privileged.isEmpty {
            do {
                try await runPrivileged(privileged)
                steps.append(Step(description: "Services et fichiers système retirés",
                                  succeeded: true))
            } catch {
                failure = "\(error)"
                steps.append(Step(description: "Retrait des éléments système", succeeded: false))
            }
        }

        if alsoRemoveUserData {
            record("Vos listes, scripts et historique supprimés", live.removeUserData())
        }

        // The part the old rollback skipped: look, then say.
        refresh()
        residue = applied
        finished = true
        steps.append(Step(
            description: residue.isEmpty
                ? "Vérifié — plus aucune trace de Tamis sur ce Mac"
                : "Vérifié — \(residue.count) élément(s) subsistent",
            succeeded: residue.isEmpty
        ))
    }

    private func record(_ description: String, _ outcomes: [Installer.Outcome]) {
        guard !outcomes.isEmpty else { return }
        steps.append(Step(description: description,
                          succeeded: !outcomes.contains { !$0.succeeded }))
    }

    /// One prompt, for a script already shown in full.
    ///
    /// The trust store is not touched here — the authority lives in the user's own
    /// keychain and comes out unprivileged, in `removeUserFiles`. Putting it in this
    /// batch is what made the *install* fail twice.
    private func runPrivileged(_ script: String) async throws {
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = [
            "-e", "do shell script \"\(escaped)\" with administrator privileges",
        ]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw Installer.Failure.commandFailed(String(decoding: data, as: UTF8.self))
        }
    }
}
