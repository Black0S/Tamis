import Foundation
import Observation
import TamisLists
import TamisSystem

/// Drives the nine screens of the first run.
///
/// Two rules shape it, and both are visible in the code rather than only in the copy.
///
/// **Everything is explained before it is done.** The preflight runs before anything is
/// asked, the full list of changes is shown before the password is requested, and the
/// exact script is available to read on the screen that asks for it.
///
/// **Nothing is left behind if the user gives up.** Until ``install()`` is called the
/// installer is in dry run and the machine is untouched; if a step fails, the log is
/// replayed backwards. A half-installed Mac is worse than an uninstalled one, because
/// its owner has no idea which half.
@MainActor
@Observable
final class OnboardingModel {

    enum Step: Int, CaseIterable, Identifiable {
        case welcome, preflight, whatChanges, authorise, installing
        case browsers, dns, verify, done

        var id: Int { rawValue }

        var title: String {
            switch self {
            case .welcome:     "Bienvenue"
            case .preflight:   "Vérification"
            case .whatChanges: "Ce qui va changer"
            case .authorise:   "Autorisation"
            case .installing:  "Installation"
            case .browsers:    "Vos navigateurs"
            case .dns:         "DNS"
            case .verify:      "Vérification finale"
            case .done:        "Terminé"
            }
        }
    }

    /// One line of the install log, kept so a failure can be undone in reverse.
    struct Operation: Identifiable, Sendable {
        let id = UUID()
        let description: String
        var succeeded: Bool
    }

    private(set) var step: Step = .welcome
    private(set) var report = Preflight.Report(findings: [])
    private(set) var operations: [Operation] = []
    private(set) var isWorking = false
    private(set) var failure: String?

    /// The exact commands the password will authorise. Shown, not summarised.
    private(set) var script = ""

    let installer: Installer

    init(applicationURL: URL = Bundle.main.bundleURL) {
        // Dry run until the user has read the plan and agreed to it. The flag is
        // flipped in one place, by one method, and nowhere else.
        self.installer = Installer(applicationURL: applicationURL, isDryRun: true)
    }

    var changes: [SystemChange] { Installation.plan() }

    /// The script macOS will evaluate for every request, built from the exclusions so
    /// banking traffic never reaches the proxy at all.
    private var pacContents: String {
        ProxyAutoConfig.script(
            proxyPort: 7654,
            directHosts: BundledExclusions.sources.flatMap { $0.entries.map(\.pattern) }
        )
    }

    /// Called by the button that says "Installer", which is the only button that does.
    func installNow() async {
        step = .installing
        await install(pacContents: pacContents)
    }

    /// The four things Tamis will not do, which the screen shows beside the four it
    /// will. Software that states its limits is more credible than software that states
    /// only its powers — and these are checkable claims, not reassurance.
    let limits = [
        "Aucune donnée ne quitte ce Mac. Jamais, pas même un rapport de plantage.",
        "Les sites bancaires ne sont jamais déchiffrés — 4 492 hôtes, listes verrouillées.",
        AuthorityStore.keyProtectionCaveat,
        "Tout est annulable, et chaque commande d'annulation est affichée.",
    ]

    // MARK: Moving

    func advance() {
        guard let next = Step(rawValue: step.rawValue + 1) else { return }
        step = next
        if next == .preflight { report = Preflight.run() }
    }

    func back() {
        guard let previous = Step(rawValue: step.rawValue - 1) else { return }
        step = previous
    }

    /// Abandoning before the password leaves nothing behind, and abandoning after it
    /// undoes what was done. Either way the answer to "what did it change" is nothing.
    func cancel() async {
        guard !operations.isEmpty else { return }
        await rollback()
    }

    var canProceedFromPreflight: Bool { report.canProceed }

    // MARK: Doing it

    /// The one place the dry run ends.
    func install(pacContents: String) async {
        isWorking = true
        failure = nil
        operations = []
        defer { isWorking = false }

        var live = installer
        live.isDryRun = false

        do {
            record("Préparation des fichiers de service", try live.stagePlists())
            record("Écriture de la configuration proxy", try live.applyUserChanges(pacContents: pacContents))

            script = live.privilegedScript()
            try await runPrivileged(script)
            operations.append(Operation(description: "Modifications système appliquées", succeeded: true))
            step = .browsers
        } catch {
            failure = "\(error)"
            // In reverse, so the machine ends where it started rather than somewhere
            // nobody planned.
            await rollback()
        }
    }

    private func record(_ description: String, _ outcomes: [Installer.Outcome]) {
        operations.append(Operation(
            description: description,
            succeeded: !outcomes.contains { !$0.succeeded }
        ))
    }

    /// One prompt, for a script the user has already been able to read.
    ///
    /// `osascript` is what asks: without a Developer ID there is no signed helper to
    /// register, and this is the honest remaining route. See ``Installer``.
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
        process.standardError = output
        process.standardOutput = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw Installer.Failure.commandFailed(String(decoding: data, as: UTF8.self))
        }
    }

    private func rollback() async {
        var live = installer
        live.isDryRun = false
        _ = try? live.removeUserFiles()

        let undo = live.uninstallScript()
        if !undo.isEmpty { try? await runPrivileged(undo) }
        operations.append(Operation(description: "Annulé — le Mac est revenu à son état initial",
                                    succeeded: true))
    }
}
