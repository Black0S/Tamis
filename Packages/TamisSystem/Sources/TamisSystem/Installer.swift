import Foundation

/// Applies the plan, or undoes it.
///
/// **Why a shell script and a single password prompt.** The tidy way to do privileged
/// work on macOS is a helper registered with `SMAppService`, which needs the application
/// to be signed with a Developer ID. Tamis deliberately has no Apple developer account —
/// that is the constraint the whole project is built under — so that route is closed.
/// What is left is asking for authorisation once, for a batch of commands the user can
/// read in full beforehand.
///
/// That is a worse mechanism than a signed helper and it is written down rather than
/// glossed: the user is trusting a script they were shown, not an entitlement the system
/// enforced. Showing the exact commands is what makes it a decision rather than a leap.
///
/// Nothing here runs unless ``isDryRun`` is false, and it is true by default.
public struct Installer: Sendable {

    public struct Outcome: Sendable, Equatable, Identifiable {
        public let id: String
        public let succeeded: Bool
        public let message: String
    }

    public enum Failure: Error, Sendable, Equatable {
        case authorisationRefused
        case commandFailed(String)
        case notWritable(String)
    }

    /// True by default. An installer that runs when nobody asked is not an installer.
    public var isDryRun: Bool
    /// Where the built application lives, which is what the jobs will point at.
    public let applicationURL: URL
    public let proxyPort: UInt16
    public let pacPort: UInt16

    public init(
        applicationURL: URL,
        proxyPort: UInt16 = 7654,
        pacPort: UInt16 = 7655,
        isDryRun: Bool = true
    ) {
        self.applicationURL = applicationURL
        self.proxyPort = proxyPort
        self.pacPort = pacPort
        self.isDryRun = isDryRun
    }

    /// Where the binaries are now.
    private var bundled: URL { applicationURL.appending(path: "Contents/MacOS") }
    /// Where the privileged ones will be, once installed. See
    /// ``Installation/privilegedDirectory``.
    private var installed: URL { Installation.privilegedDirectory }

    // MARK: Install

    /// The privileged half, as one script.
    ///
    /// Assembled rather than run so it can be displayed before it is authorised. Every
    /// line is a command the user could type; nothing is hidden behind an API call they
    /// cannot inspect.
    public func privilegedScript(authorityPEM: URL) -> String {
        // The jobs point at the installed copies, never at the bundle.
        let resolver = LaunchdJob.resolver(executable: installed.appending(path: "tamis-dnsd"))
        let directory = installed.path(percentEncoded: false)

        return """
        set -e

        # Les binaires privilégiés quittent le bundle : launchd refuse de lancer un
        # démon root depuis un emplacement que l'utilisateur peut modifier. Effet de
        # bord voulu — le service ne dépend plus de l'application, donc supprimer
        # Tamis ne laisse pas le Mac avec un réglage proxy pointant vers rien.
        mkdir -p '\(directory)'
        cp '\(bundled.appending(path: "tamis-dnsd").path(percentEncoded: false))' '\(directory)/tamis-dnsd'
        chown -R root:wheel '\(directory)'
        chmod 755 '\(directory)/tamis-dnsd'

        # Autorité de certification, marquée de confiance pour SSL uniquement.
        security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
            -p ssl '\(authorityPEM.path(percentEncoded: false))'

        # Résolveur : launchd ouvre le port 53 et transmet le descripteur.
        cp '\(stagedPlist(for: resolver).path(percentEncoded: false))' '\(resolver.plistURL.path(percentEncoded: false))'
        chown root:wheel '\(resolver.plistURL.path(percentEncoded: false))'
        chmod 644 '\(resolver.plistURL.path(percentEncoded: false))'
        launchctl bootstrap \(resolver.domain) '\(resolver.plistURL.path(percentEncoded: false))'

        # Réglages réseau — les seuls changements qui redirigent du trafic, en dernier.
        networksetup -listallnetworkservices | tail -n +2 | while read -r service; do
            networksetup -setautoproxyurl "$service" '\(Installation.pacURL(port: pacPort))'
            networksetup -setdnsservers "$service" 127.0.0.1 ::1
        done
        """
    }

    /// The unprivileged half: files inside the user's own account.
    ///
    /// Done in Swift rather than as shell, because there is no authorisation to batch
    /// and a failure here should say which file rather than which exit code.
    public func applyUserChanges(pacContents: String) throws -> [Outcome] {
        var outcomes: [Outcome] = []
        let support = Installation.supportDirectory
        let helper = LaunchdJob.pacHelper(
            executable: bundled.appending(path: "tamis-pac"), port: pacPort
        )

        outcomes.append(try write(
            id: "pac-file", data: Data(pacContents.utf8),
            to: support.appending(path: "proxy.pac")
        ))
        outcomes.append(try write(
            id: "pac-helper", data: try helper.plistData(), to: helper.plistURL
        ))

        if !isDryRun {
            _ = try? run("/bin/launchctl", [
                "bootstrap", helper.domain, helper.plistURL.path(percentEncoded: false),
            ])
        }
        return outcomes
    }

    /// Property lists are written to the support directory first, then copied into
    /// place by the privileged script.
    ///
    /// Writing them from the privileged script instead would mean generating their
    /// contents inside a shell heredoc, where a path containing a quote becomes a
    /// command. Staging keeps the generation in Swift.
    public func stagePlists() throws -> [Outcome] {
        let staging = Installation.supportDirectory.appending(path: "staging")
        var outcomes: [Outcome] = []
        for job in [
            LaunchdJob.resolver(executable: installed.appending(path: "tamis-dnsd")),
        ] {
            outcomes.append(try write(
                id: "staged-\(job.label)", data: try job.plistData(),
                to: staging.appending(path: "\(job.label).plist")
            ))
        }
        return outcomes
    }

    func stagedPlist(for job: LaunchdJob) -> URL {
        Installation.supportDirectory
            .appending(path: "staging")
            .appending(path: "\(job.label).plist")
    }

    // MARK: Uninstall

    /// The privileged half of the removal, derived from the changes that are actually
    /// in place rather than from the full plan.
    ///
    /// Undoing something that was never done is how an uninstall script ends up
    /// disabling a setting somebody else made.
    public func uninstallScript() -> String {
        let applied = Installation.applied(proxyPort: proxyPort, pacPort: pacPort)
            .filter { $0.scope == .administrator }
        guard !applied.isEmpty else { return "" }

        // No `set -e` here, deliberately: a removal must keep going when one step finds
        // nothing to remove, or a half-uninstalled machine stays half-uninstalled.
        return applied.map { "# \($0.title)\n\($0.undoCommand)" }.joined(separator: "\n\n")
    }

    public func removeUserFiles() throws -> [Outcome] {
        let applied = Installation.applied(proxyPort: proxyPort, pacPort: pacPort)
            .filter { $0.scope == .user }
        var outcomes: [Outcome] = []

        for change in applied {
            if !isDryRun {
                _ = try? run("/bin/launchctl", [
                    "bootout", "gui/\(getuid())/\(Installation.helperLabel)",
                ])
            }
            for path in change.paths {
                outcomes.append(remove(id: change.id, at: path))
            }
        }
        outcomes.append(contentsOf: (try? stagingOutcomes()) ?? [])
        return outcomes
    }

    private func stagingOutcomes() throws -> [Outcome] {
        let staging = Installation.supportDirectory.appending(path: "staging")
        guard FileManager.default.fileExists(atPath: staging.path(percentEncoded: false))
        else { return [] }
        return [remove(id: "staging", at: staging)]
    }

    /// The user's own data, removed only when asked for separately.
    public func removeUserData() -> [Outcome] {
        Installation.userData().map { remove(id: "data", at: $0) }
    }

    // MARK: Doing it

    private func write(id: String, data: Data, to url: URL) throws -> Outcome {
        guard !isDryRun else {
            return Outcome(id: id, succeeded: true,
                           message: "écrirait \(url.path(percentEncoded: false))")
        }
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            try data.write(to: url, options: .atomic)
            return Outcome(id: id, succeeded: true, message: url.path(percentEncoded: false))
        } catch {
            throw Failure.notWritable("\(url.path(percentEncoded: false)) : \(error)")
        }
    }

    private func remove(id: String, at url: URL) -> Outcome {
        let path = url.path(percentEncoded: false)
        guard FileManager.default.fileExists(atPath: path) else {
            return Outcome(id: id, succeeded: true, message: "absent : \(path)")
        }
        guard !isDryRun else {
            return Outcome(id: id, succeeded: true, message: "supprimerait \(path)")
        }
        do {
            try FileManager.default.removeItem(at: url)
            return Outcome(id: id, succeeded: true, message: "supprimé : \(path)")
        } catch {
            return Outcome(id: id, succeeded: false, message: "\(path) : \(error)")
        }
    }

    @discardableResult
    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
        guard process.terminationStatus == 0 else { throw Failure.commandFailed(text) }
        return text
    }
}
