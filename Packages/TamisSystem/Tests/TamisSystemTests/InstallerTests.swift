import Foundation
import Testing
@testable import TamisSystem

@Suite("Installer")
struct InstallerTests {

    private let application = URL(fileURLWithPath: "/Applications/Tamis.app")

    private func installer(dryRun: Bool = true) -> Installer {
        Installer(applicationURL: application, isDryRun: dryRun)
    }

    /// An installer that runs when nobody asked is not an installer.
    @Test("Nothing happens by default")
    func dryRunIsTheDefault() throws {
        #expect(Installer(applicationURL: application).isDryRun)

        let outcomes = try installer().stagePlists()
        #expect(!outcomes.contains { !$0.succeeded })
        #expect(outcomes.allSatisfy { $0.message.hasPrefix("écrirait") })

        let staging = Installation.supportDirectory.appending(path: "staging")
        #expect(!FileManager.default.fileExists(atPath: staging.path(percentEncoded: false)),
                "un essai à blanc a créé des fichiers")
    }

    /// The user is trusting a script they were shown. It has to be readable, and it has
    /// to contain exactly what it claims.
    @Test("The privileged script names every command it will run")
    func scriptIsReadable() {
        let script = installer().privilegedScript(
            authorityPEM: URL(fileURLWithPath: "/tmp/ca.pem")
        )
        // `bootstrap` takes a domain and a path; `bootout` takes a service target.
        // Getting those the wrong way round produces a command that fails at install
        // time and nowhere earlier.
        for expected in [
            "launchctl bootstrap system '/Library/LaunchDaemons/\(Installation.daemonLabel).plist'",
            "security add-trusted-cert",
            "launchctl bootstrap system '/Library/LaunchDaemons/\(Installation.resolverLabel).plist'",
            "networksetup -setautoproxyurl",
        ] {
            #expect(script.contains(expected), "le script ne contient pas « \(expected) »")
        }
    }

    /// Trusted for SSL and nothing else. A root marked good for everything could sign
    /// code, e-mail and timestamps, none of which Tamis has any business doing.
    @Test("The authority is trusted only for SSL")
    func authorityScope() {
        let script = installer().privilegedScript(authorityPEM: URL(fileURLWithPath: "/tmp/ca.pem"))
        #expect(script.contains("-p ssl"))
        #expect(script.contains("-r trustRoot"))
    }

    /// Generating property list contents inside a shell heredoc would turn a path
    /// containing a quote into a command. They are written by Swift and copied.
    @Test("Property lists are staged, never written from the shell")
    func plistsAreStaged() {
        let script = installer().privilegedScript(authorityPEM: URL(fileURLWithPath: "/tmp/ca.pem"))
        #expect(script.contains("staging/\(Installation.daemonLabel).plist"))
        #expect(!script.contains("<?xml"), "un plist est construit dans le shell")
        #expect(!script.contains("cat >"), "un fichier est écrit depuis le shell")
    }

    /// The one change that redirects traffic goes last, so an interrupted install
    /// leaves a machine that still browses normally.
    @Test("The proxy setting is the last thing the script does")
    func proxyLast() throws {
        let script = installer().privilegedScript(authorityPEM: URL(fileURLWithPath: "/tmp/ca.pem"))
        let proxy = try #require(script.range(of: "networksetup -setautoproxyurl"))
        let certificate = try #require(script.range(of: "security add-trusted-cert"))
        let resolver = try #require(script.range(of: Installation.resolverLabel))
        #expect(proxy.lowerBound > certificate.lowerBound)
        #expect(proxy.lowerBound > resolver.lowerBound)
    }

    /// Undoing something that was never done is how an uninstall comes to disable a
    /// setting somebody else made.
    @Test("The uninstall script only undoes what is in place")
    func uninstallIsDerived() {
        // Nothing is installed on a machine running the tests, so there is nothing to
        // undo — and the script must be empty rather than a list of hopeful commands.
        let script = installer().uninstallScript()
        if Installation.applied().isEmpty {
            #expect(script.isEmpty)
        } else {
            #expect(!script.isEmpty)
        }
    }

    /// A removal that stops at the first missing file leaves a half-uninstalled machine
    /// half-uninstalled.
    @Test("The uninstall script does not abort on a missing step")
    func uninstallKeepsGoing() {
        #expect(!installer().uninstallScript().contains("set -e"))
    }

    @Test("A dry-run uninstall removes nothing")
    func dryRunUninstall() throws {
        let removed = try installer().removeUserFiles()
        let outcomes = removed + installer().removeUserData()
        for outcome in outcomes {
            #expect(outcome.succeeded)
            #expect(outcome.message.hasPrefix("supprimerait") || outcome.message.hasPrefix("absent"))
        }
    }

    /// Written for real this time, into a directory the test owns, because a dry run
    /// that is never contrasted with a real one proves only that nothing happened.
    @Test("A real write produces the property list launchd expects")
    func realWrite() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-installer-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let job = LaunchdJob.resolver(executable: application.appending(path: "Contents/MacOS/x"))
        let url = root.appending(path: "\(job.label).plist")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try job.plistData().write(to: url)

        let parsed = try PropertyListSerialization.propertyList(
            from: try Data(contentsOf: url), options: [], format: nil
        ) as? [String: Any]
        #expect(parsed?["Label"] as? String == Installation.resolverLabel)
    }
}

/// The requirement that decides whether the daemon starts at all.
@Suite("Privileged binaries leave the bundle")
struct PrivilegedLocationTests {

    private let installer = Installer(
        applicationURL: URL(fileURLWithPath: "/Applications/Tamis.app")
    )

    /// launchd refuses to start a root daemon from a location the user can write to,
    /// and `/Applications` is one. A job pointing into the bundle fails at install
    /// time, with an error that says nothing about why.
    @Test("No launchd job points into the application bundle")
    func jobsPointOutsideTheBundle() throws {
        for job in [
            LaunchdJob.privilegedDaemon(
                executable: Installation.privilegedDirectory.appending(path: "tamisd")),
            LaunchdJob.resolver(
                executable: Installation.privilegedDirectory.appending(path: "tamis-dnsd")),
        ] {
            let arguments = try PropertyListSerialization.propertyList(
                from: try job.plistData(), options: [], format: nil
            ) as? [String: Any]
            let path = try #require((arguments?["ProgramArguments"] as? [String])?.first)
            #expect(!path.contains(".app/"), "\(job.label) est lancé depuis le bundle")
            #expect(path.hasPrefix(Installation.privilegedDirectory.path(percentEncoded: false)))
        }
    }

    @Test("The script copies the binaries out and makes them root-owned")
    func scriptCopiesBinaries() {
        let script = installer.privilegedScript(authorityPEM: URL(fileURLWithPath: "/tmp/ca.pem"))
        let directory = Installation.privilegedDirectory.path(percentEncoded: false)
        #expect(script.contains("cp '/Applications/Tamis.app/Contents/MacOS/tamisd' '\(directory)/tamisd'"))
        #expect(script.contains("chown -R root:wheel '\(directory)'"))
        #expect(script.contains("chmod 755"))
    }

    /// The copies are outside the bundle, so deleting the application cannot remove
    /// them — which means the uninstall has to, or they stay for ever.
    @Test("The uninstall removes the copies it made")
    func uninstallRemovesCopies() {
        let daemon = try? #require(Installation.plan().first { $0.id == "daemon" })
        #expect(daemon?.undoCommand.contains(Installation.privilegedDirectory.path(percentEncoded: false)) == true)
        #expect(daemon?.paths.contains(Installation.privilegedDirectory) == true)
    }

    /// Pointing DNS at Tamis is what makes the resolver cover the whole machine, and
    /// leaving it pointed there after uninstalling would leave a Mac that cannot
    /// resolve anything.
    @Test("DNS is set on install and cleared on uninstall")
    func dnsIsSetAndCleared() throws {
        let script = installer.privilegedScript(authorityPEM: URL(fileURLWithPath: "/tmp/ca.pem"))
        #expect(script.contains("networksetup -setdnsservers \"$service\" 127.0.0.1 ::1"))

        let proxy = try #require(Installation.plan().first { $0.id == "system-proxy" })
        #expect(proxy.undoCommand.contains("-setdnsservers"))
        #expect(proxy.undoCommand.contains("empty"))
    }
}
