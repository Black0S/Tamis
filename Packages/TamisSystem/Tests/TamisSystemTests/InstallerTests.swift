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
