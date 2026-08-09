import Foundation
import Testing
@testable import TamisSystem

@Suite("launchd jobs")
struct LaunchdJobTests {

    private func plist(_ job: LaunchdJob) throws -> [String: Any] {
        let data = try job.plistData()
        let parsed = try PropertyListSerialization.propertyList(
            from: data, options: [], format: nil
        )
        return try #require(parsed as? [String: Any])
    }

    /// launchd has no PATH worth relying on, and a job that cannot find its binary
    /// fails without saying so.
    @Test("The job names the executable by full path")
    func fullPath() throws {
        let job = LaunchdJob.privilegedDaemon(
            executable: URL(fileURLWithPath: "/Applications/Tamis.app/Contents/MacOS/tamisd")
        )
        let arguments = try #require(try plist(job)["ProgramArguments"] as? [String])
        #expect(arguments.first == "/Applications/Tamis.app/Contents/MacOS/tamisd")
    }

    /// The whole reason the resolver can answer on port 53 without privileges: launchd
    /// binds the port and hands over the descriptor.
    @Test("The resolver asks launchd for the socket rather than binding it")
    func socketActivation() throws {
        let job = LaunchdJob.resolver(
            executable: URL(fileURLWithPath: "/Applications/Tamis.app/Contents/MacOS/tamis-dnsd")
        )
        let sockets = try #require(try plist(job)["Sockets"] as? [String: Any])
        let resolver = try #require(sockets["Resolver"] as? [String: Any])

        #expect(resolver["SockServiceName"] as? String == "53")
        #expect(resolver["SockType"] as? String == "dgram")
        // An open resolver is abuse waiting to be reported.
        #expect(resolver["SockNodeName"] as? String == "127.0.0.1")
    }

    /// With a socket, launchd starts the job on demand; restarting it on exit would
    /// fight that rather than help.
    @Test("A socket-activated job does not also ask to be kept alive")
    func keepAliveOffWithSockets() throws {
        let job = LaunchdJob.resolver(executable: URL(fileURLWithPath: "/bin/true"))
        #expect(try plist(job)["KeepAlive"] as? Bool == false)

        let plain = LaunchdJob.privilegedDaemon(executable: URL(fileURLWithPath: "/bin/true"))
        #expect(try plist(plain)["KeepAlive"] as? Bool == true)
    }

    @Test("Daemons and agents land where launchd looks for them")
    func locations() {
        let daemon = LaunchdJob.privilegedDaemon(executable: URL(fileURLWithPath: "/bin/true"))
        #expect(daemon.plistURL.path(percentEncoded: false)
                == "/Library/LaunchDaemons/\(Installation.daemonLabel).plist")
        #expect(daemon.domain == "system")

        let agent = LaunchdJob.pacHelper(executable: URL(fileURLWithPath: "/bin/true"))
        #expect(agent.plistURL.path(percentEncoded: false).contains("Library/LaunchAgents"))
        #expect(agent.domain == "gui/\(getuid())")
    }

    /// The paths the plan promises to remove have to be the paths the jobs actually
    /// write. These two lists live in different files, and nothing but a test keeps
    /// them agreeing.
    @Test("The plan removes exactly what the jobs create")
    func planMatchesJobs() {
        let executable = URL(fileURLWithPath: "/Applications/Tamis.app/Contents/MacOS/x")
        let created = Set([
            LaunchdJob.resolver(executable: executable).plistURL,
            LaunchdJob.pacHelper(executable: executable).plistURL,
        ].map { $0.path(percentEncoded: false) })

        let promised = Set(Installation.plan().flatMap(\.paths).map { $0.path(percentEncoded: false) })
        for path in created {
            #expect(promised.contains(path), "\(path) est créé mais jamais retiré")
        }
    }

    @Test("The property list is what launchd accepts, not merely valid XML")
    func wellFormed() throws {
        let job = LaunchdJob.resolver(executable: URL(fileURLWithPath: "/bin/true"))
        let parsed = try plist(job)
        #expect(parsed["Label"] as? String == Installation.resolverLabel)
        #expect(parsed["RunAtLoad"] as? Bool == true)
        #expect(String(decoding: try job.plistData(), as: UTF8.self).hasPrefix("<?xml"))
    }
}
