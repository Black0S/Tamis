import Darwin
import Foundation
import Testing
@testable import TamisApps

/// Attribution is checked against a connection this process really makes, because the
/// only claim worth testing is that the walk finds a socket that exists — and a fixture
/// cannot have one.
@Suite("Process attribution", .serialized)
struct ProcessAttributorTests {

    /// Opens a listener on the loopback, connects to it, and reports the *client's*
    /// local port — which is exactly what the proxy sees on an incoming connection.
    private func makeConnection() throws -> (client: Int32, server: Int32, accepted: Int32, port: UInt16) {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        #expect(listener >= 0)
        var yes: Int32 = 1
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = 0
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        #expect(bound == 0)
        #expect(listen(listener, 1) == 0)

        var boundAddress = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &boundAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(listener, $0, &length)
            }
        }

        let client = socket(AF_INET, SOCK_STREAM, 0)
        #expect(client >= 0)
        var target = boundAddress
        let connected = withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        #expect(connected == 0)
        let accepted = accept(listener, nil, nil)

        var clientAddress = sockaddr_in()
        var clientLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &clientAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(client, $0, &clientLength)
            }
        }
        return (client, listener, accepted, UInt16(bigEndian: clientAddress.sin_port))
    }

    @Test("A live connection is attributed to this process")
    func attributesRealConnection() throws {
        let connection = try makeConnection()
        defer {
            close(connection.client); close(connection.accepted); close(connection.server)
        }

        let attributor = ProcessAttributor()
        let found = try #require(
            attributor.attribute(localPort: connection.port),
            "le port \(connection.port) n'a été attribué à aucun processus"
        )
        #expect(found.pid == getpid())
        #expect(!found.executablePath.isEmpty)
        #expect(!found.name.isEmpty)
    }

    /// The answer has to survive the connection being reused, which is what the cache is
    /// for — and it must not survive the port being reused by somebody else, which is
    /// what its lifetime is for.
    @Test("The second answer comes from the cache")
    func caches() throws {
        let connection = try makeConnection()
        defer {
            close(connection.client); close(connection.accepted); close(connection.server)
        }

        let attributor = ProcessAttributor()
        let first = try #require(attributor.attribute(localPort: connection.port))

        // Closing the socket makes the walk fail; only the cache can still answer.
        close(connection.client)
        let second = attributor.attribute(localPort: connection.port)
        #expect(second == first)

        attributor.forget()
        #expect(attributor.attribute(localPort: connection.port) == nil)
    }

    @Test("A stale cache entry is not reused")
    func cacheExpires() throws {
        let connection = try makeConnection()
        defer {
            close(connection.client); close(connection.accepted); close(connection.server)
        }

        let attributor = ProcessAttributor(portEntryLifetime: 5)
        let now = Date()
        #expect(attributor.attribute(localPort: connection.port, now: now) != nil)

        close(connection.client)
        // Past the lifetime the walk runs again, finds nothing, and says so rather than
        // handing back an answer about a port that now belongs to someone else.
        #expect(attributor.attribute(localPort: connection.port,
                                     now: now.addingTimeInterval(30)) == nil)
    }

    /// A port nobody holds must produce no answer at all. Guessing here would attribute
    /// traffic to an application chosen essentially at random.
    @Test("An unused port is not attributed")
    func unusedPort() {
        let attributor = ProcessAttributor()
        #expect(attributor.attribute(localPort: 1) == nil)
    }

    @Test("An executable inside a bundle resolves to that bundle")
    func enclosingBundle() {
        let executable = URL(fileURLWithPath: "/Applications/Safari.app/Contents/MacOS/Safari")
        #expect(ProcessAttributor.enclosingBundle(of: executable)?.lastPathComponent == "Safari.app")
    }

    /// A helper gets its own bundle, not its parent's: a renderer is a different process
    /// carrying different traffic, and a rule written for the browser should not quietly
    /// cover something else.
    @Test("A nested helper resolves to its own bundle")
    func nestedHelper() {
        let executable = URL(fileURLWithPath:
            "/Applications/X.app/Contents/Frameworks/X Helper.app/Contents/MacOS/X Helper")
        #expect(ProcessAttributor.enclosingBundle(of: executable)?.lastPathComponent
                == "X Helper.app")
    }

    @Test("A command-line tool has no bundle, and none is invented")
    func plainExecutable() {
        #expect(ProcessAttributor.enclosingBundle(of: URL(fileURLWithPath: "/usr/bin/curl")) == nil)
    }

    /// The walk costs a syscall per process and another per descriptor. Paying that on
    /// every connection to answer a question nobody asked is the thing to avoid.
    @Test("The walk is skipped when no rule depends on it")
    func skippedWhenPointless() {
        #expect(ProcessAttributor.isNeeded(policies: AppPolicySet(), hasAppScopedScripts: false)
                == false)
        #expect(ProcessAttributor.isNeeded(policies: AppPolicySet(), hasAppScopedScripts: true))

        let policies = AppPolicySet(policies: [
            AppPolicy(bundleID: "a", treatment: .passthrough, rationale: .unknownDefault)
        ])
        #expect(ProcessAttributor.isNeeded(policies: policies, hasAppScopedScripts: false))
    }
}

/// The caches and the `isNeeded` check are justified by this number, so it is measured
/// rather than asserted.
@Suite("Attribution cost")
struct AttributionCostTests {

    @Test("The walk is slow enough to be worth caching, the cache fast enough to matter")
    func cost() throws {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        listen(listener, 1)
        var bound = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) }
        }
        let client = socket(AF_INET, SOCK_STREAM, 0)
        var target = bound
        _ = withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        let accepted = accept(listener, nil, nil)
        defer { close(client); close(accepted); close(listener) }

        var clientAddress = sockaddr_in()
        var clientLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &clientAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(client, $0, &clientLength)
            }
        }
        let port = UInt16(bigEndian: clientAddress.sin_port)

        let cold = ProcessAttributor()
        var started = Date()
        for _ in 0..<10 { cold.forget(); _ = cold.attribute(localPort: port) }
        let walk = Date().timeIntervalSince(started) / 10

        let warm = ProcessAttributor()
        _ = warm.attribute(localPort: port)
        started = Date()
        for _ in 0..<10_000 { _ = warm.attribute(localPort: port) }
        let cached = Date().timeIntervalSince(started) / 10_000

        print(String(format: "  parcours %.1f ms · cache %.2f µs · rapport %.0f×",
                     walk * 1_000, cached * 1_000_000, walk / cached))
        #expect(walk > cached, "le cache doit être plus rapide que le parcours")
    }
}
