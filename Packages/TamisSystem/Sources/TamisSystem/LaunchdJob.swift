import Foundation

/// A launchd job, as the property list macOS reads.
///
/// Generated rather than shipped as a file, because two of its fields are only known at
/// install time — where the application ended up, and which port it listens on — and a
/// template with placeholders substituted by hand is a template somebody eventually
/// substitutes wrongly.
public struct LaunchdJob: Sendable, Equatable {

    public enum Kind: Sendable, Equatable {
        /// `/Library/LaunchDaemons`, running as root, one per machine.
        case daemon
        /// `~/Library/LaunchAgents`, running as the user, one per session.
        case agent
    }

    public let label: String
    public let kind: Kind
    public let executable: URL
    public let arguments: [String]
    /// Sockets launchd opens and hands over already bound.
    ///
    /// This is what lets the resolver answer on port 53 without ever running as root:
    /// launchd binds the privileged port and passes the descriptor, so the process that
    /// parses hostile input has no privileges at all.
    public let sockets: [Socket]
    public let keepAlive: Bool
    /// Mach services launchd advertises on the job's behalf.
    ///
    /// Without this the daemon can listen all it likes and nothing can find it: an XPC
    /// name is registered by launchd, not by the process.
    public let machServices: [String]

    public struct Socket: Sendable, Equatable {
        public let name: String
        public let port: UInt16
        /// `udp` for DNS, `tcp` for everything else here.
        public let isUDP: Bool
        /// Loopback only. A resolver reachable from the network is a resolver somebody
        /// else can use, and an open resolver is abuse waiting to be reported.
        public let host: String

        public init(name: String, port: UInt16, isUDP: Bool, host: String = "127.0.0.1") {
            self.name = name
            self.port = port
            self.isUDP = isUDP
            self.host = host
        }
    }

    public init(
        label: String, kind: Kind, executable: URL, arguments: [String] = [],
        sockets: [Socket] = [], keepAlive: Bool = true, machServices: [String] = []
    ) {
        self.label = label
        self.kind = kind
        self.executable = executable
        self.arguments = arguments
        self.sockets = sockets
        self.keepAlive = keepAlive
        self.machServices = machServices
    }

    /// Where this job's property list belongs.
    public var plistURL: URL {
        switch kind {
        case .daemon:
            URL(fileURLWithPath: "/Library/LaunchDaemons/\(label).plist")
        case .agent:
            FileManager.default.homeDirectoryForCurrentUser
                .appending(path: "Library/LaunchAgents/\(label).plist")
        }
    }

    /// The domain `launchctl` needs to load or unload it.
    public var domain: String {
        switch kind {
        case .daemon: "system"
        case .agent:  "gui/\(getuid())"
        }
    }

    public func plistData() throws -> Data {
        var job: [String: Any] = [
            "Label": label,
            // Full path, not just the executable name: launchd has no PATH worth
            // relying on, and a job that cannot find its binary fails silently.
            "ProgramArguments": [executable.path(percentEncoded: false)] + arguments,
            "RunAtLoad": true,
            "KeepAlive": keepAlive,
            "ProcessType": "Interactive",
        ]

        if !machServices.isEmpty {
            job["MachServices"] = Dictionary(uniqueKeysWithValues: machServices.map { ($0, true) })
        }

        if !sockets.isEmpty {
            var entries: [String: Any] = [:]
            for socket in sockets {
                entries[socket.name] = [
                    "SockServiceName": String(socket.port),
                    "SockType": socket.isUDP ? "dgram" : "stream",
                    "SockNodeName": socket.host,
                    "SockFamily": "IPv4",
                ]
            }
            job["Sockets"] = entries
            // With sockets, launchd starts the job on demand and restarting it on exit
            // would fight that.
            job["KeepAlive"] = false
        }

        return try PropertyListSerialization.data(
            fromPropertyList: job, format: .xml, options: 0
        )
    }

    // MARK: The jobs Tamis installs

    public static func resolver(executable: URL, port: UInt16 = 53) -> LaunchdJob {
        LaunchdJob(
            label: Installation.resolverLabel,
            kind: .daemon,
            executable: executable,
            arguments: ["--launchd-socket", "Resolver"],
            sockets: [Socket(name: "Resolver", port: port, isUDP: true)]
        )
    }

    /// The helper that serves the PAC.
    ///
    /// An agent rather than a daemon, and deliberately separate from the application:
    /// macOS keeps pointing at the auto-configuration URL after Tamis quits, so
    /// something must stay to answer it. What it answers when the proxy is gone is
    /// `DIRECT` — see ``ProxyAutoConfig/failOpen``.
    public static func pacHelper(executable: URL, port: UInt16 = 7655) -> LaunchdJob {
        LaunchdJob(
            label: Installation.helperLabel,
            kind: .agent,
            executable: executable,
            arguments: ["--port", String(port)]
        )
    }

    public static func privilegedDaemon(executable: URL) -> LaunchdJob {
        LaunchdJob(
            label: Installation.daemonLabel,
            kind: .daemon,
            executable: executable,
            machServices: [Installation.daemonLabel]
        )
    }
}
