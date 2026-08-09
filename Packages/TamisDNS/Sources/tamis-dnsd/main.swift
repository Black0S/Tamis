import Foundation
import TamisDNS

// The resolver daemon.
//
// Under launchd it adopts the socket launchd already bound — which is how port 53 is
// served without this process ever holding root. Run by hand it binds a port itself,
// so the whole thing can be exercised with no privileges and nothing installed:
//
//   swift run -c release tamis-dnsd --port 15353 --lists hosts.txt
//   dig @127.0.0.1 -p 15353 example.com

// Line-buffered, so output survives when stdout is a pipe or a log file rather than
// a terminal. Without this a crash loses everything the daemon had to say.
setvbuf(stdout, nil, _IOLBF, 0)

struct Options {
    var port: UInt16?
    var lists: [String] = []
    var provider = DoHProvider.cloudflare
    var socketName = "DNS"
}

func parseArguments() -> Options {
    var options = Options()
    var arguments = Array(CommandLine.arguments.dropFirst())
    while let argument = arguments.first {
        arguments.removeFirst()
        switch argument {
        case "--port":
            options.port = arguments.first.flatMap(UInt16.init)
            if !arguments.isEmpty { arguments.removeFirst() }
        case "--socket":
            if let name = arguments.first { options.socketName = name; arguments.removeFirst() }
        case "--provider":
            if let name = arguments.first?.lowercased() {
                options.provider = DoHProvider.presets.first { $0.name.lowercased() == name }
                    ?? DoHProvider.cloudflare
                arguments.removeFirst()
            }
        case "--lists":
            while let path = arguments.first, !path.hasPrefix("--") {
                options.lists.append(path)
                arguments.removeFirst()
            }
        default:
            FileHandle.standardError.write(Data("unknown argument: \(argument)\n".utf8))
            exit(2)
        }
    }
    return options
}

let options = parseArguments()

// Lists first: starting to answer before the policy is loaded would forward traffic
// the user asked to have blocked.
var lines: [String] = []
for path in options.lists {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        FileHandle.standardError.write(Data("cannot read \(path)\n".utf8))
        exit(1)
    }
    lines.append(contentsOf: text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init))
}
let blocklist = DomainBlocklist(lines: lines)
let policy = ResolverPolicy(blocklist: blocklist)

let socket: DNSSocket
if let port = options.port {
    socket = try DNSSocket.bind(host: "127.0.0.1", port: port)
} else {
    do {
        socket = try SocketActivation.socket(named: options.socketName)
    } catch {
        FileHandle.standardError.write(Data("""
        no socket from launchd (\(error)).
        Pass --port to bind one directly.\n
        """.utf8))
        exit(1)
    }
}

let server = DNSServer(
    socket: socket,
    policy: policy,
    upstream: DoHClient(provider: options.provider)
)

let listening = socket.boundPort().map(String.init) ?? "?"
print("tamis-dnsd listening on \(listening)  ·  \(blocklist.stats.blockEntries) rules  ·  upstream \(options.provider.name)")

await server.setDecisionHandler { name, outcome in
    if case .block(let reason) = outcome {
        switch reason {
        case .blocklist(let matched): print("  BLOCK  \(name)  ← \(matched)")
        case .firefoxCanary:          print("  BLOCK  \(name)  ← Firefox canary")
        }
    }
}
await server.start()

// Report on the way out rather than dying silently. The source runs on its own queue:
// the main queue is never serviced here, because `dispatchMain()` cannot be used from
// the async context that top-level `await` creates — it would return immediately and
// the process would exit with the socket barely open.
let signalQueue = DispatchQueue(label: "net.tamis.dnsd.signal")
signal(SIGINT, SIG_IGN)
signal(SIGTERM, SIG_IGN)
let sources = [SIGINT, SIGTERM].map { number -> DispatchSourceSignal in
    let source = DispatchSource.makeSignalSource(signal: number, queue: signalQueue)
    source.setEventHandler {
        Task {
            let stats = await server.statistics
            print("""

            queries \(stats.queries) · blocked \(stats.blocked) · cache \(stats.cacheHits) \
            · forwarded \(stats.forwarded) · upstream failures \(stats.upstreamFailures)
            """)
            exit(0)
        }
    }
    source.resume()
    return source
}
_ = sources

// Park the main task. The read source and the signal sources run on their own queues.
while true {
    try? await Task.sleep(for: .seconds(3600))
}
