import Foundation
import Observation
import TamisDNS
import TamisHistory

/// The local resolver, run from inside the app.
///
/// It binds a high port on the loopback and nothing else. Taking over port 53 is the
/// installer's job, and it needs a privileged daemon that does not exist yet — but a
/// resolver on 15353 is the same resolver, answering the same way, and it can be
/// pointed at with `dig` today without asking the machine for anything.
@MainActor
@Observable
final class ResolverModel {

    enum State: Sendable, Equatable {
        case stopped
        case running(port: UInt16)
        case failed(String)

        var port: UInt16? { if case .running(let p) = self { p } else { nil } }
        var isRunning: Bool { port != nil }
    }

    struct Decision: Identifiable, Sendable, Equatable {
        let id = UUID()
        let date: Date
        let name: String
        let outcome: ResolverPolicy.Outcome

        var isBlocked: Bool { if case .block = outcome { true } else { false } }
    }

    private(set) var state: State = .stopped
    private(set) var statistics = DNSServer.Statistics()
    /// The last few decisions, newest first. Bounded, because this is a window into
    /// what is happening and not the history — the history is a database that does not
    /// exist yet.
    private(set) var recent: [Decision] = []

    var provider: DoHProvider = .cloudflare
    /// 0 asks the kernel. A fixed default makes the `dig` line in the interface
    /// copyable, which is the only reason it is not 0.
    var port: UInt16 = 15353

    private var server: DNSServer?
    private var socket: DNSSocket?
    private var pollTask: Task<Void, Never>?
    /// Where decisions are kept. Set by the app; the resolver works without one.
    var history: HistoryModel?

    static let recentLimit = 50

    // MARK: Lifecycle

    func start(blocklist: DomainBlocklist) async {
        guard !state.isRunning else { return }
        do {
            let socket = try DNSSocket.bind(host: "127.0.0.1", port: port)
            let server = DNSServer(
                socket: socket,
                policy: ResolverPolicy(blocklist: blocklist),
                upstream: DoHClient(provider: provider)
            )

            // The server knows nothing about storage; it hands each decision over and
            // the model decides what to keep.
            let sink = DecisionSink { [weak self] name, outcome in
                Task { @MainActor in self?.record(name: name, outcome: outcome) }
            }
            await server.setDecisionHandler { name, outcome in sink.send(name, outcome) }
            await server.start()

            self.socket = socket
            self.server = server
            self.state = .running(port: socket.boundPort() ?? port)
            startPolling()
        } catch {
            state = .failed(Self.describe(error))
        }
    }

    func stop() async {
        pollTask?.cancel()
        pollTask = nil
        await server?.stop()
        socket?.close()
        server = nil
        socket = nil
        state = .stopped
    }

    /// Restarts with the current provider and blocklist. Changing a resolver under a
    /// running server would leave answers in flight resolved by the previous one.
    func restart(blocklist: DomainBlocklist) async {
        await stop()
        await start(blocklist: blocklist)
    }

    // MARK: Observing

    private func startPolling() {
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let server = await self?.server else { return }
                let statistics = await server.statistics
                await MainActor.run { self?.statistics = statistics }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func record(name: String, outcome: ResolverPolicy.Outcome) {
        recent.insert(Decision(date: .now, name: name, outcome: outcome), at: 0)
        if recent.count > Self.recentLimit { recent.removeLast(recent.count - Self.recentLimit) }

        guard let history else { return }
        let action: EventStore.Action
        var rule: String?
        switch outcome {
        case .forward:
            action = .allowed
        case .block(let reason):
            action = .blocked
            switch reason {
            case .blocklist(let matched): rule = matched
            case .firefoxCanary:          rule = "canari Firefox"
            }
        }
        // No URL: a resolver never sees one, and inventing the query name as a URL
        // would put something in that column that was never on the wire.
        Task { await history.record(.init(
            domain: name, action: action, layer: .dns, rule: rule
        )) }
    }

    private static func describe(_ error: Error) -> String {
        guard let error = error as? SocketError else { return "\(error)" }
        switch error {
        case .bindFailed(let code) where code == EADDRINUSE:
            return "Ce port est déjà utilisé par un autre programme."
        case .bindFailed(let code) where code == EACCES:
            return "Ce port demande des privilèges. Choisissez un port au-dessus de 1024."
        default:
            return "\(error)"
        }
    }
}

/// Bridges the server's `@Sendable` callback onto the main actor without capturing it.
private final class DecisionSink: Sendable {
    private let handler: @Sendable (String, ResolverPolicy.Outcome) -> Void

    init(_ handler: @escaping @Sendable (String, ResolverPolicy.Outcome) -> Void) {
        self.handler = handler
    }

    func send(_ name: String, _ outcome: ResolverPolicy.Outcome) {
        handler(name, outcome)
    }
}
