import Foundation
import Darwin

/// The resolver: reads queries from a UDP socket, decides, answers.
///
/// The pipeline per query, cheapest first:
///
/// 1. **Policy** — Tamis's own domains, the Firefox canary, the user's blocklists.
///    Costs a few set lookups and never touches the network.
/// 2. **Cache** — a hit answers without leaving the machine.
/// 3. **Upstream** — DoH, then the answer is cached.
///
/// A failure at step 3 answers `SERVFAIL` rather than nothing: a client left waiting
/// retries and stalls, which reads to the user as "the internet is broken".
public actor DNSServer {

    public struct Statistics: Sendable, Equatable {
        public var queries = 0
        public var blocked = 0
        public var cacheHits = 0
        public var forwarded = 0
        public var upstreamFailures = 0
        public var malformed = 0

        public init() {}
    }

    /// A DNS datagram over UDP cannot exceed 64 KiB even with EDNS0.
    static let maxDatagram = 65_535

    private let socket: DNSSocket
    private let policy: ResolverPolicy
    private let upstream: DoHClient
    private let cache: DNSCache
    private var readSource: DispatchSourceRead?

    public private(set) var statistics = Statistics()
    /// Called for every decision, so the app can build its history without the server
    /// knowing anything about storage.
    public var onDecision: (@Sendable (String, ResolverPolicy.Outcome) -> Void)?

    public init(
        socket: DNSSocket,
        policy: ResolverPolicy,
        upstream: DoHClient = DoHClient(),
        cache: DNSCache = DNSCache()
    ) {
        self.socket = socket
        self.policy = policy
        self.upstream = upstream
        self.cache = cache
    }

    public func setDecisionHandler(_ handler: @escaping @Sendable (String, ResolverPolicy.Outcome) -> Void) {
        self.onDecision = handler
    }

    // MARK: Lifecycle

    public func start() {
        guard readSource == nil else { return }
        let queue = DispatchQueue(label: "net.tamis.dnsd.read")
        let source = DispatchSource.makeReadSource(fileDescriptor: socket.descriptor, queue: queue)
        let fd = socket.descriptor

        source.setEventHandler { [weak self] in
            guard let self else { return }
            // recvfrom is non-blocking here: the source only fires when data is ready.
            var buffer = [UInt8](repeating: 0, count: Self.maxDatagram)
            var address = sockaddr_storage()
            var addressLength = socklen_t(MemoryLayout<sockaddr_storage>.size)

            let received = withUnsafeMutablePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(fd, &buffer, Self.maxDatagram, 0, sa, &addressLength)
                }
            }
            guard received > 0 else { return }

            let datagram = Array(buffer[0..<received])
            let client = ClientAddress(storage: address, length: addressLength)
            Task { await self.handle(datagram: datagram, from: client) }
        }
        source.resume()
        readSource = source
    }

    public func stop() {
        readSource?.cancel()
        readSource = nil
    }

    // MARK: Handling

    func handle(datagram: [UInt8], from client: ClientAddress) async {
        statistics.queries += 1

        guard let query = try? DNSQuery(datagram: datagram) else {
            // Not answerable: without a parsable header there is no ID to answer with,
            // and replying to a malformed datagram is how reflection attacks are fed.
            statistics.malformed += 1
            return
        }

        let outcome = policy.outcome(forName: query.name)
        onDecision?(query.name, outcome)

        if case .block = outcome {
            statistics.blocked += 1
            send(DNSResponse.refusal(to: query, code: .nameError), to: client)
            return
        }

        if let cached = await cache.lookup(query) {
            statistics.cacheHits += 1
            send(cached, to: client)
            return
        }

        do {
            let response = try await upstream.resolve(query: datagram)
            statistics.forwarded += 1
            await cache.store(query: query, response: response)
            send(response, to: client)
        } catch {
            statistics.upstreamFailures += 1
            // Answer rather than stay silent: a client left waiting retries and
            // stalls, which the user experiences as a broken network.
            send(DNSResponse.refusal(to: query, code: .serverFailure), to: client)
        }
    }

    private func send(_ bytes: [UInt8], to client: ClientAddress) {
        var storage = client.storage
        _ = withUnsafePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bytes.withUnsafeBufferPointer { buffer in
                    sendto(socket.descriptor, buffer.baseAddress, buffer.count, 0, sa, client.length)
                }
            }
        }
    }
}

/// The address a datagram came from, carried back to the reply.
struct ClientAddress: @unchecked Sendable {
    let storage: sockaddr_storage
    let length: socklen_t
}
