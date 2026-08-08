import Foundation

public enum DoHError: Error, Sendable, Equatable {
    case allEndpointsFailed(provider: String, diagnostics: [EndpointDiagnosis])
    case badStatus(Int)
    case badContentType(String?)
    case emptyResponse
    case responseTooLarge(Int)
}

/// Why one endpoint did not answer.
///
/// The distinction is not cosmetic. An endpoint that refuses to connect is a network
/// problem; an endpoint that answers but whose certificate does not validate is
/// **someone intercepting encrypted DNS**. Failing over silently in the second case
/// would hide exactly the thing Tamis exists to reveal.
///
/// Observed in the wild while building this: `1.1.1.1` answers ICMP in single-digit
/// milliseconds yet serves a certificate that fails validation, while `1.0.0.1` and
/// Cloudflare's IPv6 address are both clean. That address is widely hijacked by
/// consumer routers and ISPs.
public enum EndpointFailure: Sendable, Equatable {
    /// No usable connection: refused, timed out, unroutable.
    case unreachable
    /// Connected, but TLS validation failed — the hallmark of interception.
    case tlsValidationFailed
    /// Answered, but not with a DNS message.
    case badResponse
}

public struct EndpointDiagnosis: Sendable, Equatable {
    public let endpoint: URL
    public let failure: EndpointFailure
}

/// Sends DNS queries to an upstream resolver over HTTPS (RFC 8484).
///
/// Built on `URLSession` so the system HTTP/2 stack, connection reuse and TLS
/// validation come for free — including the post-quantum key exchange browsers now
/// negotiate by default, which we would otherwise have to track by hand.
///
/// Two things are configured deliberately rather than left to defaults:
///
/// - **The proxy is disabled explicitly.** Tamis's own traffic must never traverse
///   Tamis's proxy: the request would come straight back to us and hang.
/// - **Endpoints are IP literals**, so no name is ever resolved. See ``DoHProvider``.
public actor DoHClient {

    /// A DNS message cannot exceed 64 KiB, and an upstream that sends more is either
    /// broken or hostile. Bounded so a malicious resolver cannot exhaust memory.
    static let maxResponseBytes = 65_535

    private let session: URLSession
    private var provider: DoHProvider
    /// Index of the endpoint that last worked, tried first next time.
    private var preferredEndpoint = 0

    public init(provider: DoHProvider = .cloudflare, timeout: TimeInterval = 5) {
        self.provider = provider

        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]          // never through our own proxy
        config.timeoutIntervalForRequest = timeout
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpAdditionalHeaders = ["Accept": "application/dns-message"]
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        self.session = URLSession(configuration: config)
    }

    public func setProvider(_ provider: DoHProvider) {
        self.provider = provider
        self.preferredEndpoint = 0
    }

    public var currentProvider: DoHProvider { provider }

    /// Forwards a raw DNS query and returns the raw response.
    ///
    /// The message is relayed verbatim in both directions — never re-serialised — so
    /// EDNS options, DNSSEC records and anything else we do not model survive intact.
    public func resolve(query: [UInt8]) async throws -> [UInt8] {
        let endpoints = provider.endpoints
        guard !endpoints.isEmpty else {
            throw DoHError.allEndpointsFailed(provider: provider.name, diagnostics: [])
        }

        var diagnostics: [EndpointDiagnosis] = []
        for offset in 0..<endpoints.count {
            let index = (preferredEndpoint + offset) % endpoints.count
            let endpoint = endpoints[index]
            do {
                let response = try await send(query, to: endpoint)
                preferredEndpoint = index   // stick with whatever answered
                lastDiagnostics = diagnostics
                return response
            } catch {
                diagnostics.append(
                    EndpointDiagnosis(endpoint: endpoint, failure: Self.classify(error))
                )
            }
        }
        lastDiagnostics = diagnostics
        throw DoHError.allEndpointsFailed(provider: provider.name, diagnostics: diagnostics)
    }

    /// Failures recorded while satisfying the most recent query, including those that
    /// were recovered from by failing over.
    ///
    /// Kept even on success so the UI can report "1.1.1.1 is being intercepted on this
    /// network, using 1.0.0.1 instead" — a silent failover would leave the user
    /// believing their chosen resolver is the one answering.
    public private(set) var lastDiagnostics: [EndpointDiagnosis] = []

    static func classify(_ error: Error) -> EndpointFailure {
        guard let urlError = error as? URLError else {
            if error is DoHError { return .badResponse }
            return .unreachable
        }
        switch urlError.code {
        case .secureConnectionFailed,
             .serverCertificateUntrusted,
             .serverCertificateHasBadDate,
             .serverCertificateHasUnknownRoot,
             .serverCertificateNotYetValid,
             .clientCertificateRejected,
             .cannotLoadFromNetwork where urlError.localizedDescription.contains("SSL"):
            return .tlsValidationFailed
        case .cannotConnectToHost, .timedOut, .networkConnectionLost,
             .notConnectedToInternet, .cannotFindHost, .dnsLookupFailed:
            return .unreachable
        default:
            return .badResponse
        }
    }

    private func send(_ query: [UInt8], to endpoint: URL) async throws -> [UInt8] {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = Data(query)

        let (data, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse else { throw DoHError.emptyResponse }
        guard http.statusCode == 200 else { throw DoHError.badStatus(http.statusCode) }

        let contentType = http.value(forHTTPHeaderField: "Content-Type")?.lowercased()
        guard contentType?.hasPrefix("application/dns-message") == true else {
            throw DoHError.badContentType(contentType)
        }
        guard !data.isEmpty else { throw DoHError.emptyResponse }
        guard data.count <= Self.maxResponseBytes else {
            throw DoHError.responseTooLarge(data.count)
        }

        return [UInt8](data)
    }
}
