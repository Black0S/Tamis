import Foundation

/// Fetches a list, and nothing else.
///
/// Tamis's own traffic goes neither through its proxy nor through its filters. A
/// resolver that resolves through itself, or a downloader that downloads through the
/// thing it is updating, produces failures that look like network problems and are not.
public struct ListDownloader: Sendable {

    public struct Response: Sendable {
        public let statusCode: Int
        public let contentLength: Int?
        public let bytes: Int
        public let text: String
        public let etag: String?
        public let lastModified: String?
        /// 304: the copy on disk is current, and nothing was transferred.
        public var isUnchanged: Bool { statusCode == 304 }
    }

    public enum Failure: Error, Sendable, Equatable {
        case notHTTP
        case notUTF8
        case transport(String)
    }

    private let session: URLSession

    public init(session: URLSession? = nil) {
        self.session = session ?? Self.makeSession()
    }

    static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        // Empty, not nil: nil means "use the system settings", which Tamis has just
        // pointed at its own proxy.
        configuration.connectionProxyDictionary = [:]
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        // Conditional requests are made explicitly with the stored validators, so the
        // cache would only add a second, invisible notion of freshness.
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 300
        configuration.httpAdditionalHeaders = ["User-Agent": "Tamis"]
        return URLSession(configuration: configuration)
    }

    /// Downloads `url`, sending the stored validators so an unchanged list costs a
    /// header exchange instead of five megabytes.
    public func fetch(
        _ url: URL,
        etag: String? = nil,
        lastModified: String? = nil
    ) async throws -> Response {
        var request = URLRequest(url: url)
        if let etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        if let lastModified {
            request.setValue(lastModified, forHTTPHeaderField: "If-Modified-Since")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw Failure.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else { throw Failure.notHTTP }

        if http.statusCode == 304 {
            return Response(
                statusCode: 304, contentLength: 0, bytes: 0, text: "",
                etag: etag, lastModified: lastModified
            )
        }

        // A list that is not UTF-8 is not a list Tamis can read, and guessing an
        // encoding on a file of domain names invites silent corruption.
        guard let text = String(data: data, encoding: .utf8) else { throw Failure.notUTF8 }

        // `expectedContentLength` is -1 when the response is chunked, which is not a
        // truncation — it is the server declining to say. The guard treats nil as
        // "no promise made" rather than as a mismatch.
        let declared = http.expectedContentLength
        return Response(
            statusCode: http.statusCode,
            contentLength: declared >= 0 ? Int(declared) : nil,
            bytes: data.count,
            text: text,
            etag: http.value(forHTTPHeaderField: "ETag"),
            lastModified: http.value(forHTTPHeaderField: "Last-Modified")
        )
    }
}
