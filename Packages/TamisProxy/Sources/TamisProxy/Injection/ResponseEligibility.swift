import Foundation
import NIOHTTP1

/// Decides whether a response may be buffered and rewritten.
///
/// Expressed as a positive predicate rather than a list of exceptions, so anything
/// unforeseen falls on the safe side: not eligible means relayed untouched, zero copy.
/// A list of exclusions would have every new case default to "modify it and hope".
public enum ResponseEligibility {

    /// Beyond this, the head is not coming. No real document places `</head>` two
    /// megabytes in, and holding more would let one response consume the memory of
    /// every other connection.
    public static let maximumBufferedBytes = 2 * 1024 * 1024

    public enum Verdict: Sendable, Equatable {
        case eligible
        case notEligible(reason: Reason)
    }

    public enum Reason: Sendable, Equatable {
        case notOK(UInt)
        case notHTML(String?)
        case notADocument(String?)
        case partialContent
        case undecodableEncoding(String)
    }

    /// Content encodings the pipeline can actually decode.
    ///
    /// Brotli is included because Apple's `Compression` framework implements it, so
    /// supporting it costs no third-party C decompressor in a process whose entire
    /// input is hostile. zstd stays out: the framework does not implement it, and no
    /// measured origin chose it over brotli or gzip.
    static let decodableEncodings: Set<String> = ["gzip", "deflate", "x-gzip", "br", "identity"]

    public static func verdict(
        for head: HTTPResponseHead,
        requestType secFetchDest: String?
    ) -> Verdict {
        // 206 carries a slice of a body: injecting into a fragment corrupts it, and the
        // client will stitch the pieces back together.
        if head.status == .partialContent { return .notEligible(reason: .partialContent) }
        guard head.status == .ok else { return .notEligible(reason: .notOK(head.status.code)) }
        if head.headers.contains(name: "Content-Range") {
            return .notEligible(reason: .partialContent)
        }

        let contentType = head.headers.first(name: "Content-Type")
        guard let contentType, isHTML(contentType) else {
            return .notEligible(reason: .notHTML(contentType))
        }

        // When the client says what it wants the resource for, believe it: HTML fetched
        // by script is data, not a page, and rewriting it corrupts whatever parses it.
        if let dest = secFetchDest?.lowercased(), !dest.isEmpty {
            guard dest == "document" || dest == "iframe" || dest == "frame" else {
                return .notEligible(reason: .notADocument(dest))
            }
        }

        if let encoding = head.headers.first(name: "Content-Encoding")?.lowercased() {
            let parts = encoding.split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            for part in parts where !decodableEncodings.contains(part) {
                return .notEligible(reason: .undecodableEncoding(part))
            }
        }

        return .eligible
    }

    static func isHTML(_ contentType: String) -> Bool {
        let type = contentType.split(separator: ";").first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
        return type == "text/html" || type == "application/xhtml+xml"
    }

    /// Narrows what the origin may send to what we can decode.
    ///
    /// Only zstd is dropped. An earlier version also dropped brotli, to avoid linking a
    /// C decompressor into a process that parses hostile input — but Apple's
    /// `Compression` framework implements brotli, so the reason evaporated. Measuring
    /// the cost of that assumption is what made it worth revisiting: on origins that do
    /// serve brotli it ran from +13% to +50% on the document, and +191% on one.
    public static func rewriteAcceptEncoding(_ headers: inout HTTPHeaders) {
        headers.replaceOrAdd(name: "Accept-Encoding", value: "gzip, deflate, br")
    }

    /// Charset declared by the response, if any, so the injected markup is written in
    /// the encoding the document actually uses.
    public static func charset(of head: HTTPResponseHead) -> String? {
        guard let contentType = head.headers.first(name: "Content-Type") else { return nil }
        for part in contentType.split(separator: ";").dropFirst() {
            let piece = part.trimmingCharacters(in: .whitespaces).lowercased()
            guard piece.hasPrefix("charset=") else { continue }
            return String(piece.dropFirst("charset=".count))
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        }
        return nil
    }
}
