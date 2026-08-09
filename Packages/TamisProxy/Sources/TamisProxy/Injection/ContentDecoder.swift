import Foundation
import Compression

/// Decodes compressed response bodies.
///
/// Every algorithm here comes from Apple's own `Compression` framework, so a filtering
/// proxy gains brotli support without linking a third-party C decompressor into a
/// process whose entire input is hostile. That was the reason to avoid brotli in the
/// first place; the framework removes the reason, and with it the bandwidth cost of
/// asking origins to fall back to gzip — measured at up to +50% on sites that serve
/// brotli, and +191% on one.
///
/// zstd is still not supported: the framework does not implement it, and no measured
/// origin chose it over brotli or gzip.
public struct ContentDecoder {

    public enum Encoding: String, Sendable, CaseIterable {
        case gzip
        case deflate
        case brotli = "br"
        case identity

        static func parse(_ header: String?) -> Encoding? {
            guard let header, !header.isEmpty else { return .identity }
            let name = header.split(separator: ",").first?
                .trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            switch name {
            case "gzip", "x-gzip": return .gzip
            case "deflate":        return .deflate
            case "br":             return .brotli
            case "identity", "":   return .identity
            default:               return nil
            }
        }

        var algorithm: compression_algorithm? {
            switch self {
            case .gzip, .deflate: COMPRESSION_ZLIB
            case .brotli:         COMPRESSION_BROTLI
            case .identity:       nil
            }
        }
    }

    public enum DecodeError: Error, Sendable, Equatable {
        case unsupported(String)
        case malformed
        /// The body expanded past the limit. A few kilobytes of gzip can become
        /// gigabytes, so an unbounded decoder is a denial of service with a
        /// Content-Encoding header.
        case tooLarge(limit: Int)
    }

    /// Decodes `body`, refusing to produce more than `limit` bytes.
    public static func decode(
        _ body: [UInt8],
        encoding: Encoding,
        limit: Int = ResponseEligibility.maximumBufferedBytes
    ) throws -> [UInt8] {
        guard let algorithm = encoding.algorithm else { return body }

        // Compression's ZLIB is raw deflate; gzip wraps it in a header and trailer that
        // have to come off first.
        let payload = encoding == .gzip ? try stripGzipWrapper(body) : body
        guard !payload.isEmpty else { return [] }

        var stream = compression_stream(
            dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!, dst_size: 0,
            src_ptr: UnsafePointer<UInt8>(bitPattern: 1)!, src_size: 0, state: nil
        )
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, algorithm)
                == COMPRESSION_STATUS_OK else {
            throw DecodeError.malformed
        }
        defer { compression_stream_destroy(&stream) }

        let chunkSize = 64 * 1024
        var output = [UInt8]()
        var scratch = [UInt8](repeating: 0, count: chunkSize)

        return try payload.withUnsafeBufferPointer { source -> [UInt8] in
            stream.src_ptr = source.baseAddress!
            stream.src_size = source.count

            while true {
                let status = try scratch.withUnsafeMutableBufferPointer { destination -> compression_status in
                    stream.dst_ptr = destination.baseAddress!
                    stream.dst_size = destination.count
                    let status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                    guard status != COMPRESSION_STATUS_ERROR else { throw DecodeError.malformed }
                    let produced = destination.count - stream.dst_size
                    if produced > 0 {
                        guard output.count + produced <= limit else {
                            throw DecodeError.tooLarge(limit: limit)
                        }
                        output.append(contentsOf: destination[0..<produced])
                    }
                    return status
                }
                if status == COMPRESSION_STATUS_END { break }
                if status == COMPRESSION_STATUS_OK, stream.src_size == 0, stream.dst_size > 0 { break }
            }
            return output
        }
    }

    /// Removes the RFC 1952 header and trailer around a deflate stream.
    static func stripGzipWrapper(_ body: [UInt8]) throws -> [UInt8] {
        guard body.count > 18, body[0] == 0x1F, body[1] == 0x8B, body[2] == 0x08 else {
            throw DecodeError.malformed
        }
        let flags = body[3]
        var index = 10

        if flags & 0x04 != 0 {                       // FEXTRA
            guard index + 2 <= body.count else { throw DecodeError.malformed }
            let length = Int(body[index]) | Int(body[index + 1]) << 8
            index += 2 + length
        }
        if flags & 0x08 != 0 {                       // FNAME
            while index < body.count, body[index] != 0 { index += 1 }
            index += 1
        }
        if flags & 0x10 != 0 {                       // FCOMMENT
            while index < body.count, body[index] != 0 { index += 1 }
            index += 1
        }
        if flags & 0x02 != 0 { index += 2 }          // FHCRC

        // The trailer is CRC32 + ISIZE, eight bytes.
        guard index < body.count - 8 else { throw DecodeError.malformed }
        return Array(body[index..<(body.count - 8)])
    }
}
