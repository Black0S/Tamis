import Foundation

// Minimal DNS wire-format support (RFC 1035, plus the pieces of RFC 6891 we must not
// break). Only what the resolver actually needs to *decide*: read a query, and build
// a refusal. Full response parsing is deliberately absent — upstream answers are
// relayed byte for byte rather than re-serialised, which is both faster and immune to
// whole classes of rewriting bugs.

public enum DNSError: Error, Sendable, Equatable {
    case truncated
    case malformedName
    /// A compression pointer that loops or points forward — a classic decompression
    /// bomb. Rejected rather than followed.
    case invalidPointer
    case notAQuery
    case noQuestion
}

// MARK: - Types

public enum DNSRecordType: UInt16, Sendable {
    case a = 1
    case ns = 2
    case cname = 5
    case soa = 6
    case ptr = 12
    case mx = 15
    case txt = 16
    case aaaa = 28
    case srv = 33
    case opt = 41
    case https = 65
    case any = 255
}

public enum DNSResponseCode: UInt8, Sendable {
    case noError = 0
    case formatError = 1
    case serverFailure = 2
    case nameError = 3   // NXDOMAIN
    case notImplemented = 4
    case refused = 5
}

// MARK: - Header

public struct DNSHeader: Sendable, Equatable {
    public static let byteCount = 12

    public var id: UInt16
    public var flags: UInt16
    public var questionCount: UInt16
    public var answerCount: UInt16
    public var authorityCount: UInt16
    public var additionalCount: UInt16

    public var isResponse: Bool { flags & 0x8000 != 0 }
    public var recursionDesired: Bool { flags & 0x0100 != 0 }
    public var opcode: UInt8 { UInt8((flags >> 11) & 0x0F) }

    public init(bytes: [UInt8]) throws {
        guard bytes.count >= Self.byteCount else { throw DNSError.truncated }
        func u16(_ i: Int) -> UInt16 { UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]) }
        self.id = u16(0)
        self.flags = u16(2)
        self.questionCount = u16(4)
        self.answerCount = u16(6)
        self.authorityCount = u16(8)
        self.additionalCount = u16(10)
    }

    public init(
        id: UInt16, flags: UInt16, questionCount: UInt16,
        answerCount: UInt16 = 0, authorityCount: UInt16 = 0, additionalCount: UInt16 = 0
    ) {
        self.id = id
        self.flags = flags
        self.questionCount = questionCount
        self.answerCount = answerCount
        self.authorityCount = authorityCount
        self.additionalCount = additionalCount
    }

    public var bytes: [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(Self.byteCount)
        for value in [id, flags, questionCount, answerCount, authorityCount, additionalCount] {
            out.append(UInt8(truncatingIfNeeded: value >> 8))
            out.append(UInt8(truncatingIfNeeded: value))
        }
        return out
    }
}

// MARK: - Question

public struct DNSQuestion: Sendable, Equatable {
    /// Lowercased, without a trailing dot.
    public let name: String
    public let type: UInt16
    public let klass: UInt16
    /// Offset just past the question in the original message, so the rest can be
    /// copied verbatim.
    public let endOffset: Int

    public var recordType: DNSRecordType? { DNSRecordType(rawValue: type) }
}

// MARK: - Query

/// A parsed DNS query — only as far as the first question, which is all a filtering
/// resolver needs to decide.
public struct DNSQuery: Sendable {
    public let header: DNSHeader
    public let question: DNSQuestion
    /// The original datagram, kept so a refusal can echo the question section back.
    public let raw: [UInt8]

    public var name: String { question.name }

    public init(datagram: [UInt8]) throws {
        let header = try DNSHeader(bytes: datagram)
        guard !header.isResponse else { throw DNSError.notAQuery }
        guard header.questionCount >= 1 else { throw DNSError.noQuestion }

        let (name, afterName) = try DNSName.read(from: datagram, at: DNSHeader.byteCount)
        guard afterName + 4 <= datagram.count else { throw DNSError.truncated }

        let type = UInt16(datagram[afterName]) << 8 | UInt16(datagram[afterName + 1])
        let klass = UInt16(datagram[afterName + 2]) << 8 | UInt16(datagram[afterName + 3])

        self.header = header
        self.question = DNSQuestion(name: name, type: type, klass: klass, endOffset: afterName + 4)
        self.raw = datagram
    }
}

// MARK: - Names

public enum DNSName {

    /// Maximum pointer jumps tolerated while decompressing.
    ///
    /// A crafted message can chain pointers to make a tiny datagram expand without
    /// bound, or loop forever. Bounding the jumps is the standard defence and costs
    /// nothing.
    static let maxJumps = 16

    /// Reads a (possibly compressed) name, returning it lowercased without a trailing
    /// dot, plus the offset just past the name *in the original stream* — which is not
    /// where parsing ended if a pointer was followed.
    public static func read(from bytes: [UInt8], at start: Int) throws -> (name: String, next: Int) {
        var labels: [String] = []
        var offset = start
        var jumps = 0
        var endOfName: Int?

        while true {
            guard offset < bytes.count else { throw DNSError.truncated }
            let length = bytes[offset]

            if length == 0 {
                if endOfName == nil { endOfName = offset + 1 }
                break
            }

            if length & 0xC0 == 0xC0 {
                guard offset + 1 < bytes.count else { throw DNSError.truncated }
                let pointer = Int(UInt16(length & 0x3F) << 8 | UInt16(bytes[offset + 1]))
                // Pointers must go strictly backwards; anything else is a bomb.
                guard pointer < offset else { throw DNSError.invalidPointer }
                jumps += 1
                guard jumps <= maxJumps else { throw DNSError.invalidPointer }
                if endOfName == nil { endOfName = offset + 2 }
                offset = pointer
                continue
            }

            guard length <= 63 else { throw DNSError.malformedName }
            let from = offset + 1
            let to = from + Int(length)
            guard to <= bytes.count else { throw DNSError.truncated }
            labels.append(String(decoding: bytes[from..<to], as: UTF8.self).lowercased())
            offset = to
        }

        guard let endOfName else { throw DNSError.malformedName }
        return (labels.joined(separator: "."), endOfName)
    }

    /// Encodes a name in wire format, uncompressed.
    public static func encode(_ name: String) -> [UInt8] {
        var out: [UInt8] = []
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(0)
        return out
    }
}

// MARK: - Responses

public enum DNSResponse {

    /// Builds a refusal echoing the query's question section.
    ///
    /// The question is copied verbatim from the original datagram rather than
    /// re-encoded: some clients compare the bytes, and re-serialising a name we
    /// lowercased would not round-trip.
    public static func refusal(to query: DNSQuery, code: DNSResponseCode) -> [UInt8] {
        var flags: UInt16 = 0x8000                       // QR: this is a response
        flags |= (UInt16(query.header.opcode) << 11)
        if query.header.recursionDesired { flags |= 0x0100 }
        flags |= 0x0080                                  // RA: recursion available
        flags |= UInt16(code.rawValue)

        let header = DNSHeader(id: query.header.id, flags: flags, questionCount: 1)
        var out = header.bytes
        out.append(contentsOf: query.raw[DNSHeader.byteCount..<query.question.endOffset])
        return out
    }
}
