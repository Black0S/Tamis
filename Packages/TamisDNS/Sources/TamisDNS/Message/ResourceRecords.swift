import Foundation

/// Walks the resource-record sections of a response far enough to cache it correctly.
///
/// Two things are needed and nothing more: the smallest TTL in the answer, which sets
/// how long the entry may live, and the byte offset of every TTL field, so they can be
/// decremented when the entry is served. The rest of the message is never interpreted
/// — it is relayed verbatim, so EDNS options, DNSSEC records and anything else we do
/// not model survive untouched.
public enum ResourceRecords {

    public struct Scan: Sendable, Equatable {
        /// Offsets of TTL fields that may be rewritten. Excludes `OPT`, whose TTL field
        /// is not a TTL at all.
        public var ttlOffsets: [Int] = []
        /// Smallest TTL across the answer section, or `nil` when there is no answer.
        public var minimumTTL: UInt32?
        /// TTL of the first `SOA` in the authority section, which is what bounds a
        /// negative answer (RFC 2308).
        public var soaTTL: UInt32?
    }

    /// Scans every record section of a response.
    public static func scan(_ bytes: [UInt8], questionEnd: Int, header: DNSHeader) throws -> Scan {
        var scan = Scan()
        var offset = questionEnd

        // Additional questions, if a client ever sends more than one.
        if header.questionCount > 1 {
            for _ in 1..<header.questionCount {
                let (_, next) = try DNSName.read(from: bytes, at: offset)
                offset = next + 4
                guard offset <= bytes.count else { throw DNSError.truncated }
            }
        }

        let sections: [(count: UInt16, isAnswer: Bool, isAuthority: Bool)] = [
            (header.answerCount, true, false),
            (header.authorityCount, false, true),
            (header.additionalCount, false, false),
        ]

        for section in sections {
            for _ in 0..<section.count {
                let (_, afterName) = try DNSName.read(from: bytes, at: offset)
                // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
                guard afterName + 10 <= bytes.count else { throw DNSError.truncated }

                let type = UInt16(bytes[afterName]) << 8 | UInt16(bytes[afterName + 1])
                let ttlOffset = afterName + 4
                let ttl = UInt32(bytes[ttlOffset]) << 24 | UInt32(bytes[ttlOffset + 1]) << 16
                        | UInt32(bytes[ttlOffset + 2]) << 8 | UInt32(bytes[ttlOffset + 3])
                let rdLength = Int(UInt16(bytes[afterName + 8]) << 8 | UInt16(bytes[afterName + 9]))

                // An OPT record stores extended flags and rcode where a TTL would be.
                // Decrementing it would corrupt EDNS for every cached answer.
                if type != DNSRecordType.opt.rawValue {
                    scan.ttlOffsets.append(ttlOffset)
                    if section.isAnswer {
                        scan.minimumTTL = min(scan.minimumTTL ?? ttl, ttl)
                    }
                    if section.isAuthority, type == DNSRecordType.soa.rawValue, scan.soaTTL == nil {
                        scan.soaTTL = ttl
                    }
                }

                offset = afterName + 10 + rdLength
                guard offset <= bytes.count else { throw DNSError.truncated }
            }
        }

        return scan
    }

    /// Writes a 32-bit value at `offset`, big-endian.
    static func writeUInt32(_ value: UInt32, into bytes: inout [UInt8], at offset: Int) {
        bytes[offset]     = UInt8(truncatingIfNeeded: value >> 24)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value)
    }
}
