import Foundation

/// A TTL-respecting cache of upstream answers.
///
/// Two details separate a correct cache from one that quietly serves stale data:
///
/// - **The response ID is rewritten** to the new query's. A cached datagram carries
///   the identifier of the query that produced it; replaying it unchanged makes every
///   client discard the answer as unsolicited.
/// - **TTLs are decremented on the way out.** Serving the original values restarts the
///   clock in every downstream cache, so a 60-second record can survive for hours.
///
/// Eviction happens on write rather than on a timer, in keeping with the project's
/// no-polling rule: an idle machine must cost nothing.
public actor DNSCache {

    public struct Statistics: Sendable, Equatable {
        public var hits = 0
        public var misses = 0
        public var insertions = 0
        public var evictions = 0
        public var expirations = 0

        public var hitRate: Double {
            let total = hits + misses
            return total == 0 ? 0 : Double(hits) / Double(total)
        }
    }

    struct Key: Hashable, Sendable {
        let name: String
        let type: UInt16
        let klass: UInt16
    }

    struct Entry: Sendable {
        var response: [UInt8]
        var ttlOffsets: [Int]
        var storedAt: ContinuousClock.Instant
        var lifetime: Duration
        /// Original TTL values, so each service can compute the remaining time from
        /// the source rather than from the previous rewrite.
        var originalTTLs: [UInt32]
        var lastUsed: ContinuousClock.Instant
    }

    /// Upper bound on how long anything is kept, however generous the upstream TTL.
    /// A record pinned for a day would outlive most of the reasons it was correct.
    public static let maxTTL: UInt32 = 86_400
    /// Negative answers are capped much harder: a domain that starts existing should
    /// not stay invisible for long (RFC 2308 recommends this bound).
    public static let maxNegativeTTL: UInt32 = 300

    private let capacity: Int
    private let clock = ContinuousClock()
    private var entries: [Key: Entry] = [:]
    public private(set) var statistics = Statistics()

    public init(capacity: Int = 10_000) {
        self.capacity = capacity
    }

    public var count: Int { entries.count }

    // MARK: Lookup

    /// A cached response for `query`, with its ID and TTLs brought up to date.
    public func lookup(_ query: DNSQuery) -> [UInt8]? {
        let key = Key(name: query.name, type: query.question.type, klass: query.question.klass)
        guard var entry = entries[key] else {
            statistics.misses += 1
            return nil
        }

        let age = clock.now - entry.storedAt
        guard age < entry.lifetime else {
            entries.removeValue(forKey: key)
            statistics.expirations += 1
            statistics.misses += 1
            return nil
        }

        entry.lastUsed = clock.now
        entries[key] = entry
        statistics.hits += 1

        var response = entry.response
        // The cached datagram answers a different query; without this every client
        // treats it as unsolicited and drops it.
        response[0] = UInt8(truncatingIfNeeded: query.header.id >> 8)
        response[1] = UInt8(truncatingIfNeeded: query.header.id)

        let elapsed = UInt32(max(0, age.components.seconds))
        for (index, offset) in entry.ttlOffsets.enumerated() {
            let original = entry.originalTTLs[index]
            let remaining = original > elapsed ? original - elapsed : 0
            ResourceRecords.writeUInt32(remaining, into: &response, at: offset)
        }
        return response
    }

    // MARK: Storage

    /// Caches `response` if it is cacheable, returning whether it was kept.
    ///
    /// Refused: anything but a definitive answer, and any answer whose TTL is zero —
    /// upstreams use that to say "do not cache this".
    @discardableResult
    public func store(query: DNSQuery, response: [UInt8]) -> Bool {
        guard let header = try? DNSHeader(bytes: response), header.isResponse else { return false }

        let rcode = UInt8(header.flags & 0x000F)
        guard rcode == DNSResponseCode.noError.rawValue
                || rcode == DNSResponseCode.nameError.rawValue else { return false }

        guard let scan = try? ResourceRecords.scan(
            response, questionEnd: query.question.endOffset, header: header
        ) else { return false }

        let ttl: UInt32
        if rcode == DNSResponseCode.nameError.rawValue || header.answerCount == 0 {
            guard let soa = scan.soaTTL else { return false }
            ttl = min(soa, Self.maxNegativeTTL)
        } else {
            guard let minimum = scan.minimumTTL else { return false }
            ttl = min(minimum, Self.maxTTL)
        }
        guard ttl > 0 else { return false }

        let originals = scan.ttlOffsets.map { offset -> UInt32 in
            UInt32(response[offset]) << 24 | UInt32(response[offset + 1]) << 16
                | UInt32(response[offset + 2]) << 8 | UInt32(response[offset + 3])
        }

        let key = Key(name: query.name, type: query.question.type, klass: query.question.klass)
        entries[key] = Entry(
            response: response,
            ttlOffsets: scan.ttlOffsets,
            storedAt: clock.now,
            lifetime: .seconds(Int64(ttl)),
            originalTTLs: originals,
            lastUsed: clock.now
        )
        statistics.insertions += 1

        if entries.count > capacity { evict() }
        return true
    }

    /// Drops expired entries first — they cost nothing to lose — and only then the
    /// least recently used, until the cache is back within a tenth of capacity.
    private func evict() {
        let now = clock.now
        for (key, entry) in entries where now - entry.storedAt >= entry.lifetime {
            entries.removeValue(forKey: key)
            statistics.expirations += 1
        }
        guard entries.count > capacity else { return }

        let target = capacity - capacity / 10
        let ordered = entries.sorted { $0.value.lastUsed < $1.value.lastUsed }
        for (key, _) in ordered.prefix(entries.count - target) {
            entries.removeValue(forKey: key)
            statistics.evictions += 1
        }
    }

    public func removeAll() {
        entries.removeAll()
    }
}
