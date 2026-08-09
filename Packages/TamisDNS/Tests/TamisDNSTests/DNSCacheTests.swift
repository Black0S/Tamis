import Foundation
import Testing
@testable import TamisDNS

// MARK: - Synthetic messages

private struct RR {
    var name: String
    var type: UInt16
    var ttl: UInt32
    var rdata: [UInt8]
    var klass: UInt16 = 1
}

private func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
private func be32(_ v: UInt32) -> [UInt8] {
    [UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
}

private func encode(_ rr: RR) -> [UInt8] {
    var out = DNSName.encode(rr.name)
    out += be16(rr.type) + be16(rr.klass) + be32(rr.ttl) + be16(UInt16(rr.rdata.count)) + rr.rdata
    return out
}

private func query(_ name: String, type: UInt16 = 1, id: UInt16 = 0x1111) -> [UInt8] {
    DNSHeader(id: id, flags: 0x0100, questionCount: 1).bytes
        + DNSName.encode(name) + be16(type) + be16(1)
}

private func response(
    _ name: String,
    id: UInt16 = 0x1111,
    type: UInt16 = 1,
    rcode: UInt8 = 0,
    answers: [RR] = [],
    authority: [RR] = [],
    additional: [RR] = []
) -> [UInt8] {
    let flags: UInt16 = 0x8180 | UInt16(rcode)
    var out = DNSHeader(
        id: id, flags: flags, questionCount: 1,
        answerCount: UInt16(answers.count),
        authorityCount: UInt16(authority.count),
        additionalCount: UInt16(additional.count)
    ).bytes
    out += DNSName.encode(name) + be16(type) + be16(1)
    for rr in answers + authority + additional { out += encode(rr) }
    return out
}

private func ttlValues(of message: [UInt8], questionEnd: Int) throws -> [UInt32] {
    let header = try DNSHeader(bytes: message)
    let scan = try ResourceRecords.scan(message, questionEnd: questionEnd, header: header)
    return scan.ttlOffsets.map { offset in
        UInt32(message[offset]) << 24 | UInt32(message[offset + 1]) << 16
            | UInt32(message[offset + 2]) << 8 | UInt32(message[offset + 3])
    }
}

// MARK: - Tests

@Suite("Resource record scanning")
struct ResourceRecordTests {

    @Test("the smallest answer TTL bounds the entry")
    func minimumTTL() throws {
        let message = response("example.com", answers: [
            RR(name: "example.com", type: 1, ttl: 300, rdata: [93, 184, 216, 34]),
            RR(name: "example.com", type: 1, ttl: 60, rdata: [93, 184, 216, 35]),
        ])
        let q = try DNSQuery(datagram: query("example.com"))
        let scan = try ResourceRecords.scan(
            message, questionEnd: q.question.endOffset, header: try DNSHeader(bytes: message)
        )
        #expect(scan.minimumTTL == 60)
        #expect(scan.ttlOffsets.count == 2)
    }

    /// An OPT record stores extended flags and rcode where a TTL would be. Rewriting
    /// it would corrupt EDNS on every answer served from cache.
    @Test("an OPT record's TTL field is left alone")
    func optIsExcluded() throws {
        let message = response("example.com",
            answers: [RR(name: "example.com", type: 1, ttl: 120, rdata: [1, 2, 3, 4])],
            additional: [RR(name: "", type: 41, ttl: 0x0000_8000, rdata: [])]
        )
        let q = try DNSQuery(datagram: query("example.com"))
        let scan = try ResourceRecords.scan(
            message, questionEnd: q.question.endOffset, header: try DNSHeader(bytes: message)
        )
        #expect(scan.ttlOffsets.count == 1)   // the A record only
        #expect(scan.minimumTTL == 120)
    }

    @Test("the SOA in the authority section bounds a negative answer")
    func soaTTL() throws {
        let message = response("nope.example", rcode: 3, authority: [
            RR(name: "example", type: 6, ttl: 900, rdata: Array(repeating: 0, count: 22))
        ])
        let q = try DNSQuery(datagram: query("nope.example"))
        let scan = try ResourceRecords.scan(
            message, questionEnd: q.question.endOffset, header: try DNSHeader(bytes: message)
        )
        #expect(scan.soaTTL == 900)
        #expect(scan.minimumTTL == nil)
    }
}

@Suite("DNS cache")
struct DNSCacheTests {

    @Test("a stored answer comes back")
    func hit() async throws {
        let cache = DNSCache()
        let q = try DNSQuery(datagram: query("example.com"))
        let r = response("example.com", answers: [
            RR(name: "example.com", type: 1, ttl: 300, rdata: [93, 184, 216, 34])
        ])
        #expect(await cache.store(query: q, response: r))
        #expect(await cache.lookup(q) != nil)
        #expect(await cache.statistics.hits == 1)
    }

    /// A cached datagram carries the identifier of the query that produced it.
    /// Replayed unchanged, every client discards it as unsolicited.
    @Test("the response ID is rewritten to the new query's")
    func idIsRewritten() async throws {
        let cache = DNSCache()
        let stored = try DNSQuery(datagram: query("example.com", id: 0xAAAA))
        await cache.store(query: stored, response: response("example.com", id: 0xAAAA, answers: [
            RR(name: "example.com", type: 1, ttl: 300, rdata: [1, 2, 3, 4])
        ]))

        let asked = try DNSQuery(datagram: query("example.com", id: 0xBBBB))
        let served = try #require(await cache.lookup(asked))
        #expect(try DNSHeader(bytes: served).id == 0xBBBB)
    }

    /// Serving the original TTLs restarts the clock in every downstream cache, so a
    /// 60-second record can survive for hours. Takes real time on purpose: this is the
    /// behaviour, not an implementation detail.
    @Test(.timeLimit(.minutes(1)))
    func ttlsAreDecrementedOnTheWayOut() async throws {
        let cache = DNSCache()
        let q = try DNSQuery(datagram: query("example.com"))
        await cache.store(query: q, response: response("example.com", answers: [
            RR(name: "example.com", type: 1, ttl: 300, rdata: [1, 2, 3, 4])
        ]))

        try await Task.sleep(for: .milliseconds(1100))
        let served = try #require(await cache.lookup(q))
        let ttls = try ttlValues(of: served, questionEnd: q.question.endOffset)
        #expect(ttls.count == 1)
        #expect(ttls[0] < 300, "TTL was served unchanged")
        #expect(ttls[0] >= 298, "TTL fell further than the elapsed time")
    }

    @Test("a zero TTL means do not cache")
    func zeroTTLNotCached() async throws {
        let cache = DNSCache()
        let q = try DNSQuery(datagram: query("example.com"))
        let stored = await cache.store(query: q, response: response("example.com", answers: [
            RR(name: "example.com", type: 1, ttl: 0, rdata: [1, 2, 3, 4])
        ]))
        #expect(!stored)
        #expect(await cache.lookup(q) == nil)
    }

    @Test("NXDOMAIN is cached, but capped harder than a positive answer")
    func negativeCaching() async throws {
        let cache = DNSCache()
        let q = try DNSQuery(datagram: query("nope.example"))
        let stored = await cache.store(query: q, response: response("nope.example", rcode: 3, authority: [
            RR(name: "example", type: 6, ttl: 86_400, rdata: Array(repeating: 0, count: 22))
        ]))
        #expect(stored)
        #expect(await cache.lookup(q) != nil)
        // A domain that starts existing must not stay invisible for a day.
        #expect(DNSCache.maxNegativeTTL == 300)
    }

    @Test("a server failure is never cached")
    func serverFailureNotCached() async throws {
        let cache = DNSCache()
        let q = try DNSQuery(datagram: query("example.com"))
        let stored = await cache.store(query: q, response: response("example.com", rcode: 2))
        #expect(!stored)
    }

    @Test("entries are keyed by type, so A and AAAA do not collide")
    func keyedByType() async throws {
        let cache = DNSCache()
        let a = try DNSQuery(datagram: query("example.com", type: 1))
        let aaaa = try DNSQuery(datagram: query("example.com", type: 28))
        await cache.store(query: a, response: response("example.com", type: 1, answers: [
            RR(name: "example.com", type: 1, ttl: 300, rdata: [1, 2, 3, 4])
        ]))
        #expect(await cache.lookup(a) != nil)
        #expect(await cache.lookup(aaaa) == nil)
    }

    @Test("the cache stays within capacity")
    func eviction() async throws {
        let cache = DNSCache(capacity: 50)
        for i in 0..<80 {
            let q = try DNSQuery(datagram: query("host\(i).example"))
            await cache.store(query: q, response: response("host\(i).example", answers: [
                RR(name: "host\(i).example", type: 1, ttl: 300, rdata: [1, 2, 3, 4])
            ]))
        }
        #expect(await cache.count <= 50)
        #expect(await cache.statistics.evictions > 0)
    }
}
