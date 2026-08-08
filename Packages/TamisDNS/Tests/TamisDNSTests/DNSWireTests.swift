import Testing
@testable import TamisDNS

/// Builds a minimal query datagram for `name`.
private func query(_ name: String, type: UInt16 = 1, id: UInt16 = 0x1234) -> [UInt8] {
    var out = DNSHeader(id: id, flags: 0x0100, questionCount: 1).bytes  // RD set
    out.append(contentsOf: DNSName.encode(name))
    out.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xFF), 0x00, 0x01])
    return out
}

@Suite("DNS wire format")
struct DNSWireTests {

    @Test("a well-formed query round-trips")
    func parseQuery() throws {
        let q = try DNSQuery(datagram: query("ads.doubleclick.net"))
        #expect(q.name == "ads.doubleclick.net")
        #expect(q.header.id == 0x1234)
        #expect(q.header.recursionDesired)
        #expect(!q.header.isResponse)
        #expect(q.question.recordType == .a)
    }

    @Test("names are lowercased, as DNS is case-insensitive")
    func caseInsensitive() throws {
        let q = try DNSQuery(datagram: query("Ads.DoubleClick.NET"))
        #expect(q.name == "ads.doubleclick.net")
    }

    @Test("AAAA queries are recognised")
    func aaaa() throws {
        let q = try DNSQuery(datagram: query("example.com", type: 28))
        #expect(q.question.recordType == .aaaa)
    }

    @Test("a truncated datagram is rejected, not guessed at")
    func truncated() {
        #expect(throws: DNSError.truncated) {
            try DNSQuery(datagram: [0x12, 0x34, 0x01])
        }
    }

    @Test("a response is not accepted as a query")
    func responseRejected() {
        var datagram = query("example.com")
        datagram[2] |= 0x80  // set QR
        #expect(throws: DNSError.notAQuery) {
            try DNSQuery(datagram: datagram)
        }
    }

    /// A crafted message can chain compression pointers to expand without bound, or
    /// loop forever. Pointers must go strictly backwards and be bounded in number.
    @Test("forward and looping compression pointers are refused")
    func compressionBombs() {
        // A pointer at offset 12 aiming at itself.
        var selfLoop = DNSHeader(id: 1, flags: 0, questionCount: 1).bytes
        selfLoop.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01])
        #expect(throws: DNSError.invalidPointer) {
            try DNSQuery(datagram: selfLoop)
        }

        // A pointer aiming forward.
        var forward = DNSHeader(id: 1, flags: 0, questionCount: 1).bytes
        forward.append(contentsOf: [0xC0, 0x20, 0x00, 0x01, 0x00, 0x01])
        #expect(throws: DNSError.invalidPointer) {
            try DNSQuery(datagram: forward)
        }
    }

    @Test("a refusal echoes the question and sets the expected flags")
    func refusal() throws {
        let q = try DNSQuery(datagram: query("blocked.example"))
        let response = DNSResponse.refusal(to: q, code: .nameError)

        let header = try DNSHeader(bytes: response)
        #expect(header.id == q.header.id)
        #expect(header.isResponse)
        #expect(header.questionCount == 1)
        #expect(header.answerCount == 0)
        #expect(header.flags & 0x000F == UInt16(DNSResponseCode.nameError.rawValue))
        #expect(header.flags & 0x0080 != 0)  // recursion available
        #expect(header.recursionDesired)     // mirrored from the query

        // The question section is copied byte for byte: some clients compare it, and
        // a name we lowercased would not round-trip if re-encoded.
        let echoed = Array(response[DNSHeader.byteCount...])
        let original = Array(q.raw[DNSHeader.byteCount..<q.question.endOffset])
        #expect(echoed == original)
    }
}
