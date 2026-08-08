import Foundation
import Testing
@testable import TamisDNS

@Suite("DoH providers")
struct DoHProviderTests {

    /// The invariant the whole DNS layer rests on. A hostname endpoint would need
    /// resolving, through mDNSResponder, back into the resolver that is waiting for
    /// this very answer — a deadlock that takes the machine's DNS down with it.
    @Test("every preset endpoint is an IP literal, never a hostname", arguments: DoHProvider.presets)
    func endpointsAreIPLiterals(provider: DoHProvider) throws {
        #expect(!provider.endpoints.isEmpty)
        for endpoint in provider.endpoints {
            let host = try #require(endpoint.host())
            let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            let isIPv4 = bare.split(separator: ".").count == 4
                && bare.allSatisfy { $0.isNumber || $0 == "." }
            let isIPv6 = bare.contains(":")
            #expect(isIPv4 || isIPv6, "\(provider.name): \(host) is not an IP literal")
        }
    }

    @Test("presets use HTTPS and the RFC 8484 path", arguments: DoHProvider.presets)
    func endpointShape(provider: DoHProvider) throws {
        for endpoint in provider.endpoints {
            #expect(endpoint.scheme == "https")
            #expect(endpoint.path == "/dns-query")
        }
    }

    @Test("IPv6 endpoints are bracketed so the URL parses")
    func ipv6Bracketing() throws {
        let v6 = DoHProvider.cloudflare.endpoints.filter { $0.absoluteString.contains("[") }
        #expect(!v6.isEmpty)
        #expect(v6.allSatisfy { $0.host() != nil })
    }
}

/// Live checks against the real resolvers. Skipped unless `TAMIS_LIVE_TESTS=1`, so CI
/// and offline builds stay deterministic — but they are the only way to confirm that
/// the IP-literal endpoints really do validate without a name lookup.
@Suite("DoH live", .enabled(if: ProcessInfo.processInfo.environment["TAMIS_LIVE_TESTS"] == "1"))
struct DoHLiveTests {

    private func query(_ name: String, type: UInt16 = 1) -> [UInt8] {
        var out = DNSHeader(id: 0x4242, flags: 0x0100, questionCount: 1).bytes
        out.append(contentsOf: DNSName.encode(name))
        out.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xFF), 0x00, 0x01])
        return out
    }

    @Test("a real query round-trips through each preset", arguments: DoHProvider.presets)
    func liveResolve(provider: DoHProvider) async throws {
        let client = DoHClient(provider: provider)
        let response = try await client.resolve(query: query("example.com"))

        let header = try DNSHeader(bytes: response)
        #expect(header.id == 0x4242)
        #expect(header.isResponse)
        #expect(header.answerCount >= 1, "\(provider.name) returned no answer")
    }

    @Test("failover moves past a dead endpoint and records why")
    func failover() async throws {
        let broken = DoHProvider(
            name: "test",
            endpoints: [
                URL(string: "https://192.0.2.1/dns-query")!,   // TEST-NET-1, black hole
                DoHProvider.quad9.endpoints[0],
            ],
            hostname: "example.invalid"
        )
        let client = DoHClient(provider: broken, timeout: 3)
        let response = try await client.resolve(query: query("example.com"))
        #expect(try DNSHeader(bytes: response).isResponse)

        // The recovery is recorded rather than swallowed, so the UI can say which
        // endpoint actually answered and why the preferred one did not.
        let diagnostics = await client.lastDiagnostics
        #expect(diagnostics.count == 1)
        #expect(diagnostics.first?.failure == .unreachable)
    }

    /// Interception of encrypted DNS looks exactly like this: the address answers, but
    /// its certificate does not validate. Observed on `1.1.1.1` from a real network
    /// while building this — it replies to ICMP in single-digit milliseconds and still
    /// fails TLS, while `1.0.0.1` is clean.
    @Test("a certificate failure is reported as interception, not as an outage")
    func tlsFailureIsDistinguished() async throws {
        // expired.badssl.com serves a deliberately invalid certificate.
        let intercepted = DoHProvider(
            name: "test",
            endpoints: [URL(string: "https://expired.badssl.com/dns-query")!],
            hostname: "expired.badssl.com"
        )
        let client = DoHClient(provider: intercepted, timeout: 5)
        await #expect(throws: DoHError.self) {
            _ = try await client.resolve(query: query("example.com"))
        }
        let diagnostics = await client.lastDiagnostics
        #expect(diagnostics.first?.failure == .tlsValidationFailed)
    }
}
