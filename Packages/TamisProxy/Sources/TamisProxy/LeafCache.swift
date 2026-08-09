import Foundation
import NIOConcurrencyHelpers
import X509
import TamisTLS

/// Caches the certificates the proxy presents, keyed by connection target.
///
/// Issuing a leaf is cheap because the key pair is shared, but it is not free, and a
/// page load opens connections to dozens of hosts. More importantly the cache makes
/// certificates *stable*: a client that sees a different certificate for the same host
/// mid-session may treat it as an attack.
///
/// The entry lifetime is deliberately far shorter than the certificate's own validity.
/// If they matched, an entry could sit in the cache until the moment it expired and be
/// served with no time left, breaking the connection for no visible reason.
public final class LeafCache: Sendable {

    public struct Statistics: Sendable, Equatable {
        public var hits = 0
        public var misses = 0
        public var evictions = 0
    }

    /// Certificates live seven days; entries are refreshed daily.
    public static let entryLifetime: TimeInterval = 24 * 3600
    public static let defaultCapacity = 2_000

    private struct Entry {
        let certificate: Certificate
        let issuedAt: Date
        var lastUsed: Date
    }

    private struct State {
        var entries: [String: Entry] = [:]
        var statistics = Statistics()
    }

    private let issuer: LeafIssuer
    private let capacity: Int
    private let lifetime: TimeInterval
    private let state = NIOLockedValueBox(State())

    public init(
        issuer: LeafIssuer,
        capacity: Int = LeafCache.defaultCapacity,
        lifetime: TimeInterval = LeafCache.entryLifetime
    ) {
        self.issuer = issuer
        self.capacity = capacity
        self.lifetime = lifetime
    }

    public var statistics: Statistics {
        state.withLockedValue { $0.statistics }
    }

    public var count: Int {
        state.withLockedValue { $0.entries.count }
    }

    /// The certificate to present for `target`, minting one if needed.
    ///
    /// `target` is the host from `CONNECT host:port`. Using it rather than the SNI from
    /// the ClientHello is both simpler and sound: the CONNECT target *is* the host the
    /// client asked for, and it is the only thing available when there is no SNI at all
    /// — a connection opened straight to an address.
    public func certificate(for target: String, now: Date = Date()) throws -> Certificate {
        let key = target.lowercased()

        let cached = state.withLockedValue { state -> Certificate? in
            guard var entry = state.entries[key] else {
                state.statistics.misses += 1
                return nil
            }
            guard now.timeIntervalSince(entry.issuedAt) < lifetime else {
                state.entries.removeValue(forKey: key)
                state.statistics.misses += 1
                return nil
            }
            entry.lastUsed = now
            state.entries[key] = entry
            state.statistics.hits += 1
            return entry.certificate
        }
        if let cached { return cached }

        let certificate = try issuer.issue(for: target, now: now)
        state.withLockedValue { state in
            state.entries[key] = Entry(certificate: certificate, issuedAt: now, lastUsed: now)
            if state.entries.count > capacity {
                let excess = state.entries.count - (capacity - capacity / 10)
                let ordered = state.entries.sorted { $0.value.lastUsed < $1.value.lastUsed }
                for (key, _) in ordered.prefix(excess) {
                    state.entries.removeValue(forKey: key)
                    state.statistics.evictions += 1
                }
            }
        }
        return certificate
    }

    /// Drops everything, which is what a certificate authority renewal requires: every
    /// cached leaf was signed by the outgoing authority and would fail validation the
    /// moment it is removed from the trust store.
    public func removeAll() {
        state.withLockedValue { $0.entries.removeAll() }
    }
}
