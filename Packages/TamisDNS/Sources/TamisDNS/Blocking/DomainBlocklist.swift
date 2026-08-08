import Foundation

/// A set of domain rules gathered from hosts files and AdGuard-style DNS lists.
///
/// Matching walks from the most specific label upwards, so the closest rule wins:
/// `@@||cdn.example.com^` beats `||example.com^` for `cdn.example.com`, which is the
/// only behaviour that makes exception entries usable.
public struct DomainBlocklist: Sendable {

    public enum Decision: Sendable, Equatable {
        case block(matched: String)
        case allow(matched: String)
        case noMatch
    }

    public struct Stats: Sendable, Equatable {
        public var lines = 0
        public var comments = 0
        public var blockEntries = 0
        public var allowEntries = 0
        /// Lines that parsed as something other than a plain domain rule — regex
        /// filters, cosmetic rules, hosts entries pointing at a real address.
        public var skipped = 0
    }

    private let blocked: Set<String>
    private let allowed: Set<String>
    public let stats: Stats

    public var count: Int { blocked.count + allowed.count }

    // MARK: Building

    public init(lines: [String]) {
        var blocked = Set<String>()
        var allowed = Set<String>()
        var stats = Stats()

        for line in lines {
            stats.lines += 1
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.hasPrefix("#") || trimmed.hasPrefix("!") {
                stats.comments += 1
                continue
            }

            switch Self.parse(trimmed) {
            case .block(let domain):
                blocked.insert(domain)
                stats.blockEntries += 1
            case .allow(let domain):
                allowed.insert(domain)
                stats.allowEntries += 1
            case .none:
                stats.skipped += 1
            }
        }

        self.blocked = blocked
        self.allowed = allowed
        self.stats = stats
    }

    public init(blocking domains: [String], allowing allowedDomains: [String] = []) {
        self.blocked = Set(domains.map { $0.lowercased() })
        self.allowed = Set(allowedDomains.map { $0.lowercased() })
        self.stats = Stats()
    }

    enum Entry {
        case block(String)
        case allow(String)
        case none
    }

    /// Recognises the three shapes that make up real DNS lists.
    static func parse(_ line: String) -> Entry {
        // Strip an inline comment, which hosts files use freely.
        let withoutComment = line.split(separator: "#", maxSplits: 1).first.map(String.init) ?? line
        let text = withoutComment.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return .none }

        // 1. AdGuard DNS syntax: ||domain^ and @@||domain^
        if text.hasPrefix("@@") {
            guard let domain = adguardDomain(text.dropFirst(2)) else { return .none }
            return .allow(domain)
        }
        if text.hasPrefix("||") {
            guard let domain = adguardDomain(Substring(text)) else { return .none }
            return .block(domain)
        }

        // 2. Hosts format: `0.0.0.0 domain` — only sinkhole addresses count. An entry
        //    pointing at a real address is a genuine host mapping, not a block.
        let fields = text.split(whereSeparator: \.isWhitespace)
        if fields.count >= 2 {
            let address = String(fields[0])
            guard address == "0.0.0.0" || address == "127.0.0.1" || address == "::"
                    || address == "::1" else { return .none }
            guard let domain = plainDomain(String(fields[1])) else { return .none }
            return .block(domain)
        }

        // 3. A bare domain on its own line.
        if fields.count == 1, let domain = plainDomain(String(fields[0])) {
            return .block(domain)
        }
        return .none
    }

    /// Modifiers that do not restrict *which requests* a rule covers, and are
    /// therefore safe to ignore at the DNS layer.
    ///
    /// Everything else — `$third-party`, `$app`, `$denyallow`, request types — narrows
    /// the rule using information DNS does not have. Honouring such a rule without its
    /// modifier would block far more than its author intended, so the rule is dropped
    /// instead. Same principle as the network engine, opposite direction of caution
    /// from simply "ignore what you don't know".
    static let harmlessModifiers: Set<String> = ["important"]

    /// Extracts the domain from `||domain^`, refusing anything carrying a narrowing
    /// modifier or a path — those are network rules, not DNS rules.
    static func adguardDomain(_ text: Substring) -> String? {
        guard text.hasPrefix("||") else { return nil }
        var body = text.dropFirst(2)

        if let caret = body.firstIndex(of: "^") {
            var rest = body[body.index(after: caret)...]
            body = body[..<caret]

            if rest.hasPrefix("$") {
                rest = rest.dropFirst()
                let names = rest.split(separator: ",").map {
                    $0.trimmingCharacters(in: .whitespaces).lowercased()
                }
                guard names.allSatisfy({ harmlessModifiers.contains($0) }) else { return nil }
            } else if !rest.isEmpty {
                return nil   // a path, a wildcard, anything else
            }
        }
        return plainDomain(String(body))
    }

    static func plainDomain(_ text: String) -> String? {
        let domain = text.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !domain.isEmpty, domain.count <= 253 else { return nil }
        // `localhost` and friends appear at the top of every hosts file and must not
        // become blocking rules.
        if domain == "localhost" || domain == "localhost.localdomain"
            || domain == "broadcasthost" || domain == "local" { return nil }
        guard !domain.contains("/"), !domain.contains("*"), !domain.contains(" ") else { return nil }
        guard domain.contains(".") else { return nil }
        return domain
    }

    // MARK: Matching

    /// The most specific rule covering `name`, walking up the label hierarchy.
    public func decision(for name: String) -> Decision {
        guard !blocked.isEmpty || !allowed.isEmpty else { return .noMatch }
        let host = name.lowercased()

        var start = host.startIndex
        while true {
            let candidate = String(host[start...])
            if allowed.contains(candidate) { return .allow(matched: candidate) }
            if blocked.contains(candidate) { return .block(matched: candidate) }
            guard let dot = host[start...].firstIndex(of: "."),
                  host.index(after: dot) < host.endIndex else { return .noMatch }
            start = host.index(after: dot)
        }
    }
}
