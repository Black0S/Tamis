import Foundation

/// Computes the registrable domain (eTLD+1) of a host name, from the real list.
///
/// Which suffixes are public is a fact about registry policy, not about the shape of a
/// name: `a.co.uk` and `b.co.uk` are different sites, `a.uk` and `b.uk` are too, and no
/// rule about counting labels can tell those two cases apart. So it is looked up.
///
/// This is what decides first-party from third-party, which decides `$third-party` —
/// one of the most used modifiers in every list. A wrong answer here does not fail
/// loudly; it silently applies a rule to the wrong requests.
///
/// Rebuilt by `Scripts/update-public-suffix.py`, which also converts the 459 non-ASCII
/// rules to Punycode: a host name on the wire is always Punycode, so comparing the two
/// as written would never match.
public enum PublicSuffix {

    /// The algorithm from publicsuffix.org, whole:
    ///
    /// - a rule matches if its labels equal the domain's trailing labels, where `*`
    ///   matches any one label;
    /// - among matching rules the one with the most labels wins;
    /// - an exception rule (`!`) wins over any wildcard, and its public suffix is the
    ///   rule minus its leftmost label;
    /// - with no rule at all, the public suffix is the rightmost label.
    struct Rules: Sendable {
        /// Ordinary and exception rules, keyed by their text. Exceptions are stored
        /// without the `!`, flagged instead, because a lookup asks the same question of
        /// both and only the answer differs.
        let exact: Set<String>
        let exceptions: Set<String>
        /// Wildcard rules by the part after `*.`, so `*.ck` is found by looking up `ck`.
        let wildcards: Set<String>

        static func parse(_ text: some StringProtocol) -> Rules {
            var exact: Set<String> = []
            var exceptions: Set<String> = []
            var wildcards: Set<String> = []

            for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
                let rule = line.trimmingCharacters(in: .whitespaces)
                // The ICANN/private divider. Both sections apply: a page on
                // `a.github.io` is not first-party to one on `b.github.io`, and that is
                // exactly what the private section exists to record.
                if rule.isEmpty || rule.hasPrefix("%") { continue }

                if rule.hasPrefix("!") {
                    exceptions.insert(String(rule.dropFirst()))
                } else if rule.hasPrefix("*.") {
                    wildcards.insert(String(rule.dropFirst(2)))
                } else {
                    exact.insert(rule)
                }
            }
            return Rules(exact: exact, exceptions: exceptions, wildcards: wildcards)
        }

        /// The public suffix of `hostname`, or `nil` when the name is one.
        func publicSuffix(of hostname: String) -> String? {
            let labels = hostname.split(separator: ".", omittingEmptySubsequences: false)
            guard labels.count > 1 else { return hostname }

            // Walk from the longest candidate down, so the first hit is the prevailing
            // rule without having to compare label counts afterwards.
            for start in 0..<labels.count {
                let candidate = labels[start...].joined(separator: ".")

                // An exception cancels a wildcard: the suffix is the rule minus its
                // first label, so the name itself becomes registrable.
                if exceptions.contains(candidate) {
                    return labels[(start + 1)...].joined(separator: ".")
                }
                if exact.contains(candidate) { return candidate }

                // `*.ck` matches `foo.ck`, so the wildcard is keyed on what follows it
                // and the label in front is whatever is at `start`.
                if start > 0 {
                    let parent = labels[(start)...].joined(separator: ".")
                    if wildcards.contains(parent) {
                        return labels[(start - 1)...].joined(separator: ".")
                    }
                }
            }
            // No rule: the rightmost label, per the algorithm's implicit `*` rule.
            return labels.last.map(String.init)
        }
    }

    static let rules: Rules = {
        guard let url = Bundle.module.url(
                forResource: "public_suffix_list", withExtension: "txt",
                subdirectory: "Resources"
              ) ?? Bundle.module.url(forResource: "public_suffix_list", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8)
        else {
            // A build mistake, not a run-time condition. Loud, because the fallback
            // silently misclassifies every request instead of failing.
            assertionFailure("public_suffix_list.txt is missing from the bundle")
            return Rules(exact: [], exceptions: [], wildcards: [])
        }
        return Rules.parse(text)
    }()

    public static var ruleCount: Int {
        rules.exact.count + rules.exceptions.count + rules.wildcards.count
    }

    /// The registrable domain, or the host itself when it has none.
    ///
    /// A name that *is* a public suffix — `co.uk`, `github.io` — has no registrable
    /// domain. It is returned unchanged rather than as `nil`: the caller is deciding
    /// whether two hosts are the same site, and two requests to `co.uk` are still the
    /// same host as each other.
    public static func registrableDomain(of hostname: String) -> String {
        guard !hostname.isEmpty else { return "" }

        // IP literals have no registrable domain; they are their own identity.
        if hostname.hasPrefix("[") || isIPv4Literal(hostname) { return hostname }

        let host = hostname.hasSuffix(".") ? String(hostname.dropLast()) : hostname

        // An empty label makes the name invalid, and `.example.com` must not be read as
        // `example.com`: treating a malformed name as a well-formed one is how two
        // different things come to look like the same site.
        guard !host.split(separator: ".", omittingEmptySubsequences: false).contains(where: \.isEmpty)
        else { return host }

        guard let suffix = rules.publicSuffix(of: host) else { return host }
        guard suffix != host else { return host }

        let suffixLabels = suffix.split(separator: ".").count
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count > suffixLabels else { return host }
        return labels.suffix(suffixLabels + 1).joined(separator: ".")
    }

    static func isIPv4Literal(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.count <= 3 && part.allSatisfy(\.isNumber)
        }
    }
}
