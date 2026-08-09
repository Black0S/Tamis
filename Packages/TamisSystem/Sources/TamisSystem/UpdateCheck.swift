import Foundation

/// Whether a newer release exists.
///
/// It checks and reports. It does not download, and it does not install — and that is
/// not a missing feature. Tamis is unsigned by design: with no Developer ID there is no
/// signature for an updater to verify, so an automatic update would mean fetching a
/// binary from the network and running it on the strength of a TLS certificate alone.
/// Software whose entire purpose is to sit in the middle of TLS should not be the
/// software that does that.
///
/// So the answer is a version, a date and a link. Building from source is the
/// distribution channel, and it is the one where the user can see what they are running.
public struct UpdateCheck: Sendable {

    public struct Release: Sendable, Equatable {
        public let version: String
        public let name: String
        public let notes: String
        public let publishedAt: Date?
        public let url: URL
    }

    public enum Outcome: Sendable, Equatable {
        case upToDate(current: String)
        case available(Release)
        /// Checking failed. Not an error worth interrupting anyone for: a machine that
        /// cannot reach GitHub is still filtering.
        case unavailable(String)
    }

    public let repository: String
    public let currentVersion: String

    public init(repository: String = "Black0S/Tamis", currentVersion: String? = nil) {
        self.repository = repository
        self.currentVersion = currentVersion
            ?? (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String)
            ?? "0.0.0"
    }

    public func run(session: URLSession? = nil) async -> Outcome {
        let session = session ?? Self.makeSession()
        var request = URLRequest(url: URL(string:
            "https://api.github.com/repos/\(repository)/releases/latest")!)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Tamis", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                return .unavailable("réponse inattendue")
            }
            // A repository with no release yet answers 404, which is not a failure.
            if http.statusCode == 404 { return .upToDate(current: currentVersion) }
            guard http.statusCode == 200 else {
                return .unavailable("GitHub a répondu \(http.statusCode)")
            }
            guard let release = Self.parse(data) else {
                return .unavailable("réponse illisible")
            }
            return Self.isNewer(release.version, than: currentVersion)
                ? .available(release)
                : .upToDate(current: currentVersion)
        } catch {
            return .unavailable(error.localizedDescription)
        }
    }

    static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        // Tamis's own traffic goes neither through its proxy nor through its filters.
        configuration.connectionProxyDictionary = [:]
        configuration.timeoutIntervalForRequest = 15
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: configuration)
    }

    static func parse(_ data: Data) -> Release? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = json["tag_name"] as? String,
              let address = json["html_url"] as? String,
              let url = URL(string: address)
        else { return nil }

        // A draft has no date and is not published; a prerelease is not what somebody
        // asked to be told about.
        if json["draft"] as? Bool == true || json["prerelease"] as? Bool == true {
            return nil
        }

        let formatter = ISO8601DateFormatter()
        return Release(
            version: tag,
            name: (json["name"] as? String) ?? tag,
            notes: (json["body"] as? String) ?? "",
            publishedAt: (json["published_at"] as? String).flatMap(formatter.date(from:)),
            url: url
        )
    }

    /// Compares two versions numerically, component by component.
    ///
    /// String comparison would call 0.10.0 older than 0.9.0, which is exactly the kind
    /// of mistake that stops an update being offered at the moment it matters most.
    /// A `v` prefix and any suffix after a dash are ignored: tags carry both, versions
    /// do not.
    static func isNewer(_ candidate: String, than current: String) -> Bool {
        let left = components(of: candidate), right = components(of: current)
        for index in 0..<max(left.count, right.count) {
            let a = index < left.count ? left[index] : 0
            let b = index < right.count ? right[index] : 0
            if a != b { return a > b }
        }
        return false
    }

    static func components(of version: String) -> [Int] {
        var text = version.trimmingCharacters(in: .whitespaces).lowercased()
        if text.hasPrefix("v") { text.removeFirst() }
        if let dash = text.firstIndex(of: "-") { text = String(text[..<dash]) }
        return text.split(separator: ".").map { Int($0.filter(\.isNumber)) ?? 0 }
    }
}
