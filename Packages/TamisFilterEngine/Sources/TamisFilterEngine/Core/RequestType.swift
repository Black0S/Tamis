import Foundation

/// The resource type of a single request, in Adblock Plus terms.
///
/// A browser extension gets this for free from the `webRequest` API. A proxy has to
/// reconstruct it — see ``RequestType/inferred(secFetchDest:accept:path:)``. This
/// reconstruction is the keystone of every type-based modifier (`$script`, `$image`,
/// `$third-party` combinations, …), so it is deliberately kept explicit and testable.
public enum RequestType: String, Sendable, Hashable, CaseIterable {
    case document
    case subdocument
    case script
    case stylesheet
    case image
    case font
    case media
    case object
    case xmlHTTPRequest
    case websocket
    case ping
    case other

    /// The single-member set containing this type.
    public var asSet: RequestTypeSet { RequestTypeSet(self) }
}

// MARK: - Rule-side type set

/// The set of resource types a rule applies to.
///
/// A rule with no type modifier applies to every type; that is represented by ``all``
/// rather than by an empty set, so matching is a plain intersection test.
public struct RequestTypeSet: OptionSet, Sendable, Hashable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let document       = RequestTypeSet(rawValue: 1 << 0)
    public static let subdocument    = RequestTypeSet(rawValue: 1 << 1)
    public static let script         = RequestTypeSet(rawValue: 1 << 2)
    public static let stylesheet     = RequestTypeSet(rawValue: 1 << 3)
    public static let image          = RequestTypeSet(rawValue: 1 << 4)
    public static let font           = RequestTypeSet(rawValue: 1 << 5)
    public static let media          = RequestTypeSet(rawValue: 1 << 6)
    public static let object         = RequestTypeSet(rawValue: 1 << 7)
    public static let xmlHTTPRequest = RequestTypeSet(rawValue: 1 << 8)
    public static let websocket      = RequestTypeSet(rawValue: 1 << 9)
    public static let ping           = RequestTypeSet(rawValue: 1 << 10)
    public static let other          = RequestTypeSet(rawValue: 1 << 11)

    public static let all: RequestTypeSet = RequestTypeSet(rawValue: 0x0FFF)

    /// Everything except `document`.
    ///
    /// ABP treats a bare rule as *not* applying to top-level navigation: blocking a
    /// page the user explicitly asked for is a different intent from blocking a
    /// subresource, and `$document` must be requested by name.
    public static let defaultForRules: RequestTypeSet = all.subtracting(.document)

    public init(_ type: RequestType) {
        switch type {
        case .document:       self = .document
        case .subdocument:    self = .subdocument
        case .script:         self = .script
        case .stylesheet:     self = .stylesheet
        case .image:          self = .image
        case .font:           self = .font
        case .media:          self = .media
        case .object:         self = .object
        case .xmlHTTPRequest: self = .xmlHTTPRequest
        case .websocket:      self = .websocket
        case .ping:           self = .ping
        case .other:          self = .other
        }
    }

    public func contains(_ type: RequestType) -> Bool {
        contains(RequestTypeSet(type))
    }

    /// Parses an ABP type modifier name, or returns `nil` if it is not a type.
    public static func named(_ name: String) -> RequestTypeSet? {
        switch name {
        case "document", "doc":            .document
        case "subdocument", "frame":       .subdocument
        case "script":                     .script
        case "stylesheet", "css":          .stylesheet
        case "image", "img":               .image
        case "font":                       .font
        case "media":                      .media
        case "object", "object-subrequest": .object
        case "xmlhttprequest", "xhr":      .xmlHTTPRequest
        case "websocket":                  .websocket
        case "ping", "beacon":             .ping
        case "other":                      .other
        default:                           nil
        }
    }
}

// MARK: - Reconstruction from HTTP

extension RequestType {
    /// Reconstructs the resource type from what a proxy can actually observe.
    ///
    /// `Sec-Fetch-Dest` is authoritative and is sent by every modern browser. The
    /// `Accept` header and the path extension are fallbacks for clients that omit it —
    /// chiefly non-browser applications, where classification is inherently degraded.
    public static func inferred(
        secFetchDest: String?,
        accept: String? = nil,
        path: String? = nil
    ) -> RequestType {
        if let dest = secFetchDest?.lowercased(), dest != "empty", !dest.isEmpty,
           let mapped = fromSecFetchDest(dest) {
            return mapped
        }

        // `Sec-Fetch-Dest: empty` is what fetch() and XHR report. It is a real answer,
        // not a missing one, so it takes precedence over the heuristics below.
        if secFetchDest?.lowercased() == "empty" { return .xmlHTTPRequest }

        if let accept, let mapped = fromAccept(accept.lowercased()) { return mapped }
        if let path, let mapped = fromPathExtension(path) { return mapped }
        return .other
    }

    private static func fromSecFetchDest(_ dest: String) -> RequestType? {
        switch dest {
        case "document":                      .document
        case "iframe", "frame", "embed":      .subdocument
        case "script", "serviceworker",
             "sharedworker", "worker",
             "audioworklet", "paintworklet",
             "xslt":                          .script
        case "style":                         .stylesheet
        case "image":                         .image
        case "font":                          .font
        case "audio", "video", "track":       .media
        case "object":                        .object
        case "report", "manifest":            .other
        default:                              nil
        }
    }

    private static func fromAccept(_ accept: String) -> RequestType? {
        // Only the leading media type is considered; `*/*` carries no information.
        let first = accept.split(separator: ",").first.map(String.init) ?? accept
        let raw = first.split(separator: ";").first.map(String.init) ?? first
        let type = raw.trimmingCharacters(in: .whitespaces)

        if type.hasPrefix("image/") { return .image }
        if type.hasPrefix("font/") { return .font }
        if type.hasPrefix("audio/") || type.hasPrefix("video/") { return .media }

        switch type {
        case "text/html", "application/xhtml+xml":      return .document
        case "text/css":                                return .stylesheet
        case "application/font-woff",
             "application/font-woff2":                  return .font
        case "application/javascript", "text/javascript",
             "application/ecmascript":                  return .script
        case "application/json":                        return .xmlHTTPRequest
        default:                                        return nil
        }
    }

    private static func fromPathExtension(_ path: String) -> RequestType? {
        // Stop at the query string; `?v=1.2` must not be read as an extension.
        let bare = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path
        guard let dot = bare.lastIndex(of: "."), dot != bare.index(before: bare.endIndex)
        else { return nil }
        let ext = bare[bare.index(after: dot)...].lowercased()

        switch ext {
        case "js", "mjs", "cjs":                                   return .script
        case "css":                                                return .stylesheet
        case "png", "jpg", "jpeg", "gif", "webp", "svg",
             "ico", "bmp", "avif", "apng":                         return .image
        case "woff", "woff2", "ttf", "otf", "eot":                 return .font
        case "mp4", "webm", "ogg", "ogv", "mp3", "m4a", "wav",
             "flac", "m3u8", "ts", "mpd":                          return .media
        case "swf":                                                return .object
        case "html", "htm", "xhtml":                               return .document
        case "json":                                               return .xmlHTTPRequest
        default:                                                   return nil
        }
    }
}
