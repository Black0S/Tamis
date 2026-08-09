import Foundation

/// A `@-moz-document` scope: which pages a block of CSS applies to.
///
/// The four functions differ in ways that matter. `domain()` covers subdomains and
/// `url-prefix()` does not; `regexp()` must match the *entire* URL rather than appear
/// within it, which is the detail most reimplementations get wrong — an unanchored
/// pattern turns a style meant for one page into one that applies to a whole site.
public enum DocumentRule: Sendable, Equatable {
    case domain(String)
    case url(String)
    case urlPrefix(String)
    case regexp(String)

    public func matches(url: URL) -> Bool {
        let text = url.absoluteString
        switch self {
        case .domain(let domain):
            guard let host = url.host?.lowercased() else { return false }
            let target = domain.lowercased()
            if host == target { return true }
            // The dot matters: `notexample.com` is a different site.
            return host.hasSuffix(target)
                && host.count > target.count
                && host[host.index(host.endIndex, offsetBy: -target.count - 1)] == "."
        case .url(let exact):
            return text == exact
        case .urlPrefix(let prefix):
            return text.hasPrefix(prefix)
        case .regexp(let pattern):
            // Anchored on both ends, as Mozilla and Stylus define it.
            guard let expression = try? NSRegularExpression(pattern: "^(?:\(pattern))$") else {
                return false
            }
            let range = NSRange(text.startIndex..., in: text)
            return expression.firstMatch(in: text, options: [], range: range) != nil
        }
    }
}

/// A user style, in Stylus's UserCSS format or as plain CSS.
///
/// Shares the injection channel with cosmetic rules, and is emitted after them so a
/// style can override anything a filter list decided — which is the point of having
/// both.
public struct UserStyle: Sendable, Equatable, Identifiable {

    /// A `@var` declaration, so the app can offer a colour well or a slider instead of
    /// asking someone to edit CSS.
    public struct Variable: Sendable, Equatable {
        public let type: String
        public let name: String
        public let label: String
        public let defaultValue: String
    }

    /// One `@-moz-document` block, or the whole sheet when there is none.
    public struct Section: Sendable, Equatable {
        /// Empty means the section applies wherever the style itself does.
        public let rules: [DocumentRule]
        public let css: String

        public func matches(url: URL) -> Bool {
            rules.isEmpty || rules.contains { $0.matches(url: url) }
        }
    }

    public var id: String { name + "\u{1}" + (namespace ?? "") }

    public let name: String
    public let namespace: String?
    public let version: String?
    public let description: String?
    public let variables: [Variable]
    public let sections: [Section]
    /// Applications the user restricted this style to, empty meaning all of them.
    public let apps: [String]

    // MARK: Parsing

    public enum ParseError: Error, Sendable, Equatable {
        case noName
        case empty
    }

    /// Parses a `.user.css` file, or plain CSS.
    ///
    /// Plain CSS is accepted deliberately: a user writing three lines to hide something
    /// should not have to learn a metadata format first. Such a sheet has no scope of
    /// its own and is scoped in the app instead.
    public static func parse(_ source: String, fallbackName: String = "Untitled") throws -> UserStyle {
        let metadata = metadataBlock(in: source)
        var values: [String: [String]] = [:]
        var variables: [Variable] = []

        for line in metadata?.lines ?? [] {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("@") else { continue }
            let withoutAt = trimmed.dropFirst()
            let key = String(withoutAt.prefix { !$0.isWhitespace }).lowercased()
            let value = String(withoutAt.dropFirst(key.count)).trimmingCharacters(in: .whitespaces)

            if key == "var" || key == "advanced" {
                if let variable = parseVariable(value) { variables.append(variable) }
            } else {
                values[key, default: []].append(value)
            }
        }

        let body = metadata.map { String(source[$0.bodyStart...]) } ?? source
        let sections = parseSections(body)
        guard !sections.isEmpty else { throw ParseError.empty }

        let name = values["name"]?.first ?? (metadata == nil ? fallbackName : "")
        guard !name.isEmpty else { throw ParseError.noName }

        return UserStyle(
            name: name,
            namespace: values["namespace"]?.first,
            version: values["version"]?.first,
            description: values["description"]?.first,
            variables: variables,
            sections: sections,
            apps: values["app"] ?? []
        )
    }

    static func metadataBlock(in source: String) -> (lines: [Substring], bodyStart: String.Index)? {
        guard let open = source.range(of: "==UserStyle=="),
              let close = source.range(of: "==/UserStyle==", range: open.upperBound..<source.endIndex)
        else { return nil }
        let block = source[open.upperBound..<close.lowerBound]
        var start = close.upperBound
        // Step past the rest of the comment that carries the block.
        if let end = source.range(of: "*/", range: start..<source.endIndex) {
            start = end.upperBound
        }
        return (block.split(separator: "\n", omittingEmptySubsequences: true), start)
    }

    /// `@var color accent "Accent colour" #ff0000`
    static func parseVariable(_ text: String) -> Variable? {
        var rest = Substring(text)
        func take() -> String? {
            rest = rest.drop { $0.isWhitespace }
            guard let first = rest.first else { return nil }
            if first == "\"" || first == "'" {
                rest = rest.dropFirst()
                let value = rest.prefix { $0 != first }
                rest = rest.dropFirst(value.count)
                if rest.first == first { rest = rest.dropFirst() }
                return String(value)
            }
            let value = rest.prefix { !$0.isWhitespace }
            rest = rest.dropFirst(value.count)
            return value.isEmpty ? nil : String(value)
        }
        guard let type = take(), let name = take(), let label = take() else { return nil }
        let fallback = take() ?? ""
        return Variable(type: type, name: name, label: label, defaultValue: fallback)
    }

    /// Splits the sheet into `@-moz-document` sections, or returns it whole.
    static func parseSections(_ css: String) -> [Section] {
        var sections: [Section] = []
        var cursor = css.startIndex

        while let marker = css.range(of: "@-moz-document", range: cursor..<css.endIndex) {
            // Anything before the first block applies unconditionally.
            let preamble = String(css[cursor..<marker.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
            if !preamble.isEmpty { sections.append(Section(rules: [], css: preamble)) }

            guard let braceStart = css.range(of: "{", range: marker.upperBound..<css.endIndex),
                  let braceEnd = matchingBrace(in: css, openAt: braceStart.lowerBound)
            else { break }

            let condition = String(css[marker.upperBound..<braceStart.lowerBound])
            let body = String(css[css.index(after: braceStart.lowerBound)..<braceEnd])
            let rules = parseDocumentRules(condition)
            if !rules.isEmpty {
                sections.append(Section(
                    rules: rules,
                    css: body.trimmingCharacters(in: .whitespacesAndNewlines)
                ))
            }
            cursor = css.index(after: braceEnd)
        }

        let tail = String(css[cursor...]).trimmingCharacters(in: .whitespacesAndNewlines)
        if !tail.isEmpty { sections.append(Section(rules: [], css: tail)) }
        return sections
    }

    static func parseDocumentRules(_ condition: String) -> [DocumentRule] {
        var rules: [DocumentRule] = []
        var cursor = condition.startIndex

        while cursor < condition.endIndex {
            guard let open = condition.range(of: "(", range: cursor..<condition.endIndex),
                  let close = condition.range(of: ")", range: open.upperBound..<condition.endIndex)
            else { break }

            let function = String(condition[cursor..<open.lowerBound])
                .trimmingCharacters(in: CharacterSet(charactersIn: " ,\n\t"))
                .lowercased()
            let argument = String(condition[open.upperBound..<close.lowerBound])
                .trimmingCharacters(in: CharacterSet(charactersIn: " \"'\n\t"))

            if !argument.isEmpty {
                switch function {
                case "domain":     rules.append(.domain(argument))
                case "url":        rules.append(.url(argument))
                case "url-prefix": rules.append(.urlPrefix(argument))
                case "regexp":     rules.append(.regexp(argument))
                default:           break
                }
            }
            cursor = close.upperBound
        }
        return rules
    }

    static func matchingBrace(in text: String, openAt: String.Index) -> String.Index? {
        var depth = 0
        var index = openAt
        while index < text.endIndex {
            if text[index] == "{" { depth += 1 }
            if text[index] == "}" {
                depth -= 1
                if depth == 0 { return index }
            }
            index = text.index(after: index)
        }
        return nil
    }
}

// MARK: - Rendering

extension UserStyle {

    public func applies(toApp bundleID: String?) -> Bool {
        guard !apps.isEmpty else { return true }
        guard let bundleID else { return false }
        return apps.contains(bundleID)
    }

    /// The CSS this style contributes to a page, with variables resolved.
    ///
    /// - Parameter overrides: values the user chose in the app, by variable name.
    public func css(for url: URL, overrides: [String: String] = [:]) -> String? {
        let applicable = sections.filter { $0.matches(url: url) }
        guard !applicable.isEmpty else { return nil }

        var body = applicable.map(\.css).joined(separator: "\n")
        guard !variables.isEmpty else { return body.isEmpty ? nil : body }

        // Two spellings coexist in the wild: Stylus's own `/*[[name]]*/` placeholders,
        // and plain custom properties. Both are served, so a sheet written either way
        // works without the user knowing which era it came from.
        var declarations: [String] = []
        for variable in variables {
            let value = overrides[variable.name] ?? variable.defaultValue
            body = body.replacingOccurrences(of: "/*[[\(variable.name)]]*/", with: value)
            declarations.append("--\(variable.name): \(value);")
        }
        let prelude = ":root { " + declarations.joined(separator: " ") + " }"
        return body.isEmpty ? nil : prelude + "\n" + body
    }
}
