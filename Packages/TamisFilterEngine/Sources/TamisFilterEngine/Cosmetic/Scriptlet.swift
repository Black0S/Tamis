import Foundation

/// A `##+js(name, arg…)` invocation, parsed into a name and its arguments.
///
/// Scriptlets are the answer to scripts that fight back: an advert loader that checks
/// whether its own object exists, a paywall that reads a flag, a page that counts how
/// many of its requests failed. Hiding elements does nothing against those; running a
/// few lines before the page's own code does.
///
/// Which is why the injection point matters. The payload lands immediately after
/// `<head>`, ahead of every script the document loads, so a property can be trapped
/// before anything reads it.
public struct Scriptlet: Sendable, Equatable {
    public let name: String
    public let arguments: [String]
    public let raw: String

    /// Parses `name, arg1, arg2`.
    ///
    /// Arguments may be quoted, and a comma inside quotes belongs to the argument
    /// rather than separating it — real rules pass regular expressions and JSON paths
    /// this way.
    public static func parse(_ body: String) -> Scriptlet? {
        let parts = splitArguments(body)
        guard let name = parts.first?.trimmingCharacters(in: .whitespaces), !name.isEmpty else {
            return nil
        }
        return Scriptlet(
            name: normalise(name),
            arguments: Array(parts.dropFirst()),
            raw: body
        )
    }

    /// Lists write the same scriptlet several ways; uBO's aliases and the `.js` suffix
    /// are both common.
    static func normalise(_ name: String) -> String {
        var name = name.lowercased()
        if name.hasSuffix(".js") { name = String(name.dropLast(3)) }
        switch name {
        case "aopr":  return "abort-on-property-read"
        case "aopw":  return "abort-on-property-write"
        case "acs", "abort-current-inline-script": return "abort-current-script"
        case "set":   return "set-constant"
        case "nostif", "no-settimeout-if": return "prevent-settimeout"
        case "nosiif", "no-setinterval-if": return "prevent-setinterval"
        case "ra":    return "remove-attr"
        case "rmnt":  return "remove-node-text"
        case "sls", "set-local-storage-item": return "set-local-storage-item"
        case "no-xhr-if", "prevent-xhr": return "prevent-xhr"
        case "rc":    return "remove-class"
        default:      return name
        }
    }

    static func splitArguments(_ body: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var quote: Character?
        var escaped = false

        for character in body {
            if escaped {
                current.append(character)
                escaped = false
                continue
            }
            if character == "\\" {
                escaped = true
                continue
            }
            if let active = quote {
                if character == active { quote = nil } else { current.append(character) }
                continue
            }
            if character == "'" || character == "\"" {
                quote = character
                continue
            }
            if character == "," {
                parts.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
                continue
            }
            current.append(character)
        }
        parts.append(current.trimmingCharacters(in: .whitespaces))
        return parts
    }
}
