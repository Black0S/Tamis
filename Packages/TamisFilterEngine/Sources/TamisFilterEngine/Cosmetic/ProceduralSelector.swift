import Foundation

/// A cosmetic selector a stylesheet cannot express, broken into steps the injected
/// runtime can execute.
///
/// Parsing here rather than in the page is deliberate. A malformed rule is rejected
/// before it reaches the browser, the runtime stays small because it never has to
/// parse anything, and the page is handed structured data instead of a string it would
/// have to interpret.
public struct ProceduralSelector: Sendable, Equatable {

    public enum Operation: Sendable, Equatable {
        /// `:has-text(needle)` — keep elements whose text contains the needle.
        case hasText(String)
        /// `:has-text(/regex/i)` — the same, by pattern.
        case hasTextPattern(pattern: String, flags: String)
        /// `:has(selector)` — keep elements with a matching descendant.
        case has(String)
        /// `:not(selector)` applied procedurally, for use after another step.
        case not(String)
        /// `:matches-css(prop: value)` — keep elements whose computed style matches.
        case matchesCSS(property: String, value: String)
        /// `:matches-attr(name=value)` — keep elements whose attribute matches.
        case matchesAttr(name: String, value: String?)
        /// `:min-text-length(n)`
        case minTextLength(Int)
        /// `:upward(n)` — move to the nth ancestor.
        case upwardDepth(Int)
        /// `:upward(selector)` — move to the closest matching ancestor.
        case upwardSelector(String)
        /// `:xpath(expr)` — replace the set with an XPath evaluation.
        case xpath(String)
        /// `:remove()` — delete rather than hide. Terminal.
        case remove
    }

    /// The plain CSS the runtime starts from. Empty means "every element".
    public let base: String
    public let operations: [Operation]
    public let raw: String

    /// Whether the last step deletes the element instead of hiding it.
    public var removesElement: Bool { operations.last == .remove }

    // MARK: Parsing

    /// Parses a selector, or returns `nil` when it uses something unsupported.
    ///
    /// Refusing is better than approximating: a selector we half-understand hides the
    /// wrong element, which reads to the user as a broken site rather than as a missing
    /// filter.
    public static func parse(_ selector: String) -> ProceduralSelector? {
        var base = ""
        var operations: [Operation] = []
        var index = selector.startIndex
        var seenOperation = false

        while index < selector.endIndex {
            guard let colon = selector[index...].firstIndex(of: ":") else {
                let tail = String(selector[index...])
                if seenOperation, !tail.trimmingCharacters(in: .whitespaces).isEmpty { return nil }
                base += tail
                break
            }

            let afterColon = selector.index(after: colon)
            guard let parenthesis = selector[afterColon...].firstIndex(of: "("),
                  let name = Optional(String(selector[afterColon..<parenthesis])),
                  isProceduralName(name)
            else {
                // A plain pseudo-class such as `:hover` belongs to the base selector.
                base += String(selector[index...colon])
                index = selector.index(after: colon)
                continue
            }

            base += String(selector[index..<colon])
            guard let closing = matchingParenthesis(in: selector, openAt: parenthesis) else { return nil }
            let argument = String(selector[selector.index(after: parenthesis)..<closing])

            guard let operation = makeOperation(name: name, argument: argument) else { return nil }
            operations.append(operation)
            seenOperation = true
            index = selector.index(after: closing)
        }

        guard !operations.isEmpty else { return nil }
        return ProceduralSelector(
            base: base.trimmingCharacters(in: .whitespaces),
            operations: operations,
            raw: selector
        )
    }

    static func isProceduralName(_ name: String) -> Bool {
        [
            "has", "has-text", "contains", "matches-css", "matches-attr",
            "min-text-length", "upward", "nth-ancestor", "xpath", "remove", "not",
        ].contains(name)
    }

    static func makeOperation(name: String, argument: String) -> Operation? {
        let argument = argument.trimmingCharacters(in: .whitespaces)
        switch name {
        case "has":
            return argument.isEmpty ? nil : .has(argument)
        case "not":
            return argument.isEmpty ? nil : .not(argument)
        case "has-text", "contains":
            if argument.hasPrefix("/"), let last = argument.lastIndex(of: "/"), last > argument.startIndex {
                let pattern = String(argument[argument.index(after: argument.startIndex)..<last])
                let flags = String(argument[argument.index(after: last)...])
                return pattern.isEmpty ? nil : .hasTextPattern(pattern: pattern, flags: flags)
            }
            return argument.isEmpty ? nil : .hasText(argument)
        case "matches-css":
            guard let colon = argument.firstIndex(of: ":") else { return nil }
            let property = String(argument[argument.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(argument[argument.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            return property.isEmpty ? nil : .matchesCSS(property: property, value: value)
        case "matches-attr":
            if let equals = argument.firstIndex(of: "=") {
                let name = String(argument[argument.startIndex..<equals])
                let value = String(argument[argument.index(after: equals)...])
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                return name.isEmpty ? nil : .matchesAttr(name: name, value: value)
            }
            return argument.isEmpty ? nil : .matchesAttr(name: argument, value: nil)
        case "min-text-length":
            guard let length = Int(argument), length >= 0 else { return nil }
            return .minTextLength(length)
        case "upward", "nth-ancestor":
            if let depth = Int(argument) {
                // uBO caps this; an unbounded walk would climb out of the document.
                guard depth > 0, depth <= 256 else { return nil }
                return .upwardDepth(depth)
            }
            return argument.isEmpty ? nil : .upwardSelector(argument)
        case "xpath":
            return argument.isEmpty ? nil : .xpath(argument)
        case "remove":
            return argument.isEmpty ? .remove : nil
        default:
            return nil
        }
    }

    /// Finds the parenthesis closing the one at `openAt`, respecting nesting.
    ///
    /// `:has(:not(.x))` is ordinary in real lists, and stopping at the first `)` would
    /// silently truncate the argument.
    static func matchingParenthesis(in text: String, openAt: String.Index) -> String.Index? {
        var depth = 0
        var index = openAt
        while index < text.endIndex {
            let character = text[index]
            if character == "(" { depth += 1 }
            if character == ")" {
                depth -= 1
                if depth == 0 { return index }
            }
            index = text.index(after: index)
        }
        return nil
    }
}

// MARK: - Wire format

extension ProceduralSelector {

    /// The compact form handed to the runtime.
    ///
    /// Arrays rather than objects: the payload goes into every page, and shorter is
    /// better when it is measured in kilobytes per page load.
    public func encoded() -> [Any] {
        var steps: [[Any]] = []
        for operation in operations {
            switch operation {
            case .hasText(let text):                    steps.append(["t", text])
            case .hasTextPattern(let pattern, let flags): steps.append(["r", pattern, flags])
            case .has(let selector):                    steps.append(["h", selector])
            case .not(let selector):                    steps.append(["n", selector])
            case .matchesCSS(let property, let value):  steps.append(["c", property, value])
            case .matchesAttr(let name, let value):     steps.append(["a", name, value ?? ""])
            case .minTextLength(let length):            steps.append(["l", length])
            case .upwardDepth(let depth):               steps.append(["u", depth])
            case .upwardSelector(let selector):         steps.append(["U", selector])
            case .xpath(let expression):                steps.append(["x", expression])
            case .remove:                               steps.append(["R"])
            }
        }
        return [base, steps]
    }
}
