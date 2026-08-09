import Foundation
import JavaScriptCore

/// Checks that a script parses, before it is saved.
///
/// `new Function(source)` compiles the text as a function body and **does not run it**,
/// which is exactly the guarantee needed: a syntax error is caught at the moment the
/// user presses save, and nothing the script would do happens. JavaScriptCore is a
/// system framework, so this costs no dependency.
///
/// The source is handed over as a variable rather than interpolated into the script
/// being evaluated. Building JavaScript by string concatenation out of the very text
/// being validated would be a way to execute it by accident.
public enum ScriptValidator {

    public struct Problem: Sendable, Equatable {
        public let message: String
        /// 1-based, when JavaScriptCore reports one.
        public let line: Int?
    }

    public static func validate(_ source: String, kind: ScriptStore.Kind) -> Problem? {
        switch kind {
        case .script: validateJavaScript(source)
        case .style:  validateCSS(source)
        }
    }

    static func validateJavaScript(_ source: String) -> Problem? {
        guard let context = JSContext() else { return nil }
        var thrown: Problem?
        context.exceptionHandler = { _, exception in
            thrown = Problem(message: exception?.toString() ?? "erreur inconnue", line: nil)
        }
        context.setObject(source as NSString, forKeyedSubscript: "__tamisSource" as NSString)

        let result = context.evaluateScript("""
        (function () {
            try { new Function(__tamisSource); return null }
            catch (error) {
                return { message: String(error && error.message || error),
                         line: (error && error.line) || null }
            }
        })()
        """)

        if let thrown { return thrown }
        guard let result, !result.isNull, !result.isUndefined else { return nil }
        let message = result.objectForKeyedSubscript("message")?.toString() ?? "erreur de syntaxe"
        let lineValue = result.objectForKeyedSubscript("line")
        let line = (lineValue?.isNumber ?? false) ? Int(lineValue!.toInt32()) : nil
        return Problem(message: message, line: line)
    }

    /// Braces only.
    ///
    /// There is no CSS parser here and adding one would be a large dependency for a
    /// small return. An unbalanced brace is the mistake that actually happens when
    /// editing a stylesheet by hand, and it is the one that silently swallows every
    /// rule after it. Anything subtler is left to the browser, which is where CSS
    /// errors are recoverable by design.
    static func validateCSS(_ source: String) -> Problem? {
        var depth = 0
        var line = 1
        var inString: Character?
        var inComment = false
        var previous: Character = " "

        for character in source {
            if character == "\n" { line += 1 }

            if inComment {
                if previous == "*" && character == "/" { inComment = false }
                previous = character
                continue
            }
            if let quote = inString {
                if character == quote && previous != "\\" { inString = nil }
                previous = character
                continue
            }
            switch character {
            case "\"", "'":       inString = character
            case "*" where previous == "/": inComment = true
            case "{":             depth += 1
            case "}":
                depth -= 1
                if depth < 0 {
                    return Problem(message: "Accolade fermante en trop.", line: line)
                }
            default: break
            }
            previous = character
        }

        guard depth == 0 else {
            return Problem(
                message: depth == 1 ? "Une accolade n'est pas fermée."
                                    : "\(depth) accolades ne sont pas fermées.",
                line: nil
            )
        }
        return nil
    }
}
