import Foundation

/// Assembles the script injected into a page for the user scripts that match it.
///
/// Two things come free from running in a proxy rather than an extension, and both are
/// visible here. There is no isolated world, so `unsafeWindow` is simply `window` and
/// scripts that manipulate a page's own globals work without ceremony. And the payload
/// is placed ahead of the document's own scripts, so `@run-at document-start` means
/// what it says.
///
/// What is not free is `GM_xmlhttpRequest`, whose entire purpose is to bypass CORS.
/// That needs an endpoint on the proxy to perform the request natively, which does not
/// exist yet — so it reports instead of pretending, for the same reason an unknown
/// scriptlet is skipped rather than approximated.
public enum UserScriptRuntime {

    public struct Assembly: Sendable, Equatable {
        public let source: String
        /// Scripts whose `@grant` asks for something not yet provided.
        public let unsupportedGrants: [(script: String, grant: String)]

        public static func == (lhs: Assembly, rhs: Assembly) -> Bool {
            lhs.source == rhs.source
                && lhs.unsupportedGrants.map(\.script) == rhs.unsupportedGrants.map(\.script)
                && lhs.unsupportedGrants.map(\.grant) == rhs.unsupportedGrants.map(\.grant)
        }
    }

    /// Grants the shim implements.
    public static let supportedGrants: Set<String> = [
        "none", "unsafeWindow", "GM_addStyle", "GM_log", "GM_info",
        "GM_setValue", "GM_getValue", "GM_deleteValue", "GM_listValues",
        "GM_getResourceText", "GM_getResourceURL", "GM_openInTab",
    ]

    /// Builds the payload for a page, or `nil` when no script matches.
    ///
    /// - Parameter resolvedRequires: contents of `@require` URLs, already fetched and
    ///   cached. A script whose requirements are missing is skipped rather than run
    ///   half-initialised, which would fail in the page with an unattributable error.
    public static func assemble(
        scripts: [UserScript],
        resolvedRequires: [URL: String] = [:]
    ) -> Assembly? {
        var pieces: [String] = []
        var unsupported: [(script: String, grant: String)] = []

        for script in scripts {
            for grant in script.grants where !supportedGrants.contains(grant) {
                unsupported.append((script.name, grant))
            }

            let missing = script.requires.filter { resolvedRequires[$0] == nil }
            guard missing.isEmpty else { continue }

            let libraries = script.requires.compactMap { resolvedRequires[$0] }.joined(separator: "\n")
            let inner = libraries.isEmpty ? script.body : libraries + "\n" + script.body

            guard let identifier = try? JSONSerialization.data(
                withJSONObject: [script.id, script.name, script.version ?? ""]
            ), let identifierJSON = String(data: identifier, encoding: .utf8) else { continue }

            pieces.append("""
            __tamisRun(\(identifierJSON), "\(script.runAt.rawValue)", function (GM_info, unsafeWindow, GM_addStyle, GM_log, GM_setValue, GM_getValue, GM_deleteValue, GM_listValues, GM_openInTab, GM_xmlhttpRequest) {
            \(inner)
            });
            """)
        }

        guard !pieces.isEmpty || !unsupported.isEmpty else { return nil }
        guard !pieces.isEmpty else { return Assembly(source: "", unsupportedGrants: unsupported) }

        let source = shim + "\n" + pieces.joined(separator: "\n") + "\n})();"
        return Assembly(source: source, unsupportedGrants: unsupported)
    }

    static let shim = #"""
    (function () {
      "use strict";
      var STORAGE_PREFIX = "tamis.gm.";

      function makeAPI(id, name, version) {
        var prefix = STORAGE_PREFIX + id + ".";
        return {
          info: { script: { name: name, version: version }, scriptHandler: "Tamis" },
          addStyle: function (css) {
            var el = document.createElement("style");
            el.textContent = css;
            (document.head || document.documentElement).appendChild(el);
            return el;
          },
          log: function () { try { console.log.apply(console, arguments); } catch (e) {} },
          setValue: function (key, value) {
            try { localStorage.setItem(prefix + key, JSON.stringify(value)); } catch (e) {}
          },
          getValue: function (key, fallback) {
            try {
              var raw = localStorage.getItem(prefix + key);
              return raw === null ? fallback : JSON.parse(raw);
            } catch (e) { return fallback; }
          },
          deleteValue: function (key) {
            try { localStorage.removeItem(prefix + key); } catch (e) {}
          },
          listValues: function () {
            var keys = [];
            try {
              for (var i = 0; i < localStorage.length; i++) {
                var k = localStorage.key(i);
                if (k && k.indexOf(prefix) === 0) keys.push(k.slice(prefix.length));
              }
            } catch (e) {}
            return keys;
          },
          openInTab: function (url) { try { return window.open(url, "_blank"); } catch (e) { return null; } },
          // Its whole purpose is to bypass CORS, which needs the proxy to perform the
          // request natively. Reporting beats a fetch that will simply be refused.
          xmlhttpRequest: function (options) {
            var message = "GM_xmlhttpRequest is not available in this build of Tamis";
            try { console.warn("[Tamis] " + message); } catch (e) {}
            if (options && typeof options.onerror === "function") {
              options.onerror({ error: message });
            }
          }
        };
      }

      function __tamisRun(identity, runAt, body) {
        var api = makeAPI(identity[0], identity[1], identity[2]);
        var invoke = function () {
          try {
            body(api.info, window, api.addStyle, api.log, api.setValue, api.getValue,
                 api.deleteValue, api.listValues, api.openInTab, api.xmlhttpRequest);
          } catch (e) {
            // One broken script must cost that script alone. A user script that throws
            // where the page can see it is indistinguishable, to the user, from Tamis
            // breaking the site.
            try { console.error("[Tamis] " + identity[1] + ": " + e); } catch (ignored) {}
          }
        };

        if (runAt === "document-start") { invoke(); return; }
        if (document.readyState === "complete"
            || (runAt !== "document-idle" && document.readyState !== "loading")) {
          invoke(); return;
        }
        var event = runAt === "document-idle" ? "load" : "DOMContentLoaded";
        window.addEventListener(event, invoke, { once: true });
      }
    """#
}
