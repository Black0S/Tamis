import Foundation
import TamisFilterEngine

/// Implementations for the `##+js()` scriptlets a page may need.
///
/// uBlock Origin ships around two hundred of these; this is the subset that appears in
/// the lists Tamis loads, written rather than imported so the code in the security
/// boundary is code that was read. Unknown names are dropped: running an approximation
/// of a scriptlet is how a page breaks in a way nobody can attribute.
///
/// Every implementation is wrapped by the caller, so one that throws costs its own rule
/// and nothing else.
public enum ScriptletLibrary {

    /// Scriptlets that can be honoured. Anything else is reported and skipped.
    public static var supported: Set<String> { Set(implementations.keys) }

    /// Builds the script for a page's scriptlets, or `nil` when none are supported.
    public static func script(for scriptlets: [Scriptlet]) -> (source: String, skipped: [String])? {
        var bodies: [String] = []
        var skipped: [String] = []

        for scriptlet in scriptlets {
            guard let implementation = implementations[scriptlet.name] else {
                skipped.append(scriptlet.name)
                continue
            }
            guard let arguments = try? JSONSerialization.data(withJSONObject: scriptlet.arguments),
                  let json = String(data: arguments, encoding: .utf8) else { continue }
            bodies.append("""
            try { (function (args) { \(implementation) })(\(json)); } catch (e) {}
            """)
        }

        guard !bodies.isEmpty else { return skipped.isEmpty ? nil : ("", skipped) }
        return ("(function () { \"use strict\";\n" + bodies.joined(separator: "\n") + "\n})();", skipped)
    }

    /// Each body receives `args`, the scriptlet's arguments as an array of strings.
    static let implementations: [String: String] = [

        // Trapping a property before the page reads it is only possible because the
        // payload is injected ahead of every script the document loads.
        "abort-on-property-read": #"""
        var chain = args[0]; if (!chain) return;
        var thrower = function () { throw new ReferenceError(Math.random().toString(36).slice(2)); };
        var install = function (owner, path) {
          var dot = path.indexOf(".");
          if (dot === -1) {
            Object.defineProperty(owner, path, { get: thrower, set: function () {} });
            return;
          }
          var head = path.slice(0, dot), rest = path.slice(dot + 1);
          var value = owner[head];
          if (value instanceof Object || (typeof value === "object" && value !== null)) {
            install(value, rest); return;
          }
          var stored = value;
          Object.defineProperty(owner, head, {
            get: function () { return stored; },
            set: function (v) { stored = v; if (v instanceof Object) install(v, rest); }
          });
        };
        install(window, chain);
        """#,

        "abort-on-property-write": #"""
        var chain = args[0]; if (!chain) return;
        var thrower = function () { throw new ReferenceError(Math.random().toString(36).slice(2)); };
        var dot = chain.lastIndexOf(".");
        var owner = window, name = chain;
        if (dot !== -1) {
          var parts = chain.slice(0, dot).split(".");
          for (var i = 0; i < parts.length && owner; i++) owner = owner[parts[i]];
          name = chain.slice(dot + 1);
        }
        if (!owner) return;
        Object.defineProperty(owner, name, { get: function () { return undefined; }, set: thrower });
        """#,

        // Pins a value the page would otherwise set, which is how most "is an ad
        // blocker present" flags are neutralised.
        "set-constant": #"""
        var chain = args[0], raw = args[1];
        if (!chain) return;
        var value;
        if (raw === "true") value = true;
        else if (raw === "false") value = false;
        else if (raw === "null") value = null;
        else if (raw === "undefined") value = undefined;
        else if (raw === "noopFunc") value = function () {};
        else if (raw === "trueFunc") value = function () { return true; };
        else if (raw === "falseFunc") value = function () { return false; };
        else if (raw === "emptyArr") value = [];
        else if (raw === "emptyObj") value = {};
        else if (raw === "''") value = "";
        else if (/^-?\d+(\.\d+)?$/.test(raw)) value = Number(raw);
        else value = raw;

        var parts = chain.split("."), owner = window;
        for (var i = 0; i < parts.length - 1; i++) {
          if (owner[parts[i]] === undefined || owner[parts[i]] === null) owner[parts[i]] = {};
          owner = owner[parts[i]];
        }
        Object.defineProperty(owner, parts[parts.length - 1], {
          get: function () { return value; },
          set: function () {},
          configurable: false
        });
        """#,

        // Timers are how anti-adblock scripts re-check after the page settles.
        "prevent-settimeout": #"""
        var needle = args[0] || "";
        var negated = needle.charAt(0) === "!";
        if (negated) needle = needle.slice(1);
        var test = needle === "" ? function () { return true; } : function (source) {
          if (needle.charAt(0) === "/" && needle.lastIndexOf("/") > 0) {
            var end = needle.lastIndexOf("/");
            try { return new RegExp(needle.slice(1, end), needle.slice(end + 1)).test(source); }
            catch (e) { return false; }
          }
          return source.indexOf(needle) !== -1;
        };
        var original = window.setTimeout;
        window.setTimeout = function (handler, delay) {
          var source = typeof handler === "function" ? handler.toString() : String(handler);
          var matched = test(source);
          if (negated ? !matched : matched) return 0;
          return original.apply(window, arguments);
        };
        """#,

        "prevent-setinterval": #"""
        var needle = args[0] || "";
        var negated = needle.charAt(0) === "!";
        if (negated) needle = needle.slice(1);
        var test = needle === "" ? function () { return true; } : function (source) {
          return source.indexOf(needle) !== -1;
        };
        var original = window.setInterval;
        window.setInterval = function (handler) {
          var source = typeof handler === "function" ? handler.toString() : String(handler);
          var matched = test(source);
          if (negated ? !matched : matched) return 0;
          return original.apply(window, arguments);
        };
        """#,

        "remove-attr": #"""
        var attributes = (args[0] || "").split("|"), selector = args[1] || "*";
        var run = function () {
          var nodes;
          try { nodes = document.querySelectorAll(selector); } catch (e) { return; }
          for (var i = 0; i < nodes.length; i++) {
            for (var a = 0; a < attributes.length; a++) nodes[i].removeAttribute(attributes[a]);
          }
        };
        run();
        try {
          new MutationObserver(run).observe(document.documentElement, {
            childList: true, subtree: true, attributes: true
          });
        } catch (e) {}
        """#,

        "remove-class": #"""
        var classes = (args[0] || "").split("|"), selector = args[1] || "*";
        var run = function () {
          var nodes;
          try { nodes = document.querySelectorAll(selector); } catch (e) { return; }
          for (var i = 0; i < nodes.length; i++) {
            for (var c = 0; c < classes.length; c++) nodes[i].classList.remove(classes[c]);
          }
        };
        run();
        try {
          new MutationObserver(run).observe(document.documentElement, {
            childList: true, subtree: true, attributes: true
          });
        } catch (e) {}
        """#,

        // Some pages route their telemetry through WebRTC, which no proxy can see.
        "nowebrtc": #"""
        var Original = window.RTCPeerConnection || window.webkitRTCPeerConnection;
        if (!Original) return;
        var Blocked = function () { throw new Error("RTCPeerConnection blocked"); };
        Blocked.prototype = Original.prototype;
        window.RTCPeerConnection = Blocked;
        window.webkitRTCPeerConnection = Blocked;
        """#,

        // The most-used scriptlet in real lists after set-constant: it throws only when
        // the property is read from a script whose source matches, so the page's own
        // code keeps working while the advert loader does not.
        "abort-current-script": #"""
        var chain = args[0], needle = args[1] || "";
        if (!chain) return;
        var matches = function (source) {
          if (needle === "") return true;
          if (needle.charAt(0) === "/" && needle.lastIndexOf("/") > 0) {
            var end = needle.lastIndexOf("/");
            try { return new RegExp(needle.slice(1, end), needle.slice(end + 1)).test(source); }
            catch (e) { return false; }
          }
          return source.indexOf(needle) !== -1;
        };
        var parts = chain.split("."), owner = window;
        for (var i = 0; i < parts.length - 1 && owner; i++) owner = owner[parts[i]];
        if (!owner) return;
        var name = parts[parts.length - 1];
        var stored = owner[name];
        Object.defineProperty(owner, name, {
          get: function () {
            var script = document.currentScript;
            if (script && matches(script.textContent || script.src || "")) {
              throw new ReferenceError(Math.random().toString(36).slice(2));
            }
            return stored;
          },
          set: function (v) { stored = v; }
        });
        """#,

        "set-local-storage-item": #"""
        var key = args[0], raw = args[1];
        if (!key) return;
        var value = raw;
        if (raw === "$remove$") { try { localStorage.removeItem(key); } catch (e) {} return; }
        if (raw === "true" || raw === "false" || raw === "null" || raw === "undefined") value = raw;
        else if (raw === "emptyArr") value = "[]";
        else if (raw === "emptyObj") value = "{}";
        try { localStorage.setItem(key, value); } catch (e) {}
        """#,

        // Some paywalls and anti-adblock notices are plain text nodes with no class or
        // id, which nothing in a stylesheet can reach.
        "remove-node-text": #"""
        var tag = (args[0] || "").toLowerCase(), needle = args[1] || "";
        if (!tag || !needle) return;
        var matches = function (text) {
          if (needle.charAt(0) === "/" && needle.lastIndexOf("/") > 0) {
            var end = needle.lastIndexOf("/");
            try { return new RegExp(needle.slice(1, end), needle.slice(end + 1)).test(text); }
            catch (e) { return false; }
          }
          return text.indexOf(needle) !== -1;
        };
        var run = function () {
          var nodes = document.getElementsByTagName(tag);
          for (var i = nodes.length - 1; i >= 0; i--) {
            if (matches(nodes[i].textContent || "")) nodes[i].textContent = "";
          }
        };
        run();
        try {
          new MutationObserver(run).observe(document.documentElement, {
            childList: true, subtree: true
          });
        } catch (e) {}
        """#,

        "prevent-xhr": #"""
        var needle = args[0] || "";
        var Original = window.XMLHttpRequest;
        if (!Original) return;
        var shouldBlock = function (url) {
          if (needle === "" || needle === "*") return true;
          return String(url).indexOf(needle) !== -1;
        };
        window.XMLHttpRequest = function () {
          var request = new Original();
          var blocked = false;
          var open = request.open;
          request.open = function (method, url) {
            blocked = shouldBlock(url);
            return open.apply(request, arguments);
          };
          var send = request.send;
          request.send = function () {
            if (!blocked) return send.apply(request, arguments);
            // Answer as an empty success rather than an error: a page that sees a
            // failed request often retries forever or reports it as broken.
            Object.defineProperty(request, "readyState", { get: function () { return 4; } });
            Object.defineProperty(request, "status", { get: function () { return 200; } });
            Object.defineProperty(request, "responseText", { get: function () { return ""; } });
            Object.defineProperty(request, "response", { get: function () { return ""; } });
            setTimeout(function () {
              if (typeof request.onreadystatechange === "function") request.onreadystatechange();
              if (typeof request.onload === "function") request.onload();
            }, 1);
          };
          return request;
        };
        window.XMLHttpRequest.prototype = Original.prototype;
        """#,

        // Some scripts only misbehave when called from a particular place; this throws
        // on the read only when the call stack matches, leaving the page's own use of
        // the same property working.
        "abort-on-stack-trace": #"""
        var chain = args[0], needle = args[1] || "";
        if (!chain) return;
        var matches = function (stack) {
          if (needle === "") return true;
          if (needle.charAt(0) === "/" && needle.lastIndexOf("/") > 0) {
            var end = needle.lastIndexOf("/");
            try { return new RegExp(needle.slice(1, end), needle.slice(end + 1)).test(stack); }
            catch (e) { return false; }
          }
          return stack.indexOf(needle) !== -1;
        };
        var parts = chain.split("."), owner = window;
        for (var i = 0; i < parts.length - 1 && owner; i++) owner = owner[parts[i]];
        if (!owner) return;
        var name = parts[parts.length - 1];
        var stored = owner[name];
        try {
          Object.defineProperty(owner, name, {
            get: function () {
              var stack = "";
              try { throw new Error(); } catch (e) { stack = e.stack || ""; }
              if (matches(stack)) throw new ReferenceError(Math.random().toString(36).slice(2));
              return stored;
            },
            set: function (v) { stored = v; }
          });
        } catch (e) {}
        """#,

        "set-cookie": #"""
        var name = args[0], raw = args[1], path = args[2] || "/";
        if (!name) return;
        var vocabulary = {
          "true": "true", "false": "false", "yes": "yes", "no": "no",
          "ok": "ok", "accept": "accept", "reject": "reject",
          "allow": "allow", "deny": "deny", "0": "0", "1": "1"
        };
        var value = Object.prototype.hasOwnProperty.call(vocabulary, raw) ? vocabulary[raw] : raw;
        if (value === undefined) return;
        try {
          document.cookie = encodeURIComponent(name) + "=" + encodeURIComponent(value)
            + "; path=" + path + "; expires=Tue, 19 Jan 2038 03:14:07 GMT";
        } catch (e) { return; }
        // A consent cookie only takes effect on the next load, so lists ask for one.
        if (args.indexOf("reload") !== -1) {
          try {
            var key = "tamis-reloaded-" + name;
            if (!sessionStorage.getItem(key)) {
              sessionStorage.setItem(key, "1");
              location.reload();
            }
          } catch (e) {}
        }
        """#,

        // The value may name another attribute in brackets, meaning "copy from there" —
        // which is how lazy-loading images are forced to reveal their real source.
        "set-attr": #"""
        var selector = args[0], attribute = args[1], raw = args[2] || "";
        if (!selector || !attribute) return;
        var run = function () {
          var nodes;
          try { nodes = document.querySelectorAll(selector); } catch (e) { return; }
          for (var i = 0; i < nodes.length; i++) {
            var value = raw;
            if (raw.charAt(0) === "[" && raw.charAt(raw.length - 1) === "]") {
              value = nodes[i].getAttribute(raw.slice(1, -1));
              if (value === null) continue;
            }
            if (nodes[i].getAttribute(attribute) !== value) nodes[i].setAttribute(attribute, value);
          }
        };
        run();
        try {
          new MutationObserver(run).observe(document.documentElement, {
            childList: true, subtree: true, attributes: true
          });
        } catch (e) {}
        """#,

        "prevent-fetch": #"""
        var needle = args[0] || "";
        var original = window.fetch;
        if (typeof original !== "function") return;
        var shouldBlock = function (input) {
          if (needle === "" || needle === "*") return true;
          var url = typeof input === "string" ? input : (input && input.url) || "";
          return String(url).indexOf(needle) !== -1;
        };
        window.fetch = function (input) {
          if (!shouldBlock(input)) return original.apply(window, arguments);
          // An empty success rather than a rejection: a page that sees fetch fail often
          // retries forever or reports itself as broken.
          return Promise.resolve(new Response("", { status: 200, statusText: "OK" }));
        };
        """#,

        "cookie-remover": #"""
        var name = args[0];
        if (!name) return;
        var matches = function (candidate) {
          if (name.charAt(0) === "/" && name.lastIndexOf("/") > 0) {
            var end = name.lastIndexOf("/");
            try { return new RegExp(name.slice(1, end), name.slice(end + 1)).test(candidate); }
            catch (e) { return false; }
          }
          return candidate === name;
        };
        var remove = function () {
          var cookies = document.cookie.split(";");
          for (var i = 0; i < cookies.length; i++) {
            var key = cookies[i].split("=")[0].trim();
            if (!key || !matches(key)) continue;
            // The path and domain a cookie was set with are not readable, so every
            // plausible scope is cleared.
            var host = location.hostname.split(".");
            var domains = [""];
            for (var d = 0; d < host.length - 1; d++) domains.push("; domain=." + host.slice(d).join("."));
            var paths = ["/", location.pathname];
            for (var p = 0; p < paths.length; p++) {
              for (var g = 0; g < domains.length; g++) {
                document.cookie = key + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path="
                  + paths[p] + domains[g];
              }
            }
          }
        };
        remove();
        try { setInterval(remove, 1000); } catch (e) {}
        """#,

        "json-prune": #"""
        var toPrune = (args[0] || "").split(" ").filter(Boolean);
        if (!toPrune.length) return;
        var prune = function (value) {
          for (var i = 0; i < toPrune.length; i++) {
            var parts = toPrune[i].split("."), owner = value;
            for (var p = 0; p < parts.length - 1 && owner; p++) owner = owner[parts[p]];
            if (owner && typeof owner === "object") delete owner[parts[parts.length - 1]];
          }
          return value;
        };
        var originalParse = JSON.parse;
        JSON.parse = function () {
          return prune(originalParse.apply(JSON, arguments));
        };
        """#,
    ]
}
