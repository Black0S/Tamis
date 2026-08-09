import Foundation
import TamisFilterEngine

/// The script injected alongside the stylesheet.
///
/// It exists because a stylesheet cannot express "the element containing this text".
/// Roughly six hundred rules in EasyList need it, and without it they are parsed and
/// then quietly ignored.
///
/// Three constraints shape it:
///
/// - **It must not break the page.** Every step is wrapped so that a bad selector
///   costs one rule, not the whole runtime. A blocker that throws in a page's console
///   is indistinguishable, to the user, from a blocker that broke the site.
/// - **It must survive dynamic content.** Single-page applications insert adverts long
///   after load, so a `MutationObserver` re-runs the rules — debounced, because firing
///   on every DOM change is how an extension becomes the reason a page stutters.
/// - **It must not be parsed twice.** Selectors arrive pre-parsed from Swift, so the
///   runtime is an interpreter of structured steps rather than a parser.
public enum CosmeticRuntime {

    /// Builds the script for one page, or `nil` when there is nothing to run.
    public static func script(for selectors: [ProceduralSelector]) -> String? {
        guard !selectors.isEmpty else { return nil }
        let encoded = selectors.map { $0.encoded() }
        guard let data = try? JSONSerialization.data(withJSONObject: encoded),
              let json = String(data: data, encoding: .utf8) else { return nil }
        return source.replacingOccurrences(of: "__TAMIS_RULES__", with: json)
    }

    /// Maximum elements a single step may consider.
    ///
    /// A generic base selector on a large document can match tens of thousands of
    /// nodes, and walking them all on every mutation would cost more than the adverts
    /// ever did.
    public static let elementBudget = 8_000

    static let source = #"""
    (function () {
      "use strict";
      var RULES = __TAMIS_RULES__;
      var BUDGET = 8000;
      var hidden = new WeakSet();

      function text(el) {
        return el.textContent || "";
      }

      function step(elements, op) {
        var kind = op[0], out = [], i, el;
        switch (kind) {
          case "t":
            for (i = 0; i < elements.length; i++) {
              if (text(elements[i]).indexOf(op[1]) !== -1) out.push(elements[i]);
            }
            return out;
          case "r":
            var re;
            try { re = new RegExp(op[1], op[2] || ""); } catch (e) { return []; }
            for (i = 0; i < elements.length; i++) {
              if (re.test(text(elements[i]))) out.push(elements[i]);
            }
            return out;
          case "h":
            for (i = 0; i < elements.length; i++) {
              try { if (elements[i].querySelector(op[1])) out.push(elements[i]); } catch (e) { return []; }
            }
            return out;
          case "n":
            for (i = 0; i < elements.length; i++) {
              try { if (!elements[i].matches(op[1])) out.push(elements[i]); } catch (e) { return []; }
            }
            return out;
          case "c":
            for (i = 0; i < elements.length; i++) {
              var computed = getComputedStyle(elements[i]).getPropertyValue(op[1]);
              if (computed && computed.trim() === op[2]) out.push(elements[i]);
            }
            return out;
          case "a":
            for (i = 0; i < elements.length; i++) {
              var attr = elements[i].getAttribute(op[1]);
              if (attr === null) continue;
              if (op[2] === "" || attr === op[2]) out.push(elements[i]);
            }
            return out;
          case "l":
            for (i = 0; i < elements.length; i++) {
              if (text(elements[i]).trim().length >= op[1]) out.push(elements[i]);
            }
            return out;
          case "u":
            for (i = 0; i < elements.length; i++) {
              el = elements[i];
              for (var d = 0; d < op[1] && el; d++) el = el.parentElement;
              if (el) out.push(el);
            }
            return out;
          case "U":
            for (i = 0; i < elements.length; i++) {
              try {
                el = elements[i].parentElement && elements[i].parentElement.closest(op[1]);
              } catch (e) { return []; }
              if (el) out.push(el);
            }
            return out;
          case "x":
            var result;
            try {
              result = document.evaluate(op[1], document, null, 7, null);
            } catch (e) { return []; }
            for (i = 0; i < result.snapshotLength && out.length < BUDGET; i++) {
              out.push(result.snapshotItem(i));
            }
            return out;
          case "R":
            for (i = 0; i < elements.length; i++) {
              if (elements[i].parentNode) elements[i].parentNode.removeChild(elements[i]);
            }
            return [];
          default:
            return [];
        }
      }

      function apply() {
        for (var r = 0; r < RULES.length; r++) {
          try {
            var base = RULES[r][0], ops = RULES[r][1], elements;
            if (base) {
              elements = Array.prototype.slice.call(document.querySelectorAll(base), 0, BUDGET);
            } else {
              elements = Array.prototype.slice.call(document.querySelectorAll("*"), 0, BUDGET);
            }
            for (var o = 0; o < ops.length && elements.length; o++) {
              elements = step(elements, ops[o]);
            }
            for (var i = 0; i < elements.length; i++) {
              var el = elements[i];
              if (hidden.has(el)) continue;
              hidden.add(el);
              el.style.setProperty("display", "none", "important");
            }
          } catch (e) {
            // One bad rule must cost one rule, never the whole runtime.
          }
        }
      }

      var scheduled = false;
      function schedule() {
        if (scheduled) return;
        scheduled = true;
        // Coalesce bursts: single-page applications mutate the DOM continuously, and
        // running on every change is how a blocker becomes the reason a page stutters.
        (window.requestIdleCallback || window.setTimeout)(function () {
          scheduled = false;
          apply();
        }, 100);
      }

      apply();
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", apply, { once: true });
      }
      try {
        new MutationObserver(schedule).observe(document.documentElement, {
          childList: true, subtree: true
        });
      } catch (e) {}
    })();
    """#
}
