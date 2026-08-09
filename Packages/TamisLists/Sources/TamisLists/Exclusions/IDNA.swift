import Foundation

/// Converts host names to the ASCII form that actually appears on the wire.
///
/// This is not a nicety. `onlinebanking-hüttenberger-bank.de` is in AdGuard's bank
/// exclusions, and a CONNECT request for it carries
/// `xn--onlinebanking-httenberger-bank-jfd.de`. Compare the two as written and they
/// never match — the entry silently does nothing and a bank gets decrypted. That is the
/// precise failure the exclusion lists exist to prevent, so the conversion belongs here,
/// at parse time, rather than being hoped for elsewhere.
///
/// Foundation does not offer this: `URL.host` percent-encodes non-ASCII rather than
/// applying IDNA, which produces `onlinebanking-h%C3%BCttenberger-bank.de` — a string
/// that appears in no DNS query and no TLS handshake.
///
/// What is implemented is Punycode (RFC 3492) over lowercased, canonically composed
/// input. Full UTS-46 mapping is not: the deviation characters (ß, ς, ZWJ, ZWNJ) are
/// left alone, which is what browsers do in non-transitional mode, so `faß.de` becomes
/// `xn--fa-hia.de` and not `fass.de`.
public enum IDNA {

    /// Normalises a host for comparison: lowercased, composed, Punycode where needed.
    ///
    /// Returns `nil` only for input that cannot be a host name at all.
    public static func normalize(host: String) -> String? {
        var host = host.trimmingCharacters(in: .whitespaces)
        if host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty else { return nil }

        // Fast path: the overwhelming majority of entries are already plain ASCII.
        if host.allSatisfy(\.isASCII) {
            return host.lowercased()
        }

        let normalized = host.precomposedStringWithCanonicalMapping.lowercased()
        var labels: [String] = []
        for label in normalized.split(separator: ".", omittingEmptySubsequences: false) {
            if label.allSatisfy(\.isASCII) {
                labels.append(String(label))
            } else if let encoded = punycode(String(label)) {
                labels.append("xn--" + encoded)
            } else {
                return nil
            }
        }
        return labels.joined(separator: ".")
    }

    // MARK: Punycode (RFC 3492)

    private static let base = 36
    private static let tmin = 1
    private static let tmax = 26
    private static let skew = 38
    private static let damp = 700
    private static let initialBias = 72
    private static let initialN = 128

    /// Encodes one label. The caller adds the `xn--` prefix.
    static func punycode(_ label: String) -> String? {
        let input = Array(label.unicodeScalars)
        var n = initialN
        var delta = 0
        var bias = initialBias

        var output = String(String.UnicodeScalarView(input.filter { $0.value < 0x80 }))
        let basicCount = output.unicodeScalars.count
        var handled = basicCount
        if basicCount > 0 { output.append("-") }

        while handled < input.count {
            // Smallest code point not yet handled: the next one to encode.
            guard let m = input.lazy.map({ Int($0.value) }).filter({ $0 >= n }).min() else {
                return nil
            }
            // Overflow here would mean a label far beyond any legal length.
            let (scaled, overflow) = (m - n).multipliedReportingOverflow(by: handled + 1)
            guard !overflow else { return nil }
            delta += scaled
            n = m

            for scalar in input {
                let c = Int(scalar.value)
                if c < n { delta += 1 }
                guard c == n else { continue }

                var q = delta
                var k = base
                while true {
                    let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                    if q < t { break }
                    output.append(digit(t + (q - t) % (base - t)))
                    q = (q - t) / (base - t)
                    k += base
                }
                output.append(digit(q))
                bias = adapt(delta: delta, numPoints: handled + 1, firstTime: handled == basicCount)
                delta = 0
                handled += 1
            }
            delta += 1
            n += 1
        }
        return output
    }

    private static func adapt(delta: Int, numPoints: Int, firstTime: Bool) -> Int {
        var delta = firstTime ? delta / damp : delta / 2
        delta += delta / numPoints
        var k = 0
        while delta > ((base - tmin) * tmax) / 2 {
            delta /= base - tmin
            k += base
        }
        return k + (((base - tmin + 1) * delta) / (delta + skew))
    }

    private static func digit(_ value: Int) -> Character {
        value < 26
            ? Character(UnicodeScalar(UInt8(97 + value)))   // a-z
            : Character(UnicodeScalar(UInt8(48 + value - 26))) // 0-9
    }
}
