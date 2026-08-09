import Foundation

/// What the privileged daemon will do for the proxy, and the shape of what it refuses.
///
/// The whole point is the absence: there is no method that returns the authority's
/// private key. The proxy can ask for the certificate — public by nature, it goes into
/// the trust store — and for a leaf signed by it. It cannot ask for the thing that
/// makes the signature possible, because nothing here offers it.
///
/// A compromise of the proxy therefore yields certificates for as long as the
/// compromise lasts, and nothing afterwards. A compromise that reached the key would
/// yield certificates for ten years, on any machine, for any site.
@objc public protocol AuthorityService {

    /// The authority's certificate, and a leaf key pair shared by every issued leaf.
    ///
    /// The leaf key is safe to hand over: on its own it authenticates nothing. Only the
    /// authority's signature over the matching public key makes a certificate, and that
    /// signature is made here.
    @objc func materials(reply: @escaping (Data?, Data?, String?) -> Void)

    /// Signs a certificate for one host. The private key never moves.
    @objc func issue(host: String, reply: @escaping (Data?, String?) -> Void)

    /// Whether the daemon holds an authority at all, so the interface can tell "not
    /// installed" from "installed and broken".
    @objc func status(reply: @escaping (Bool, String?) -> Void)
}

/// The Mach service name launchd registers, shared by both sides so a typo cannot make
/// them disagree silently.
public enum AuthorityServiceName {
    public static let mach = "io.github.black0s.tamisd"
}
