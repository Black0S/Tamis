# Tamis

Ad and telemetry blocker for macOS, written entirely in Swift.

Tamis filters **every browser at once** — and applications that are not browsers —
from outside the browser, with no extension to install. It runs two layers: a local
DNS resolver that covers the whole machine, and an HTTPS proxy that blocks requests and
hides what a blocked advert would have left behind.

It depends on **no Apple developer account**: no entitlement, no Developer ID, no
approval. Anyone who clones this repository gets a working build.

> **Status: not yet a working install.** The engines, the DNS layer, the proxy and the
> list management all work and are tested, and the app builds and runs — but nothing
> installs itself yet, so no traffic passes through it. Everything below is runnable
> today. See [Where this stands](#where-this-stands).

---

## Why it exists

Safari no longer has uBlock Origin — support was dropped. Chrome's Manifest V3 leaves
only uBO Lite, with a hard cap on rules. Tamis sits below the browser instead, so it is
unaffected by either, and covers the applications an extension can never reach.

Measured against EasyList and EasyPrivacy: **115 532 network rules** and **24 177
cosmetic rules** parsed with no errors, matching in **136 µs** per request. Against the
whole suggested selection — eleven lists, 456 183 lines — 300 841 network rules and
273 739 blocked domains.

What it does not do: on Firefox, where uBlock Origin still runs unrestricted, uBO's
cosmetic filtering is finer than injecting from outside the page. Tamis is strongest
exactly where extensions have lost ground.

## Requirements

- macOS 26 or later, Apple Silicon
- Xcode 26 or later

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
```

## Try it now

Two tools run today without installing anything, without privileges, and without
touching any system setting.

### The DNS resolver

```bash
curl -sLO https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
swift run -c release --package-path Packages/TamisDNS tamis-dnsd --port 15353 --lists hosts
```

Then, from another terminal:

```bash
dig @127.0.0.1 -p 15353 ads.doubleclick.net    # NXDOMAIN
dig @127.0.0.1 -p 15353 example.com            # resolved over encrypted DNS
```

### The filter engine benchmark

```bash
curl -sLO https://easylist.to/easylist/easylist.txt
swift run -c release --package-path Packages/TamisFilterEngine tamis-bench easylist.txt
```

Reports how much of a list is really enforced, how many rules land in the
always-checked bucket, and how long a match takes.

### What is never decrypted

```bash
swift run --package-path Packages/TamisLists tamis-exclusions
swift run --package-path Packages/TamisLists tamis-exclusions mabanque.bnpparibas
```

Lists the shipped HTTPS exclusions, or answers *is this host protected* — and by which
list, exactly or with subdomains, under which application restriction.

```bash
swift run --package-path Packages/TamisLists tamis-exclusions --allowlist
swift run --package-path Packages/TamisLists tamis-exclusions --check-updates
```

`--allowlist` prints the hosts Tamis will never block and why each one is there.
`--check-updates` runs the whole update chain against the live upstreams — download,
guardrails, diff, verdict — and writes nothing.

### The whole list chain

```bash
swift run --package-path Packages/TamisLists tamis-lists --root /tmp/tamis --suggested --compile
```

Subscribes to the suggested selection, downloads it for real, then compiles what arrived
into both engines and checks that three advertising hosts are blocked and nine ordinary
sites are not. The second half is the half that matters: an engine that blocks
everything passes the first.

### Real traffic through the real engines

```bash
swift run -c release --package-path Packages/TamisProxy tamis-proxy \
    --root /tmp/tamis --port 18080 --scripts ~/Library/Application\ Support/Tamis/Scripts
```

Starts the proxy on a port with whatever lists are in that store, and writes its
certificate authority next to them. From another terminal — no system proxy setting, no
keychain, no root:

```bash
curl -x http://127.0.0.1:18080 --cacert /tmp/tamis/ca.pem https://example.com/
```

It logs every decision: intercepted, blocked and by which rule, tunnelled and by which
exclusion list, and which user scripts and styles reached which page.

`--scripts` is what makes a script enabled in the app actually run. The app manages the
library; it does not yet carry traffic, so the two are joined by hand for now.

### The application

```bash
Scripts/bundle-app.sh && open build/Tamis.app
```

Builds `Tamis.app` and signs it ad hoc — no certificate, no account. The Filters screen
browses all 165 lists, downloads what you enable into
`~/Library/Application Support/Tamis`, and compiles it into the engines. The DNS screen
runs the resolver on a local port and answers `dig` — nothing on the Mac is
reconfigured, so the system does not use it yet. The Scripts screen manages
`~/Library/Application Support/Tamis/Scripts` as an ordinary folder tree.

`TAMIS_STORE` and `TAMIS_SCRIPTS` point those two directories elsewhere.

`TAMIS_STORE=/some/path` points it at a throwaway set of lists instead.

## Build and test

```bash
for package in TamisFilterEngine TamisDNS TamisTLS TamisUserScripts TamisLists TamisProxy; do
  swift test --package-path "Packages/$package"
done
```

Tests that reach the network are skipped unless asked for, so offline runs stay
deterministic:

```bash
TAMIS_LIVE_TESTS=1 swift test --package-path Packages/TamisDNS
```

## How it works

| Layer | Covers | Mechanism |
|---|---|---|
| **DNS** | The whole machine, daemons included | Local resolver, blocklists, encrypted DNS upstream |
| **Proxy** | Browsers and applications that honour the system proxy | Request blocking, cosmetic filtering, user scripts |

Three processes, split by privilege. Nothing exposed to hostile content ever runs as
root:

- `tamisd` — root, minimal, no network parsing at all. System settings and the
  certificate authority's key.
- `tamis-dnsd` — never root. launchd binds port 53 and hands it over already open.
- `Tamis.app` — the user's session. Interface, proxy, filter engine.

### Packages

| Package | What it holds |
|---|---|
| `TamisFilterEngine` | Adblock Plus syntax, matching, cosmetic rules |
| `TamisDNS` | Wire format, blocklists, DNS-over-HTTPS, resolver |
| `TamisTLS` | Certificate authority and short-lived leaf certificates |
| `TamisUserScripts` | Tampermonkey scripts and UserCSS styles |
| `TamisLists` | HTTPS exclusions, IDNA, list sources |
| `TamisProxy` | CONNECT, TLS interception, HTTP filtering, injection |

## What Tamis will never do

- **Send anything anywhere.** No telemetry, not even a crash report.
- **Decrypt banking or password-manager traffic.** 4 492 hosts are excluded by design,
  from two independent maintained lists, embedded so they work on a first launch with
  no network, and the banking and password-manager lists cannot be disabled.
- **Intercept Tor Browser or Mullvad Browser.** Locked out, because filtering them
  would destroy the reason they exist.
- **Let its own authority's key leave the privileged daemon.** A complete compromise of
  the proxy still cannot exfiltrate it.

## Where this stands

| | |
|---|---|
| Filter engine — network and cosmetic | done |
| Public Suffix List — the real one, official suite passing | done |
| DNS resolver, encrypted upstream, cache | done |
| Certificate authority and leaf issuance | done |
| Proxy: CONNECT, TLS interception, filtering, injection | done |
| User scripts and user styles | done |
| HTTPS exclusions — embedded, locked, wired into the proxy | done |
| Blocklist catalogue — 165 lists, embedded, nothing downloaded | done |
| List downloading, update guardrails, diffs, rollback | done |
| Subscriptions, refresh, compiling into both engines | done |
| Filters screen — browse, enable, refresh, add by URL | done |
| Compiling the enabled lists into the engines, in the app | done |
| Proxy carrying real traffic, on a port, with real lists | done |
| DNS screen — provider, local resolver, live decisions | done |
| Scripts screen — filesystem tree, editor, install, revert | done |
| User scripts and styles reaching real pages through the proxy | done |
| Installing: system proxy, port 53, trusted authority | not started |
| HTTP/2 | written, not enabled — see below |
| SwiftUI application | shell only — navigation and dashboard, no engine behind it |
| Onboarding, uninstall, privileged daemon | not started |

HTTP/2 negotiates on both sides and the bridge installs, but response frames are not
delivered to the stream channel. It is deliberately not advertised, since negotiating
a protocol and then hanging is worse than not offering it. The end-to-end tests are
committed and disabled, carrying the diagnosis.

## Design notes

[`SPEC.md`](SPEC.md) records every decision and, more usefully, why the alternatives
were rejected. It is in French.

## Licence

GPLv3. Not a default: Tamis installs a root certificate authority on the machine, and
copyleft is what guarantees any fork stays auditable — nobody can take this code, add
an authority that exfiltrates, and ship it as a closed binary.

The same reasoning rules out the Mac App Store, which GPLv3 is incompatible with. No
loss: an application that installs a certificate authority and rewrites network
settings would never have been accepted there.
