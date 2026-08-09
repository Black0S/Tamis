#!/usr/bin/env python3
"""Rebuilds the embedded Public Suffix List.

Why it has to be the real list rather than a heuristic: `a.co.uk` and `b.co.uk` are
different sites, and no amount of counting labels can know that. Which suffixes are
public is a fact about registry policy, not about the shape of a name — so it is looked
up, never inferred. Getting it wrong makes `$third-party` wrong, and `$third-party` is
one of the most used modifiers in every list.

Two things happen here that the Swift side then never has to:

  - Unicode labels are converted to Punycode. 459 rules are non-ASCII, and a host name
    on the wire is always Punycode, so comparing them as written would silently never
    match — the same failure the exclusion lists had.
  - Comments and blank lines are dropped, and the ICANN/PRIVATE divider is replaced by
    a single sentinel, so the parser is a loop over lines and nothing more.

Usage:  Scripts/update-public-suffix.py
Then read the diff and run the tests: the official test suite is checked in beside it.
"""

import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "Packages/TamisFilterEngine/Sources/TamisFilterEngine/Resources/public_suffix_list.txt"
TESTS = ROOT / "Packages/TamisFilterEngine/Tests/TamisFilterEngineTests/Resources/psl_tests.txt"

LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
TESTS_URL = "https://raw.githubusercontent.com/publicsuffix/list/master/tests/test_psl.txt"

PRIVATE_SENTINEL = "%PRIVATE%"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Tamis PSL builder"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")


def punycode(rule):
    """Encodes a rule's labels, leaving `*` and `!` markers alone."""
    if rule.isascii():
        return rule.lower()
    out = []
    for label in rule.split("."):
        if label in ("*", "") or label.isascii():
            out.append(label.lower())
            continue
        try:
            out.append("xn--" + label.encode("punycode").decode("ascii"))
        except UnicodeError:
            print(f"  cannot encode {rule!r}", file=sys.stderr)
            return None
    return ".".join(out)


def main():
    print(f"==> {LIST_URL}")
    text = fetch(LIST_URL)

    rules, private, dropped = [], False, 0
    for line in text.splitlines():
        stripped = line.strip()
        if "BEGIN PRIVATE DOMAINS" in line:
            private = True
            rules.append(PRIVATE_SENTINEL)
            continue
        if not stripped or stripped.startswith("//"):
            continue
        encoded = punycode(stripped)
        if encoded is None:
            dropped += 1
            continue
        rules.append(encoded)

    if not private:
        sys.exit("error: the PRIVATE DOMAINS divider is missing — refusing to write")
    # A list that lost most of itself is worse than one a week out of date.
    if len(rules) < 8_000:
        sys.exit(f"error: only {len(rules)} rules — refusing to write")

    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text("\n".join(rules) + "\n", encoding="utf-8")

    print(f"==> {TESTS_URL}")
    TESTS.parent.mkdir(parents=True, exist_ok=True)
    TESTS.write_text(fetch(TESTS_URL), encoding="utf-8")

    icann = rules.index(PRIVATE_SENTINEL)
    print()
    print(f"  {len(rules) - 1} rules — {icann} ICANN, {len(rules) - icann - 1} private")
    print(f"  wildcards  {sum(1 for r in rules if r.startswith('*'))}")
    print(f"  exceptions {sum(1 for r in rules if r.startswith('!'))}")
    if dropped:
        print(f"  dropped    {dropped}")
    print(f"  {DEST.relative_to(ROOT)} — {DEST.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
