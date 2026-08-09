#!/bin/bash
#
# Refreshes the vendored HTTPS exclusion lists.
#
# These files are embedded rather than fetched at run time: they are active before the
# user has chosen anything, so the first banking connection after installation must
# already be protected — including when that first launch is offline.
#
# Sources are kept as separate files, deliberately. Merging them would make a diff
# unreadable (which source moved?), force a re-merge on every upstream change, and leave
# nobody to report a missing domain to. They are combined only at match time.
#
# Both upstreams are MIT. See Sources/TamisLists/Resources/Exclusions/README.md.
#
# This script only downloads. Applying an update is a separate, reviewed step: run it,
# read `git diff`, and judge the removals.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/Packages/TamisLists/Sources/TamisLists/Resources/Exclusions"
ADGUARD="https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions"
ZEN="https://raw.githubusercontent.com/irbis-sh/zen-desktop/master/internal/sysproxy/exclusions"

mkdir -p "$DEST"

fetch() {
    local url="$1" out="$2" tmp
    tmp="$(mktemp)"
    if ! curl -sfL --proto '=https' --tlsv1.2 -o "$tmp" "$url"; then
        echo "  $out — FAILED, keeping the copy already here" >&2
        rm -f "$tmp"
        return 1
    fi
    # A truncated download is the common failure, and an exclusion list that lost most
    # of its entries is worse than one that is a week out of date.
    if [ ! -s "$tmp" ]; then
        echo "  $out — empty response, refused" >&2
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$DEST/$out"
    printf '  %-24s %6s lines\n' "$out" "$(wc -l < "$DEST/$out" | tr -d ' ')"
}

echo "==> AdGuard HttpsExclusions"
for f in banks sensitive issues mac firefox; do fetch "$ADGUARD/$f.txt" "adguard-$f.txt" || true; done

echo "==> Zen"
for f in darwin common; do fetch "$ZEN/$f.txt" "zen-$f.txt" || true; done

echo
echo "Now read the diff before committing — removals reduce protection:"
echo "  git diff --stat $DEST"
