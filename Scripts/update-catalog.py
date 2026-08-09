#!/usr/bin/env python3
"""Rebuilds the embedded blocklist catalogue.

Only metadata is embedded — roughly a hundred kilobytes. That is what lets the catalogue
be browsed offline on a first launch while, deliberately, not a single list has been
downloaded: the choice is the user's, and they cannot make it in front of an empty
screen.

Two registries, kept side by side rather than reconciled:

  uBlock Origin  assets.json    71 lists
  AdGuard        filters.json   88 lists

They do not overlap by download URL — AdGuard serves everything from its own mirrors —
so nothing merges, and about twenty lists legitimately appear twice under the same name
from two different publishers. Both are kept, each naming its registry, because they are
genuinely different files with different update cadences. Hiding one would mean choosing
for the user which mirror they trust.

A third section is written by hand: DNS-format lists, which neither registry carries and
which the resolver needs.

Usage:  Scripts/update-catalog.py
Then read the diff.
"""

import json
import sys
import urllib.request
from datetime import date, timezone, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "Packages/TamisLists/Sources/TamisLists/Resources/catalog.json"

UBO_URL = "https://raw.githubusercontent.com/gorhill/uBlock/master/assets/assets.json"
ADGUARD_URL = "https://filters.adtidy.org/extension/chromium/filters.json"

UBO_CATEGORY = {
    "default": "base",
    "ads": "ads",
    "privacy": "privacy",
    "malware": "security",
    "annoyances": "annoyances",
    "multipurpose": "multipurpose",
    "regions": "regional",
}

ADGUARD_CATEGORY = {
    1: "ads",
    2: "privacy",
    3: "social",
    4: "annoyances",
    5: "security",
    6: "other",
    7: "regional",
}

# Neither registry lists DNS-format blocklists: they describe what a browser extension
# subscribes to, and Tamis also has a resolver. Written by hand, checked by hand.
DNS_LISTS = [
    {
        "id": "dns:stevenblack",
        "name": "StevenBlack — unified hosts",
        "description": "Publicités et trackers, format hosts. Agrège plusieurs sources "
                       "reconnues et sert de référence de fait.",
        "downloadURL": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "homepage": "https://github.com/StevenBlack/hosts",
        "registry": "Tamis",
        "category": "dns",
        "format": "hosts",
        "languages": [],
        "recommendedByRegistry": True,
        "inSuggestedSelection": True,
        "deprecated": False,
        "trust": None,
    },
    {
        "id": "dns:adguard",
        "name": "AdGuard DNS filter",
        "description": "La liste que fait tourner AdGuard sur ses propres résolveurs.",
        "downloadURL": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "homepage": "https://github.com/AdguardTeam/AdGuardSDNSFilter",
        "registry": "Tamis",
        "category": "dns",
        "format": "adblock",
        "languages": [],
        "recommendedByRegistry": True,
        "inSuggestedSelection": True,
        "deprecated": False,
        "trust": None,
    },
    {
        "id": "dns:oisd-small",
        "name": "OISD — small",
        "description": "Publicité et pistage, resserrée pour ne rien casser.",
        "downloadURL": "https://small.oisd.nl/",
        "homepage": "https://oisd.nl",
        "registry": "Tamis",
        "category": "dns",
        "format": "adblock",
        "languages": [],
        "recommendedByRegistry": False,
        "inSuggestedSelection": False,
        "deprecated": False,
        "trust": None,
    },
    {
        "id": "dns:oisd-big",
        "name": "OISD — big",
        "description": "La même, nettement plus large. Attendez-vous à devoir "
                       "débloquer ponctuellement.",
        "downloadURL": "https://big.oisd.nl/",
        "homepage": "https://oisd.nl",
        "registry": "Tamis",
        "category": "dns",
        "format": "adblock",
        "languages": [],
        "recommendedByRegistry": False,
        "inSuggestedSelection": False,
        "deprecated": False,
        "trust": None,
    },
    {
        "id": "dns:hagezi-light",
        "name": "HaGeZi — Light",
        "description": "Le strict nécessaire : publicité et pistage les plus répandus.",
        "downloadURL": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
        "homepage": "https://github.com/hagezi/dns-blocklists",
        "registry": "Tamis",
        "category": "dns",
        "format": "adblock",
        "languages": [],
        "recommendedByRegistry": False,
        "inSuggestedSelection": False,
        "deprecated": False,
        "trust": None,
    },
    {
        "id": "dns:hagezi-multi",
        "name": "HaGeZi — Multi Normal",
        "description": "Publicité, pistage, télémétrie, hameçonnage, minage.",
        "downloadURL": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
        "homepage": "https://github.com/hagezi/dns-blocklists",
        "registry": "Tamis",
        "category": "dns",
        "format": "adblock",
        "languages": [],
        "recommendedByRegistry": False,
        "inSuggestedSelection": False,
        "deprecated": False,
        "trust": None,
    },
    {
        "id": "dns:hagezi-pro",
        "name": "HaGeZi — Multi Pro",
        "description": "La précédente, élargie. Bon compromis pour qui accepte de "
                       "débloquer de temps en temps.",
        "downloadURL": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        "homepage": "https://github.com/hagezi/dns-blocklists",
        "registry": "Tamis",
        "category": "dns",
        "format": "adblock",
        "languages": [],
        "recommendedByRegistry": False,
        "inSuggestedSelection": False,
        "deprecated": False,
        "trust": None,
    },
]


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Tamis catalogue builder"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def first_http(value):
    """`contentURL` is a string here and a list there."""
    candidates = value if isinstance(value, list) else [value]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.startswith("http"):
            return candidate
    return None


def from_ubo(assets):
    entries = []
    for key, value in assets.items():
        if value.get("content") != "filters":
            continue
        url = first_http(value.get("contentURL", []))
        if not url:
            print(f"  skipped {key}: no remote URL", file=sys.stderr)
            continue
        group = value.get("group", "other")
        entries.append({
            "id": f"ubo:{key}",
            "name": value.get("title", key),
            # uBO's registry carries no prose. The interface shows nothing rather than
            # inventing something.
            "description": "",
            "downloadURL": url,
            "homepage": value.get("supportURL", ""),
            "registry": "uBlock Origin",
            "category": UBO_CATEGORY.get(group, "other"),
            "format": "adblock",
            "languages": sorted(value.get("lang", "").split()) if value.get("lang") else [],
            "recommendedByRegistry": not value.get("off", False),
            # uBO's own out-of-the-box configuration: nine lists, chosen and maintained
            # by people who do this full time. Reused rather than replaced, because a
            # default set invented here would be a judgement with nothing behind it.
            "inSuggestedSelection": not value.get("off", False),
            "deprecated": False,
            "trust": None,
        })
    return entries


def from_adguard(registry):
    tags = {tag["tagId"]: tag["keyword"] for tag in registry["tags"]}
    entries = []
    for filt in registry["filters"]:
        keywords = {tags.get(t, "") for t in filt.get("tags", [])}
        entries.append({
            "id": f"adguard:{filt['filterId']}",
            "name": filt["name"],
            "description": filt.get("description", ""),
            "downloadURL": filt["downloadUrl"],
            "homepage": filt.get("homepage", ""),
            "registry": "AdGuard",
            "category": ADGUARD_CATEGORY.get(filt.get("groupId"), "other"),
            "format": "adblock",
            "languages": sorted(filt.get("languages", [])),
            # AdGuard's recommendation, passed through as theirs. It is not a default:
            # it marks 42 lists, most of them language-specific, so it answers
            # "worth knowing about" rather than "switch this on".
            "recommendedByRegistry": "recommended" in keywords,
            "inSuggestedSelection": False,
            "deprecated": bool(filt.get("deprecated", False)),
            "trust": filt.get("trustLevel"),
        })
    return entries


def main():
    print("==> uBlock Origin assets.json")
    ubo = from_ubo(fetch(UBO_URL))
    print(f"    {len(ubo)} lists")

    print("==> AdGuard filters.json")
    adguard = from_adguard(fetch(ADGUARD_URL))
    print(f"    {len(adguard)} lists")

    entries = ubo + adguard + DNS_LISTS

    # Deduplicate on the download URL: the same file offered twice is one subscription.
    seen, unique = set(), []
    for entry in entries:
        if entry["downloadURL"] in seen:
            continue
        seen.add(entry["downloadURL"])
        unique.append(entry)
    dropped = len(entries) - len(unique)

    unique.sort(key=lambda e: (e["category"], e["name"].lower()))

    catalog = {
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "registries": [
            {"name": "uBlock Origin", "url": UBO_URL},
            {"name": "AdGuard", "url": ADGUARD_URL},
        ],
        "entries": unique,
    }

    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text(json.dumps(catalog, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    size = DEST.stat().st_size
    print()
    print(f"  {len(unique)} lists, {dropped} duplicate URLs dropped")
    print(f"  {DEST.relative_to(ROOT)} — {size // 1024} KB")
    print(f"  suggested selection: {sum(1 for e in unique if e['inSuggestedSelection'])}")
    print(f"  recommended by their registry: {sum(1 for e in unique if e['recommendedByRegistry'])}")
    print(f"  deprecated: {sum(1 for e in unique if e['deprecated'])}")
    print()
    print("Nothing here is downloaded. Read the diff before committing.")


if __name__ == "__main__":
    main()
