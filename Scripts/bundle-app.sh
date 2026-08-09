#!/bin/bash
#
# Wraps the TamisApp executable into Tamis.app.
#
# SwiftPM builds a bare Mach-O; macOS refuses to give one a menu bar, a Dock entry or a
# bundle identifier. The bundle is the minimum that makes those work, and it is built
# here rather than by an .xcodeproj so the repository has no generated project to drift.
#
# The signature is ad hoc (`codesign -s -`), which is the whole point: it needs no Apple
# developer account, no certificate, no notarisation. Anyone who clones this gets a
# launchable application.
#
# Usage: Scripts/bundle-app.sh [debug|release]      (default: release)

set -euo pipefail

CONFIGURATION="${1:-release}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE="$ROOT/Packages/TamisApp"
VERSION="0.1.0"

echo "==> Building TamisApp ($CONFIGURATION)"
swift build --package-path "$PACKAGE" -c "$CONFIGURATION"

BINARY="$(swift build --package-path "$PACKAGE" -c "$CONFIGURATION" --show-bin-path)/TamisApp"
[ -x "$BINARY" ] || { echo "error: no executable at $BINARY" >&2; exit 1; }

# The helpers the installer copies out of the bundle. Building the app alone produces
# a bundle that installs a service pointing at a file that is not there — which fails
# at install time and nowhere earlier.
echo "==> Building helpers"
swift build --package-path "$ROOT/Packages/TamisDNS" -c "$CONFIGURATION" --product tamis-dnsd
swift build --package-path "$ROOT/Packages/TamisSystem" -c "$CONFIGURATION" --product tamis-pac
DNSD="$(swift build --package-path "$ROOT/Packages/TamisDNS" -c "$CONFIGURATION" --show-bin-path)/tamis-dnsd"
PAC="$(swift build --package-path "$ROOT/Packages/TamisSystem" -c "$CONFIGURATION" --show-bin-path)/tamis-pac"
for helper in "$DNSD" "$PAC"; do
    [ -x "$helper" ] || { echo "error: no executable at $helper" >&2; exit 1; }
done

APP="$ROOT/build/Tamis.app"
echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Named Tamis, not TamisApp: this is what shows in the Dock, in Force Quit and in the
# process list.
cp "$BINARY" "$APP/Contents/MacOS/Tamis"
cp "$DNSD" "$APP/Contents/MacOS/tamis-dnsd"
cp "$PAC"  "$APP/Contents/MacOS/tamis-pac"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>              <string>Tamis</string>
    <key>CFBundleDisplayName</key>       <string>Tamis</string>
    <key>CFBundleIdentifier</key>        <string>io.github.black0s.tamis</string>
    <key>CFBundleExecutable</key>        <string>Tamis</string>
    <key>CFBundlePackageType</key>       <string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key>           <string>$VERSION</string>
    <key>LSMinimumSystemVersion</key>    <string>26.0</string>
    <key>NSHumanReadableCopyright</key>  <string>GPLv3</string>
    <key>NSSupportsAutomaticTermination</key><false/>
    <key>NSSupportsSuddenTermination</key>   <false/>
</dict>
</plist>
PLIST

# Ad hoc: identity "-" means no certificate and no account. macOS accepts it for a
# locally built application, which is exactly how Tamis is meant to be obtained.
echo "==> Signing (ad hoc)"
codesign --force --sign - --timestamp=none "$APP"
codesign --verify --deep --strict "$APP"

echo "==> $APP"
echo "    open \"$APP\""
