#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command ditto
require_command hdiutil
require_command shasum

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
APP_PATH="$DIST_DIR/Aegis Secret.app"
DMG_STAGING_DIR="$DIST_DIR/dmg-root"
DMG_PATH="$DIST_DIR/Aegis Secret-$VERSION-macOS.dmg"
INSTALL_NOTES_PATH="$DMG_STAGING_DIR/INSTALL.txt"
CHECKSUMS_PATH="$DIST_DIR/SHA256SUMS"

if [[ ! -d "$APP_PATH" ]]; then
  echo "Error: release app not found at $APP_PATH. Run build/notarize first." >&2
  exit 1
fi

rm -rf "$DMG_STAGING_DIR"
mkdir -p "$DMG_STAGING_DIR"
cp -R "$APP_PATH" "$DMG_STAGING_DIR/"
ln -s /Applications "$DMG_STAGING_DIR/Applications"

cat > "$INSTALL_NOTES_PATH" <<'EOF'
Aegis Secret install

1. Drag "Aegis Secret.app" into Applications.
2. Run:

   /Applications/Aegis\ Secret.app/Contents/MacOS/aegis-secret install-user

That command creates the PATH shims in ~/.local/bin and registers the
user-scoped MCP integrations for Codex and Claude when those CLIs are present.
EOF

rm -f "$DMG_PATH" "$CHECKSUMS_PATH"
hdiutil create \
  -volname "Aegis Secret" \
  -srcfolder "$DMG_STAGING_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH" >/dev/null

(
  cd "$DIST_DIR"
  shasum -a 256 "${DMG_PATH:t}" > "${CHECKSUMS_PATH:t}"
)

echo "Packaged release assets in:"
echo "  $DIST_DIR"
