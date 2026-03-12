#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command xcrun
require_command spctl

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
DMG_PATH="$DIST_DIR/Aegis Secret-$VERSION-macOS.dmg"
NOTARY_PROFILE="${AEGIS_SECRET_NOTARY_PROFILE:-$DEFAULT_NOTARY_PROFILE}"

if [[ ! -f "$DMG_PATH" ]]; then
  echo "Error: release disk image not found at $DMG_PATH. Run ./scripts/package-release-assets.sh $TAG first." >&2
  exit 1
fi

require_value "$NOTARY_PROFILE" "AEGIS_SECRET_NOTARY_PROFILE"

xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG_PATH"
spctl --assess --type open -vv "$DMG_PATH"

echo "Notarized and stapled disk image:"
echo "  $DMG_PATH"
