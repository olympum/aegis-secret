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
PKG_PATH="$DIST_DIR/Aegis Secret-$VERSION-installer.pkg"
NOTARY_PROFILE="${AEGIS_SECRET_NOTARY_PROFILE:-$DEFAULT_NOTARY_PROFILE}"

if [[ ! -f "$PKG_PATH" ]]; then
  echo "Error: installer package not found at $PKG_PATH. Run ./scripts/package-release-assets.sh $TAG first." >&2
  exit 1
fi

require_value "$NOTARY_PROFILE" "AEGIS_SECRET_NOTARY_PROFILE"

xcrun notarytool submit "$PKG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$PKG_PATH"
spctl --assess --type install -vv "$PKG_PATH"

echo "Notarized and stapled installer package:"
echo "  $PKG_PATH"
