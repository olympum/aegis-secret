#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command ditto
require_command shasum

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
APP_PATH="$DIST_DIR/Aegis Secret.app"
ZIP_PATH="$DIST_DIR/Aegis Secret-$VERSION-macOS.zip"
INSTALLER_ASSET="$DIST_DIR/install-downloaded-app.sh"
CHECKSUMS_PATH="$DIST_DIR/SHA256SUMS"

if [[ ! -d "$APP_PATH" ]]; then
  echo "Error: release app not found at $APP_PATH. Run build/notarize first." >&2
  exit 1
fi

cp "$ROOT_DIR/scripts/install-downloaded-app.sh" "$INSTALLER_ASSET"
chmod +x "$INSTALLER_ASSET"

rm -f "$ZIP_PATH" "$CHECKSUMS_PATH"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"

(
  cd "$DIST_DIR"
  shasum -a 256 "${ZIP_PATH:t}" "${INSTALLER_ASSET:t}" > "${CHECKSUMS_PATH:t}"
)

echo "Packaged release assets in:"
echo "  $DIST_DIR"
