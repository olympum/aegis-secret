#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command ditto
require_command xcrun
require_command spctl

TAG="$(resolve_release_tag "${1:-}")"
DIST_DIR="$(release_dist_dir "$TAG")"
APP_PATH="$DIST_DIR/Aegis Secret.app"
NOTARY_PROFILE="${AEGIS_SECRET_NOTARY_PROFILE:-$DEFAULT_NOTARY_PROFILE}"
TEMP_ZIP="$DIST_DIR/Aegis Secret-notary-upload.zip"

if [[ ! -d "$APP_PATH" ]]; then
  echo "Error: release app not found at $APP_PATH. Run ./scripts/build-release.sh $TAG first." >&2
  exit 1
fi

require_value "$NOTARY_PROFILE" "AEGIS_SECRET_NOTARY_PROFILE"

rm -f "$TEMP_ZIP"
ditto -c -k --keepParent "$APP_PATH" "$TEMP_ZIP"

xcrun notarytool submit "$TEMP_ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP_PATH"
spctl --assess --type execute -vv "$APP_PATH"

rm -f "$TEMP_ZIP"

echo "Notarized and stapled:"
echo "  $APP_PATH"
