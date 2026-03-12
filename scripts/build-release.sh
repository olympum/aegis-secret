#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command xcodebuild
require_command codesign

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
BUILD_DIR="$ROOT_DIR/.build/xcode-release/$TAG"
ARCHIVE_PATH="$DIST_DIR/Aegis Secret.xcarchive"
APP_PATH="$DIST_DIR/Aegis Secret.app"
BUILD_LOG="$DIST_DIR/xcodebuild-release.log"
TEAM_ID="${AEGIS_SECRET_TEAM_ID:-}"
SIGNING_IDENTITY="${AEGIS_SECRET_RELEASE_SIGNING_IDENTITY:-$(detect_developer_id_identity)}"
PROFILE_SPECIFIER="${AEGIS_SECRET_RELEASE_PROVISIONING_PROFILE_SPECIFIER:-}"

require_value "$TEAM_ID" "AEGIS_SECRET_TEAM_ID"
require_value "$SIGNING_IDENTITY" "AEGIS_SECRET_RELEASE_SIGNING_IDENTITY or an installed Developer ID Application identity"

mkdir -p "$DIST_DIR" "$BUILD_DIR"
rm -rf "$ARCHIVE_PATH" "$APP_PATH"

XCODEBUILD_ARGS=(
  xcodebuild
  -project "$ROOT_DIR/Aegis Secret.xcodeproj"
  -scheme "Aegis Secret"
  -configuration Release
  -destination "platform=macOS"
  -archivePath "$ARCHIVE_PATH"
  -derivedDataPath "$BUILD_DIR"
  DEVELOPMENT_TEAM="$TEAM_ID"
  CODE_SIGN_IDENTITY="$SIGNING_IDENTITY"
)

if [[ -n "$PROFILE_SPECIFIER" ]]; then
  XCODEBUILD_ARGS+=(
    CODE_SIGN_STYLE=Manual
    PROVISIONING_PROFILE_SPECIFIER="$PROFILE_SPECIFIER"
  )
else
  XCODEBUILD_ARGS+=(-allowProvisioningUpdates)
fi

XCODEBUILD_ARGS+=(archive)

"${XCODEBUILD_ARGS[@]}" | tee "$BUILD_LOG"

cp -R "$ARCHIVE_PATH/Products/Applications/Aegis Secret.app" "$APP_PATH"

codesign -dv --verbose=4 "$APP_PATH" >/dev/null

echo "Built release app for $TAG at:"
echo "  $APP_PATH"
