#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command xcodebuild

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
BUILD_DIR="$ROOT_DIR/.build/xcode-release/$TAG"
ARCHIVE_PATH="$DIST_DIR/Aegis Secret.xcarchive"
EXPORT_DIR="$DIST_DIR/export"
APP_PATH="$DIST_DIR/Aegis Secret.app"
ARCHIVE_LOG="$DIST_DIR/xcodebuild-archive.log"
EXPORT_LOG="$DIST_DIR/xcodebuild-export.log"
EXPORT_OPTIONS_PLIST="$DIST_DIR/ExportOptions.plist"
TEAM_ID="${AEGIS_SECRET_TEAM_ID:-}"

require_value "$TEAM_ID" "AEGIS_SECRET_TEAM_ID"

mkdir -p "$DIST_DIR" "$BUILD_DIR"
rm -rf "$ARCHIVE_PATH" "$EXPORT_DIR" "$APP_PATH"

ARCHIVE_ARGS=(
  xcodebuild
  -project "$ROOT_DIR/Aegis Secret.xcodeproj"
  -scheme "Aegis Secret"
  -configuration Release
  -destination "platform=macOS"
  -archivePath "$ARCHIVE_PATH"
  -derivedDataPath "$BUILD_DIR"
  -allowProvisioningUpdates
  DEVELOPMENT_TEAM="$TEAM_ID"
  archive
)
append_xcode_auth_args ARCHIVE_ARGS

"${ARCHIVE_ARGS[@]}" | tee "$ARCHIVE_LOG"

cat > "$EXPORT_OPTIONS_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>destination</key>
  <string>export</string>
  <key>method</key>
  <string>developer-id</string>
  <key>signingStyle</key>
  <string>automatic</string>
  <key>teamID</key>
  <string>$TEAM_ID</string>
</dict>
</plist>
EOF

EXPORT_ARGS=(
  xcodebuild
  -exportArchive
  -archivePath "$ARCHIVE_PATH"
  -exportPath "$EXPORT_DIR"
  -exportOptionsPlist "$EXPORT_OPTIONS_PLIST"
  -allowProvisioningUpdates
)
append_xcode_auth_args EXPORT_ARGS

"${EXPORT_ARGS[@]}" | tee "$EXPORT_LOG"

cp -R "$EXPORT_DIR/Aegis Secret.app" "$APP_PATH"

codesign -dv --verbose=4 "$APP_PATH" >/dev/null

echo "Built release app for $TAG at:"
echo "  $APP_PATH"
