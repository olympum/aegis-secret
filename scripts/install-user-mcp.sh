#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/Applications/Aegis Secret.app"
BUILD_DIR="$ROOT_DIR/.build/xcode"
APP_SRC_DIR="$BUILD_DIR/Build/Products/Release/Aegis Secret.app"
APP_BINARY="$APP_DIR/Contents/MacOS/aegis-secret"
CONFIG_DIR="$HOME/.config/aegis-secret"
INSTALL_ENV_FILE="$CONFIG_DIR/install.env"
TEAM_ID="${AEGIS_SECRET_TEAM_ID:-}"
BUILD_LOG="$BUILD_DIR/xcodebuild-install.log"

cd "$ROOT_DIR"

if [[ -z "$TEAM_ID" && -f "$INSTALL_ENV_FILE" ]]; then
  set -a
  source "$INSTALL_ENV_FILE"
  set +a
  TEAM_ID="${AEGIS_SECRET_TEAM_ID:-${TEAM_ID:-}}"
fi

if [[ -z "$TEAM_ID" ]]; then
  cat >&2 <<'EOF'
Error: AEGIS_SECRET_TEAM_ID is required.

The Apple Development certificate name does not reliably contain the Xcode development team ID.
Set it in one of these places:

1. Shell env:
   export AEGIS_SECRET_TEAM_ID="YOURTEAMID"
2. User config:
   ~/.config/aegis-secret/install.env

with:
  AEGIS_SECRET_TEAM_ID=YOURTEAMID
EOF
  exit 1
fi

mkdir -p "$BIN_DIR"
mkdir -p "$BUILD_DIR"

if ! xcodebuild \
  -project "$ROOT_DIR/Aegis Secret.xcodeproj" \
  -scheme "Aegis Secret" \
  -configuration Release \
  -destination "platform=macOS" \
  -derivedDataPath "$BUILD_DIR" \
  -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  build | tee "$BUILD_LOG"; then
  if grep -q "No profiles for" "$BUILD_LOG" || grep -q "No Accounts" "$BUILD_LOG"; then
    cat >&2 <<EOF

Xcode could not create or find a provisioning profile for the signed app bundle.

One-time bootstrap:
1. Open $ROOT_DIR/Aegis Secret.xcodeproj in Xcode.
2. Select the "Aegis Secret" target.
3. In Signing & Capabilities, choose your paid team ($TEAM_ID).
4. Build the app once in Xcode so it can create the provisioning profile.
5. Rerun ./scripts/install-user-mcp.sh
EOF
  fi
  exit 1
fi

mkdir -p "$HOME/Applications"
rm -rf "$APP_DIR"
cp -R "$APP_SRC_DIR" "$APP_DIR"
"$APP_BINARY" install-user
