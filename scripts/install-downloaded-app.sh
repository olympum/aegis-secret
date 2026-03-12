#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
APP_NAME="Aegis Secret.app"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/Applications/$APP_NAME"
APP_BINARY="$APP_DIR/Contents/MacOS/aegis-secret"
SERVER_NAME="aegis-secret"
TMP_DIR=""

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage:
  ./scripts/install-downloaded-app.sh [<Aegis Secret.app | Aegis Secret.zip>]

If no path is provided, the script looks in the current directory for:
  - ./Aegis Secret.app
  - the first *.zip that expands to Aegis Secret.app
EOF
}

resolve_source_path() {
  local input="${1:-}"
  if [[ -n "$input" ]]; then
    echo "$input"
    return
  fi

  if [[ -d "$PWD/$APP_NAME" ]]; then
    echo "$PWD/$APP_NAME"
    return
  fi

  local zip_matches=("$PWD"/*.zip(N))
  if (( ${#zip_matches[@]} > 0 )); then
    echo "$zip_matches[1]"
    return
  fi

  echo "Error: provide a path to $APP_NAME or a release zip." >&2
  usage >&2
  exit 1
}

materialize_app() {
  local source_path="$1"

  if [[ -d "$source_path" && "${source_path:t}" == "$APP_NAME" ]]; then
    echo "$source_path"
    return
  fi

  if [[ -f "$source_path" && "$source_path" == *.zip ]]; then
    TMP_DIR="$(mktemp -d)"
    ditto -x -k "$source_path" "$TMP_DIR"

    if [[ -d "$TMP_DIR/$APP_NAME" ]]; then
      echo "$TMP_DIR/$APP_NAME"
      return
    fi

    local found_app
    found_app="$(find "$TMP_DIR" -maxdepth 2 -type d -name "$APP_NAME" | head -n 1)"
    if [[ -n "$found_app" ]]; then
      echo "$found_app"
      return
    fi
  fi

  echo "Error: could not locate $APP_NAME in $source_path." >&2
  exit 1
}

SOURCE_PATH="$(resolve_source_path "${1:-}")"
SOURCE_APP="$(materialize_app "$SOURCE_PATH")"

mkdir -p "$HOME/Applications" "$BIN_DIR"
rm -rf "$APP_DIR"
cp -R "$SOURCE_APP" "$APP_DIR"

cat > "$BIN_DIR/aegis-secret" <<EOF
#!/bin/zsh
exec "$APP_BINARY" "\$@"
EOF

cat > "$BIN_DIR/aegis-secret-mcp" <<EOF
#!/bin/zsh
exec "$APP_BINARY" --mcp-server "\$@"
EOF

chmod +x "$BIN_DIR/aegis-secret" "$BIN_DIR/aegis-secret-mcp"

if command -v codex >/dev/null 2>&1; then
  codex mcp remove "$SERVER_NAME" >/dev/null 2>&1 || true
  codex mcp add "$SERVER_NAME" --env AEGIS_SECRET_AGENT_NAME=Codex -- "$APP_BINARY" --mcp-server
fi

if command -v claude >/dev/null 2>&1; then
  claude mcp remove "$SERVER_NAME" >/dev/null 2>&1 || true
  claude mcp add-json "$SERVER_NAME" "{\"type\":\"stdio\",\"command\":\"$APP_BINARY\",\"args\":[\"--mcp-server\"],\"env\":{\"AEGIS_SECRET_AGENT_NAME\":\"Claude\"}}"
fi

echo "Installed $APP_NAME to $APP_DIR and registered user-level CLI shims and MCP integration."
