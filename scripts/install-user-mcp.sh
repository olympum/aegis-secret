#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$HOME/.local/bin"
SERVER_NAME="aegis-secret"

cd "$ROOT_DIR"
swift build -c release

mkdir -p "$BIN_DIR"
cp .build/release/aegis-secret "$BIN_DIR/aegis-secret"
cp .build/release/aegis-secret-mcp "$BIN_DIR/aegis-secret-mcp"
chmod +x "$BIN_DIR/aegis-secret" "$BIN_DIR/aegis-secret-mcp"

if command -v codex >/dev/null 2>&1; then
  codex mcp remove "$SERVER_NAME" >/dev/null 2>&1 || true
  codex mcp add "$SERVER_NAME" --env AEGIS_SECRET_AGENT_NAME=Codex -- "$BIN_DIR/aegis-secret-mcp"
fi

if command -v claude >/dev/null 2>&1; then
  claude mcp remove --scope user "$SERVER_NAME" >/dev/null 2>&1 || true
  claude mcp add-json --scope user "$SERVER_NAME" "{\"type\":\"stdio\",\"command\":\"$BIN_DIR/aegis-secret-mcp\",\"args\":[],\"env\":{\"AEGIS_SECRET_AGENT_NAME\":\"Claude\"}}"
fi

echo "Installed aegis-secret binaries to $BIN_DIR and registered the user-level MCP server."
