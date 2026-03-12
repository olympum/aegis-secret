#!/bin/zsh

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$HOME/.config/aegis-secret"
INSTALL_ENV_FILE="$CONFIG_DIR/install.env"
RELEASE_ENV_FILE="$CONFIG_DIR/release.env"
DEFAULT_NOTARY_PROFILE="AegisSecretRelease"
DEFAULT_GITHUB_REPOSITORY="olympum/aegis-secret"

load_release_env() {
  if [[ -f "$INSTALL_ENV_FILE" ]]; then
    set -a
    source "$INSTALL_ENV_FILE"
    set +a
  fi

  if [[ -f "$RELEASE_ENV_FILE" ]]; then
    set -a
    source "$RELEASE_ENV_FILE"
    set +a
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Error: required command not found: $command_name" >&2
    exit 1
  fi
}

resolve_release_tag() {
  local explicit_tag="${1:-${AEGIS_SECRET_RELEASE_TAG:-}}"
  if [[ -n "$explicit_tag" ]]; then
    echo "$explicit_tag"
    return
  fi

  local exact_tag
  exact_tag="$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null || true)"
  if [[ -n "$exact_tag" ]]; then
    echo "$exact_tag"
    return
  fi

  echo "Error: release tag is required. Pass a tag like v0.1.0 or set AEGIS_SECRET_RELEASE_TAG." >&2
  exit 1
}

release_version_from_tag() {
  local tag="$1"
  echo "${tag#v}"
}

release_dist_dir() {
  local tag="$1"
  echo "$ROOT_DIR/dist/$tag"
}

detect_developer_id_identity() {
  security find-identity -v -p codesigning \
    | sed -n 's/.*"\(Developer ID Application: [^"]*\)"/\1/p' \
    | head -n 1
}

require_value() {
  local value="$1"
  local label="$2"
  if [[ -z "$value" ]]; then
    echo "Error: $label is required." >&2
    exit 1
  fi
}
