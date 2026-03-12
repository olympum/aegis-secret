#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/release-common.sh"

load_release_env

require_command gh
require_command git

TAG="$(resolve_release_tag "${1:-}")"
VERSION="$(release_version_from_tag "$TAG")"
DIST_DIR="$(release_dist_dir "$TAG")"
PKG_PATH="$DIST_DIR/Aegis Secret-$VERSION-installer.pkg"
CHECKSUMS_PATH="$DIST_DIR/SHA256SUMS"
NOTES_FILE="${AEGIS_SECRET_RELEASE_NOTES_FILE:-}"
REPOSITORY="${AEGIS_SECRET_GITHUB_REPOSITORY:-$DEFAULT_GITHUB_REPOSITORY}"

for required_path in "$PKG_PATH" "$CHECKSUMS_PATH"; do
  if [[ ! -f "$required_path" ]]; then
    echo "Error: release asset not found: $required_path" >&2
    exit 1
  fi
done

if gh release view "$TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
  gh release delete "$TAG" --repo "$REPOSITORY" --cleanup-tag=false --yes
fi

RELEASE_ARGS=(
  gh release create "$TAG"
  "$PKG_PATH"
  "$CHECKSUMS_PATH"
  --repo "$REPOSITORY"
  --draft
  --target "$(git -C "$ROOT_DIR" rev-parse HEAD)"
  --title "Aegis Secret $VERSION"
)

if [[ -n "$NOTES_FILE" ]]; then
  RELEASE_ARGS+=(--notes-file "$NOTES_FILE")
else
  RELEASE_ARGS+=(--notes "Binary release for Aegis Secret $VERSION.")
fi

"${RELEASE_ARGS[@]}"
