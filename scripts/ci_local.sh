#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

latest_xcode="$(find /Applications -maxdepth 1 -type d -name 'Xcode_*.app' ! -iname '*beta*' | sort -V | tail -1)"
if [[ -z "$latest_xcode" ]]; then
  latest_xcode="$(find /Applications -maxdepth 1 -type d -name 'Xcode*.app' ! -iname '*beta*' | sort -V | tail -1)"
fi
if [[ -z "$latest_xcode" ]]; then
  echo "No stable Xcode installation found" >&2
  exit 1
fi

echo "Using Xcode at $latest_xcode"
DEVELOPER_DIR="${latest_xcode}/Contents/Developer"
export DEVELOPER_DIR

xcodebuild -version
swift --version
swift test
