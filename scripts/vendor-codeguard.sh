#!/usr/bin/env bash
# Re-vendor Project CodeGuard v1.4.0 into vendor/codeguard + rules/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="${1:-v1.4.0}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
curl -fsSL -o SHA256SUMS "https://github.com/cosai-oasis/project-codeguard/releases/download/${VER}/SHA256SUMS"
curl -fsSL -o codeguard-all.zip "https://github.com/cosai-oasis/project-codeguard/releases/download/${VER}/codeguard-all.zip"
sha256sum -c SHA256SUMS --ignore-missing
unzip -q codeguard-all.zip
rm -rf "$ROOT/vendor/codeguard/cursor"
mkdir -p "$ROOT/vendor/codeguard/cursor" "$ROOT/rules"
cp -a dist/.cursor/. "$ROOT/vendor/codeguard/cursor/"
cp -a dist/.cursor/rules/*.mdc "$ROOT/rules/"
cp SHA256SUMS "$ROOT/vendor/codeguard/SHA256SUMS"
echo "Vendored CodeGuard ${VER}"
