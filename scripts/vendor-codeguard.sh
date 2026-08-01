#!/usr/bin/env bash
# Re-vendor Project CodeGuard v1.4.0 into:
#   - vendor/codeguard/  (release mirror + SHA256SUMS)
#   - rules/             (normalized .mdc rules for the acyl detector)
#   - .cursor/           (Cursor rules, agents, and skills — travels with every clone)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="${1:-v1.4.0}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

curl -fsSL -o SHA256SUMS "https://github.com/cosai-oasis/project-codeguard/releases/download/${VER}/SHA256SUMS"
curl -fsSL -o codeguard-all.zip "https://github.com/cosai-oasis/project-codeguard/releases/download/${VER}/codeguard-all.zip"
curl -fsSL -o codeguard-cursor.zip "https://github.com/cosai-oasis/project-codeguard/releases/download/${VER}/codeguard-cursor.zip"
sha256sum -c SHA256SUMS --ignore-missing
unzip -q codeguard-all.zip
unzip -q codeguard-cursor.zip -d cursor-dist

# Source-tree skills (security-review, memory-safe-migration) ship in the git tag,
# not in the release zip assets.
curl -fsSL -o src.tar.gz "https://github.com/cosai-oasis/project-codeguard/archive/refs/tags/${VER}.tar.gz"
tar -xzf src.tar.gz
SRC="project-codeguard-${VER#v}"

# --- vendor mirror (release slice for air-gap / attribution) ---
rm -rf "$ROOT/vendor/codeguard/cursor"
mkdir -p "$ROOT/vendor/codeguard/cursor" "$ROOT/rules"
cp -a dist/.cursor/. "$ROOT/vendor/codeguard/cursor/"
cp -a dist/.cursor/rules/*.mdc "$ROOT/rules/"
cp SHA256SUMS "$ROOT/vendor/codeguard/SHA256SUMS"

# --- live Cursor project config (committed so clones work anywhere) ---
mkdir -p "$ROOT/.cursor/rules" "$ROOT/.cursor/agents" "$ROOT/.cursor/skills"

# Official Cursor zip → rules + agent
rm -f "$ROOT/.cursor/rules"/codeguard-*.mdc
cp -a cursor-dist/.cursor/rules/*.mdc "$ROOT/.cursor/rules/"
cp -a cursor-dist/.cursor/agents/codeguard-reviewer.md "$ROOT/.cursor/agents/"

# Agent Skills from the all-zip dist + git tag sources/
rm -rf "$ROOT/.cursor/skills/codeguard"
cp -a dist/.agents/skills/codeguard "$ROOT/.cursor/skills/codeguard"

rm -rf "$ROOT/.cursor/skills/security-review"
cp -a "$SRC/sources/skills/security-review" "$ROOT/.cursor/skills/security-review"

rm -rf "$ROOT/.cursor/skills/memory-safe-migration"
cp -a "$SRC/sources/skills/memory-safe-migration" "$ROOT/.cursor/skills/memory-safe-migration"

# NOTICE is maintained in-repo (see .cursor/CODEGUARD_NOTICE.md); do not overwrite.

echo "Vendored CodeGuard ${VER} → vendor/codeguard/, rules/, .cursor/"
