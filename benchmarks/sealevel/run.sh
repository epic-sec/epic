#!/usr/bin/env bash
# Runs EPIC against every insecure/secure/recommended variant in the
# coral-xyz/sealevel-attacks benchmark and prints a per-variant summary.
#
# Usage:
#   ./benchmarks/sealevel/run.sh
#
# The benchmark is pinned to a specific commit (see PINNED_COMMIT below) so
# results are reproducible — sealevel-attacks is a teaching repo that can
# change its fixtures over time. Set SEALEVEL_ATTACKS_DIR to reuse an
# existing clone instead of cloning a fresh one into a temp directory.
set -euo pipefail

PINNED_COMMIT="24555d044802db4022112a94d6d70e74291a4b6d"
REPO_URL="https://github.com/coral-xyz/sealevel-attacks.git"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLONE_DIR="${SEALEVEL_ATTACKS_DIR:-}"

if [ -z "$CLONE_DIR" ]; then
  CLONE_DIR="$(mktemp -d)/sealevel-attacks"
fi

if [ ! -d "$CLONE_DIR/.git" ]; then
  echo "Cloning sealevel-attacks into $CLONE_DIR..." >&2
  git clone --quiet "$REPO_URL" "$CLONE_DIR"
fi

echo "Checking out pinned commit $PINNED_COMMIT..." >&2
git -C "$CLONE_DIR" fetch --quiet origin "$PINNED_COMMIT" 2>/dev/null || true
git -C "$CLONE_DIR" checkout --quiet "$PINNED_COMMIT"

echo "Building epic (release)..." >&2
cargo build --release -p epic --manifest-path "$REPO_ROOT/Cargo.toml" >&2
EPIC_BIN="$REPO_ROOT/target/release/epic"

echo >&2
printf "%-32s %-20s %-14s %s\n" "CLASS" "VARIANT" "VERDICT" "FINDINGS (rule x count)"
printf "%-32s %-20s %-14s %s\n" "-----" "-------" "-------" "------------------------"

for classdir in "$CLONE_DIR"/programs/*/; do
  class=$(basename "$classdir")
  for variantdir in "$classdir"*/; do
    variant=$(basename "$variantdir")
    out=$("$EPIC_BIN" audit "$variantdir" 2>/dev/null || true)
    verdict=$(echo "$out" | grep -A1 "Final Verdict" | tail -1 | xargs || echo "UNKNOWN")
    findings=$( (echo "$out" | grep -oE "EPIC-SEC-[A-Z0-9]+" || true) | sort | uniq -c \
      | awk '{printf "%s x%s; ", $2, $1}')
    [ -z "$findings" ] && findings="(none)"
    printf "%-32s %-20s %-14s %s\n" "$class" "$variant" "$verdict" "$findings"
  done
done

echo >&2
echo "Pinned commit: $PINNED_COMMIT" >&2
echo "See RESULTS.md in this directory for the classified verdict table (TRUE POSITIVE / FALSE NEGATIVE / FALSE POSITIVE / NOT COVERED) and analysis." >&2
