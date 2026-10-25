#!/usr/bin/env bash
# =============================================================================
# skills/skill-sync/assets/drift-audit.sh reports dead citations, including the
# ones its old fallbacks hid (drift-map #33).
#
# Builds a throwaway repository with the real script copied in, then audits one
# fixture skill per case:
#   - a markdown link resolves from the citing file only, so [AGENTS.md](../AGENTS.md)
#     in skills/<name>/SKILL.md is dead although webapp/../AGENTS.md exists;
#   - a backticked path whose basename alone exists under a root is dead;
#   - live links, repo-root paths and component-root-relative paths still pass.
#
# Run: bash tests/drift_audit_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT="$REPO_ROOT/skills/skill-sync/assets/drift-audit.sh"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

FX="$(mktemp -d)"
trap 'rm -rf "$FX"' EXIT
mkdir -p "$FX/skills/skill-sync/assets" "$FX/webapp" "$FX/recon/helpers" "$FX/agentic"
cp "$AUDIT" "$FX/skills/skill-sync/assets/drift-audit.sh"
: > "$FX/AGENTS.md"
: > "$FX/recon/helpers/scan_utils.py"
: > "$FX/recon/scan_utils.py"
: > "$FX/agentic/AGENTS.md"
# A repository of its own, so the script's `git rev-parse` and `git ls-files`
# see the fixture and not the checkout this test lives in.
git -C "$FX" init -q 2>/dev/null || { echo "  SKIP  git is not available"; exit 0; }

# skill <name> <body>: write skills/<name>/SKILL.md.
skill() { mkdir -p "$FX/skills/$1"; printf '%s\n' "$2" > "$FX/skills/$1/SKILL.md"; }
# audit <name>: run the copied script on that one skill; sets OUT and RC.
audit() { OUT="$(bash "$FX/skills/skill-sync/assets/drift-audit.sh" --skill "$1" 2>&1)"; RC=$?; }

echo "== live citations pass =="
skill live 'See the [root AGENTS.md](../../AGENTS.md) and [agentic](../../agentic/AGENTS.md).
The helper `recon/helpers/scan_utils.py` (repo root) is also `helpers/scan_utils.py` in recon.'
audit live
[[ $RC -eq 0 ]] && pass "exit 0 when every citation resolves" || fail "exit $RC on live citations: $OUT"
[[ "$OUT" == *"OK - every cited path resolves."* ]] && pass "reports OK" || fail "no OK line: $OUT"

echo "== a dead relative link is reported =="
skill deadlink 'Rules: [AGENTS.md](../AGENTS.md) CRITICAL RULES.'
audit deadlink
[[ $RC -eq 1 ]] && pass "exit 1 on a dead relative link" || fail "exit $RC on [AGENTS.md](../AGENTS.md)"
[[ "$OUT" == *"skills/deadlink/SKILL.md -> ../AGENTS.md"* ]] \
    && pass "names skills/deadlink/SKILL.md -> ../AGENTS.md" || fail "dead link not named: $OUT"

echo "== a link resolves from its own file, not from a component root =="
skill rootlink 'The [helper](helpers/scan_utils.py) used by recon.'
audit rootlink
[[ $RC -eq 1 && "$OUT" == *"-> helpers/scan_utils.py"* ]] \
    && pass "a link that only resolves under recon/ is dead" || fail "exit $RC: $OUT"

echo "== a basename match is not a live citation =="
skill basename 'The scanner lives in `scanners/scan_utils.py`.'
audit basename
[[ $RC -eq 1 && "$OUT" == *"-> scanners/scan_utils.py"* ]] \
    && pass "a path whose basename exists elsewhere is dead" || fail "exit $RC: $OUT"

echo "== AGENTS.md citations are audited and flagged first =="
printf '%s\n' 'Run `tooling/missing.sh` first.' > "$FX/agentic/AGENTS.md"
rm -rf "$FX/skills/deadlink" "$FX/skills/rootlink" "$FX/skills/basename"
OUT="$(bash "$FX/skills/skill-sync/assets/drift-audit.sh" 2>&1)"; RC=$?
[[ $RC -eq 1 && "$OUT" == *"[AGENTS] dead citations"* && "$OUT" == *"agentic/AGENTS.md -> tooling/missing.sh"* ]] \
    && pass "agentic/AGENTS.md -> tooling/missing.sh under [AGENTS]" || fail "exit $RC: $OUT"

echo
echo "-----------------------------------------"
printf 'drift-audit suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
