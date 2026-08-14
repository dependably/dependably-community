#!/usr/bin/env bash
# Self-contained regression suite for ci/ai-review.sh's finding-classification
# and clean-review-verification state machine. No bats/shunit dependency —
# `source`s ai-review.sh (guarded so sourcing does not trigger a real model
# call) and drives its functions, including a full `main` run per scenario
# with `run_turn`/`compute_diff`/`truncate_diff` stubbed so no network or git
# state is needed. Invoked directly: `bash ci/ai-review-test.sh`.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS=0
FAIL=0

assert_eq() {  # <expected> <actual> <message>
  if [ "$1" = "$2" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL: $3"
    echo "  expected: $1"
    echo "  actual:   $2"
  fi
}

assert_contains() {  # <file> <needle> <message>
  if grep -qF "$2" "$1" 2>/dev/null; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL: $3"
    echo "  expected '$1' to contain: $2"
    echo "  --- actual content of $1 ---"
    cat "$1" 2>/dev/null
    echo "  ----------------------------"
  fi
}

assert_not_contains() {  # <file> <needle> <message>
  if grep -qF "$2" "$1" 2>/dev/null; then
    FAIL=$((FAIL + 1))
    echo "FAIL: $3"
    echo "  expected '$1' NOT to contain: $2"
  else
    PASS=$((PASS + 1))
  fi
}

# ── Source the script under test ────────────────────────────────────────────
# Required env vars are stubbed; the BASH_SOURCE guard at the bottom of
# ai-review.sh keeps `main` from running just because we sourced it.
export OLLAMA_URL="http://stub.invalid:1"
export OLLAMA_MODEL="stub-model"
export CI_MERGE_REQUEST_IID="1"
export CI_PROJECT_ID="1"
export CI_API_V4_URL="http://stub.invalid:1/api/v4"
unset AI_REVIEW_GITLAB_TOKEN 2>/dev/null || true   # post_or_update_note stays artifact-only, no network

# shellcheck source=./ai-review.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/ai-review.sh" ci/prompts/security.md "$TMP_DIR/report-init.md"

# ═══════════════════════════════════════════════════════════════════════════
# Part 1 — pure function unit tests
# ═══════════════════════════════════════════════════════════════════════════

echo "== extract_clean_sentinel: single source of truth from each persona =="
assert_eq "_No material security findings._" \
  "$(extract_clean_sentinel ci/prompts/security.md)" "security.md sentinel"
assert_eq "_No material code-quality findings._" \
  "$(extract_clean_sentinel ci/prompts/code.md)" "code.md sentinel"
assert_eq "_No material architectural findings._" \
  "$(extract_clean_sentinel ci/prompts/architecture.md)" "architecture.md sentinel"
assert_eq "_No documentation gaps._" \
  "$(extract_clean_sentinel ci/prompts/documentation.md)" "documentation.md sentinel"

SECURITY_SENTINEL="$(extract_clean_sentinel ci/prompts/security.md)"

echo "== classify_response: (b) marker-free, non-sentinel prose -> ambiguous, NEVER clean =="
# This is the exact attack from #536: a diff instructs the model to reply with
# bare prose that reads as "no findings" but carries none of the format
# markers has_findings looks for, and is not byte-identical to the sentinel
# the persona was told to emit. The pre-fix script read marker-absence alone
# as clean; classify_response must not.
printf 'Everything checks out here, nothing to flag in this change.' > "$TMP_DIR/ambiguous.txt"
result="$(classify_response "$TMP_DIR/ambiguous.txt" "$SECURITY_SENTINEL")"
assert_eq "ambiguous" "$result" "marker-free non-sentinel prose must classify as ambiguous, not clean"

# Regression pin: the heuristic ai-review.sh used before this fix (marker
# absence alone => clean) is reproduced literally here, not sourced from git
# history, so this assertion keeps meaning even as the script evolves further.
# It documents that the exact input above WOULD have been posted as a clean
# review under the old logic — the divergence from classify_response above is
# the fix.
legacy_marker_absence_means_clean() {  # <file>; the removed pre-fix heuristic
  ! (grep -qE '^[[:space:]]*>' "$1" || grep -qiE '^[[:space:]]*([-*+] |#{1,6} |[0-9]+[.)] |(finding|problem|issue|bug)[ :0-9])' "$1")
}
if legacy_marker_absence_means_clean "$TMP_DIR/ambiguous.txt"; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  echo "FAIL: sanity check that the injection payload matches NO format marker (test input is wrong)"
fi

echo "== classify_response: (b) the exact sentinel -> clean =="
printf '%s' "$SECURITY_SENTINEL" > "$TMP_DIR/sentinel.txt"
result="$(classify_response "$TMP_DIR/sentinel.txt" "$SECURITY_SENTINEL")"
assert_eq "clean" "$result" "byte-exact sentinel match must classify as clean"

echo "   .. tolerates incidental surrounding whitespace/newlines .."
printf '\n\n%s\n\n' "$SECURITY_SENTINEL" > "$TMP_DIR/sentinel-padded.txt"
result="$(classify_response "$TMP_DIR/sentinel-padded.txt" "$SECURITY_SENTINEL")"
assert_eq "clean" "$result" "sentinel plus incidental whitespace/newlines still classifies as clean"

echo "   .. a near-miss (not byte-exact) is NOT clean .."
printf '_No material security findings, none at all._' > "$TMP_DIR/near-miss.txt"
result="$(classify_response "$TMP_DIR/near-miss.txt" "$SECURITY_SENTINEL")"
assert_eq "ambiguous" "$result" "a near-miss paraphrase of the sentinel must not count as clean"

echo "== classify_response: (c) a normal finding set -> findings =="
{
  printf '> + var sql = $"SELECT * FROM packages WHERE name = '"'"'{name}'"'"'";\n\n'
  printf '**High:** SQL injection via string interpolation.\n'
} > "$TMP_DIR/finding.txt"
result="$(classify_response "$TMP_DIR/finding.txt" "$SECURITY_SENTINEL")"
assert_eq "findings" "$result" "a marker-bearing finding block must classify as findings"

# ═══════════════════════════════════════════════════════════════════════════
# Part 2 — confirm_clean: independent second-pass verification of a clean claim
# ═══════════════════════════════════════════════════════════════════════════

# confirm_clean's user-turn builder reads the capped diff main() would already
# have prepared by this point; called directly (outside main), supply it.
printf 'diff --git a/x b/x\n+dummy\n' > /tmp/ai-capped.txt

# Stub run_turn so no network call happens; responses are dequeued in call order.
STUB_QUEUE_RC=()
STUB_QUEUE_CONTENT=()
STUB_QUEUE_DONE_REASON=()
STUB_CALL_COUNT=0

reset_stub() { STUB_QUEUE_RC=(); STUB_QUEUE_CONTENT=(); STUB_QUEUE_DONE_REASON=(); STUB_CALL_COUNT=0; }
queue_response() { STUB_QUEUE_RC+=("$1"); STUB_QUEUE_CONTENT+=("$2"); STUB_QUEUE_DONE_REASON+=("${3:-stop}"); }

run_turn() {  # overrides the real one for the rest of this process
  local idx=$STUB_CALL_COUNT
  STUB_CALL_COUNT=$((STUB_CALL_COUNT + 1))
  local rc="${STUB_QUEUE_RC[$idx]:-1}"
  # shellcheck disable=SC2034  # consumed by looks_degenerate/confirm_clean in the sourced ai-review.sh
  LAST_DONE_REASON="${STUB_QUEUE_DONE_REASON[$idx]:-stop}"
  printf '%s' "${STUB_QUEUE_CONTENT[$idx]:-}" > "$3"
  return "$rc"
}

VERIFY_SENTINEL="_No findings survived verification._"

echo "== confirm_clean: independent pass agrees -> clean =="
reset_stub
queue_response 0 "$VERIFY_SENTINEL"
printf '%s' "$SECURITY_SENTINEL" > "$TMP_DIR/clean-claim.txt"
result="$(confirm_clean "$TMP_DIR/clean-claim.txt")"
assert_eq "clean" "$result" "verify pass echoing its own sentinel confirms clean"

echo "== confirm_clean: independent pass finds something pass-1 missed -> findings =="
reset_stub
queue_response 0 "> + var sql = \$\"SELECT * FROM x WHERE y = '{z}'\";
**High:** SQL injection."
result="$(confirm_clean "$TMP_DIR/clean-claim.txt")"
assert_eq "findings" "$result" "verify pass surfacing a grounded finding overrides the clean claim"
assert_contains "/tmp/ai-confirm.txt" "SQL injection" "the surfaced finding's content is left for the caller to route into the report"

echo "== confirm_clean: verify pass unreachable -> degraded, never silently clean =="
reset_stub
queue_response 1 ""
result="$(confirm_clean "$TMP_DIR/clean-claim.txt")"
assert_eq "degraded" "$result" "an unreachable verify pass must not fall back to trusting the clean claim"

echo "== confirm_clean: verify pass returns unrecognised marker-free prose -> degraded =="
reset_stub
queue_response 0 "Yeah, looks fine to me too."
result="$(confirm_clean "$TMP_DIR/clean-claim.txt")"
assert_eq "degraded" "$result" "an ambiguous confirmation response must not be trusted as clean either"

echo "== confirm_clean: SELF_VERIFY=0 -> explicit unconfirmed mode, no network call =="
reset_stub
# shellcheck disable=SC2034  # read by confirm_clean in the sourced ai-review.sh
SELF_VERIFY=0
result="$(confirm_clean "$TMP_DIR/clean-claim.txt")"
assert_eq "clean-unconfirmed" "$result" "SELF_VERIFY=0 yields the documented weaker clean-unconfirmed state"
assert_eq "0" "$STUB_CALL_COUNT" "SELF_VERIFY=0 must not invoke run_turn at all"
# shellcheck disable=SC2034
SELF_VERIFY=1

# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — end-to-end: drive the actual report path (has_findings -> emit_report)
# ═══════════════════════════════════════════════════════════════════════════

compute_diff() { printf 'diff --git a/x b/x\n+dummy\n' > /tmp/ai-diff.txt; echo 42; }
truncate_diff() { cp /tmp/ai-diff.txt /tmp/ai-capped.txt; }

echo "== main(): (a) marker-free non-sentinel output -> degraded report, never clean =="
# shellcheck disable=SC2034  # read by main/classify_response in the sourced ai-review.sh
PERSONA_FILE="ci/prompts/security.md"
REPORT_FILE="$TMP_DIR/report-ambiguous.md"
reset_stub
queue_response 0 "Everything checks out here, nothing to flag in this change."
( main ) || true
assert_contains "$REPORT_FILE" "(unverifiable response)" \
  "an ambiguous pass-1 reply must render as a degraded/no-signal state in the posted report"
assert_not_contains "$REPORT_FILE" "Everything checks out" \
  "the raw unverifiable content must not be echoed as if it were a certified clean review"

echo "== main(): (b) the exact sentinel, independently confirmed -> clean report =="
REPORT_FILE="$TMP_DIR/report-clean.md"
reset_stub
queue_response 0 "$SECURITY_SENTINEL"
queue_response 0 "$VERIFY_SENTINEL"
( main )
assert_contains "$REPORT_FILE" "$SECURITY_SENTINEL" "a confirmed-clean result posts the sentinel"
assert_not_contains "$REPORT_FILE" "(unverifiable response)" "a confirmed-clean result is not degraded"

echo "== main(): (b') the exact sentinel, confirmation pass unreachable -> degraded, not clean =="
REPORT_FILE="$TMP_DIR/report-clean-unconfirmed.md"
reset_stub
queue_response 0 "$SECURITY_SENTINEL"
queue_response 1 ""
( main ) || true
assert_contains "$REPORT_FILE" "(unverifiable response)" \
  "a clean claim that could not be independently confirmed must not be posted as a pass"

echo "== main(): (c) a real finding set -> findings survive to the report =="
REPORT_FILE="$TMP_DIR/report-findings.md"
reset_stub
finding_block="> + var sql = \$\"SELECT * FROM packages WHERE name = '{name}'\";

**High:** SQL injection via string interpolation."
queue_response 0 "$finding_block"
queue_response 0 "$finding_block"
( main )
assert_contains "$REPORT_FILE" "SQL injection" "a real, marker-bearing finding still reaches the report"

# ═══════════════════════════════════════════════════════════════════════════
echo
echo "ai-review-test.sh: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
