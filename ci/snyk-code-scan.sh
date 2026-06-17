#!/usr/bin/env bash
# Snyk Code (SAST) baseline gate.
#
# Snyk Code has no per-finding ignore that the CLI honours: `.snyk` supports only
# whole-file `exclude.code`, and surgical per-finding ignores live in the Snyk
# platform ("consistent ignores", which need `--report` + a service account).
# Inline `// deepcode ignore` markers are honoured by Snyk's IDE plugin and its
# merge-request integration, but NOT by `snyk code test` — so the bare CLI (and
# the MCP `snyk_code_scan`, and any CI invocation) re-reports every already-
# triaged false positive, burying any genuinely new finding.
#
# This script closes that gap for the CLI and CI: it runs `snyk code test`, then
# fails ONLY on findings absent from ci/snyk-code-baseline.json — a committed set
# of identities for the known, already-triaged false positives. A NEW finding
# in any file (including a real bug in a file that also hosts a baselined FP)
# still surfaces and fails the gate, so detection is not weakened.
#
# Identity key: rule + file + Snyk's path-based identity fingerprint
# (`fingerprints["1"]`), NOT the primary content fingerprint (`fingerprints["0"]`).
# The content fingerprint folds in surrounding lines, so any edit to a file that
# hosts a baselined FP shifts that finding's hash — making it read as "new" and
# the old one as "stale", failing the gate on cosmetic line moves. The identity
# fingerprint encodes the data-flow path structure and is line-independent, so
# routine edits no longer drift the baseline. Trade-off: two findings of the SAME
# rule in the SAME file with an identical flow shape share one identity, so an
# extra instance of an already-baselined FP class can be absorbed silently — an
# accepted weakening, since every baselined rule here is a benign FP class. A new
# finding of any non-baselined rule has no identity to collide with and surfaces.
#
# Usage:
#   ci/snyk-code-scan.sh           Scan; exit 1 if any finding is NOT on the baseline.
#   ci/snyk-code-scan.sh --update  Re-triage: regenerate the baseline from the current
#                                  scan. Review the diff before committing.
#
# Exit: 0 = clean (only known FPs, or none); 1 = new finding(s); 2 = tooling/scan error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="$ROOT/ci/snyk-code-baseline.json"

command -v snyk >/dev/null 2>&1 || { echo "error: snyk CLI not on PATH" >&2; exit 2; }
command -v jq   >/dev/null 2>&1 || { echo "error: jq not on PATH" >&2; exit 2; }

SARIF="$(mktemp)"; CUR="$(mktemp)"
trap 'rm -f "$SARIF" "$CUR"' EXIT

# `snyk code test` exits 1 when issues exist and 0 when none — both are healthy
# scans. The authoritative success signal is a SARIF carrying .runs[].results;
# anything else (auth failure, no supported files, network) is a real error.
cd "$ROOT"
set +e
snyk code test --sarif-file-output="$SARIF" >/dev/null 2>&1
set -e
if ! jq -e '.runs[0].results' "$SARIF" >/dev/null 2>&1; then
  echo "error: snyk code test produced no valid SARIF — check auth (snyk auth /" >&2
  echo "       SNYK_TOKEN), folder trust (snyk trust), and connectivity, then retry." >&2
  exit 2
fi

# One compact record per finding. `id` is the matching key: rule + file + Snyk's
# line-independent identity fingerprint (`fingerprints["1"]`). `line` is retained
# for human triage only — it is not part of the key, so line moves don't drift it.
jq '[ .runs[0].results[] | {
        id:   "\(.ruleId)|\(.locations[0].physicalLocation.artifactLocation.uri)|\(.fingerprints["1"])",
        rule: .ruleId,
        file: .locations[0].physicalLocation.artifactLocation.uri,
        line: .locations[0].physicalLocation.region.startLine,
        text: (.message.text | gsub("\\s+"; " ") | .[0:130])
      } ] | sort_by(.file, .line)' "$SARIF" > "$CUR"

if [[ "${1:-}" == "--update" ]]; then
  jq '{ _comment: "Known Snyk Code false positives — each already triaged, with an inline // deepcode ignore at the site. The snyk CLI does not honour those inline markers, so this identity set keeps ci/snyk-code-scan.sh from re-flagging them. Each id is rule|file|<line-independent identity fingerprint>, so cosmetic line moves do not drift the baseline. Per-rule rationale: CONTRIBUTING.md > Static analysis (Snyk Code). Regenerate after re-triage: ci/snyk-code-scan.sh --update.",
        count: length,
        fingerprints: . }' "$CUR" > "$BASELINE"
  echo "baseline written: $(jq 'length' "$CUR") finding(s) -> ci/snyk-code-baseline.json"
  exit 0
fi

[[ -f "$BASELINE" ]] || { echo "error: $BASELINE missing — generate it with: ci/snyk-code-scan.sh --update" >&2; exit 2; }

new="$(jq --argjson known "$(jq '[.fingerprints[].id]' "$BASELINE")" \
        'map(select(.id as $f | $known | index($f) | not))' "$CUR")"
stale="$(jq --argjson cur "$(jq 'map(.id)' "$CUR")" \
        '[.fingerprints[] | select(.id as $f | $cur | index($f) | not)]' "$BASELINE")"

total="$(jq 'length' "$CUR")"
known_n="$(jq '.fingerprints | length' "$BASELINE")"
new_n="$(jq 'length' <<<"$new")"
stale_n="$(jq 'length' <<<"$stale")"

echo "Snyk Code: ${total} finding(s) — ${known_n} baselined, ${new_n} new, ${stale_n} stale."

if [[ "$stale_n" -gt 0 ]]; then
  echo "note: ${stale_n} baseline entry(ies) no longer present (FP fixed or moved); run --update to prune." >&2
fi

if [[ "$new_n" -gt 0 ]]; then
  {
    echo ""
    echo "NEW Snyk Code finding(s) not on the baseline — triage required:"
    jq -r '.[] | "  [\(.rule)] \(.file):\(.line)\n      \(.text)"' <<<"$new"
    echo ""
    echo "If a finding is a genuine false positive: add an inline // deepcode ignore at the"
    echo "site (keeps the IDE/MR view quiet) AND run: ci/snyk-code-scan.sh --update"
  } >&2
  exit 1
fi

echo "OK — every finding is a known, triaged false positive."
exit 0
