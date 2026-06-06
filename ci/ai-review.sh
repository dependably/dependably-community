#!/usr/bin/env bash
# Advisory LLM review of an MR diff via a local Ollama instance.
# Args: <persona_file> <report_file>. Invoked by the ai-review-* jobs in
# .gitlab-ci.yml. Signal-only: any infra/LLM hiccup writes an explanatory
# report and exits 0 so the pipeline never goes red on a flaky LAN host or
# model. Only a genuine config bug (missing arg / persona file) exits non-zero.
set -euo pipefail

PERSONA_FILE="${1:?usage: ai-review.sh <persona_file> <report_file>}"
REPORT_FILE="${2:?usage: ai-review.sh <persona_file> <report_file>}"
: "${OLLAMA_URL:?OLLAMA_URL must be set}"
: "${OLLAMA_MODEL:?OLLAMA_MODEL must be set}"
: "${CI_MERGE_REQUEST_IID:?this script only runs on merge_request_event pipelines}"

MAX_DIFF_BYTES="${AI_REVIEW_MAX_DIFF_BYTES:-120000}"
NUM_CTX="${AI_REVIEW_NUM_CTX:-16384}"
# Sampling tuned to avoid BOTH degeneration modes a 30B quantized coder falls
# into. A small non-zero temperature avoids greedy repetition loops. min_p
# tail-cuts improbable tokens, which is the robust guard against word-salad.
# repeat_penalty stays modest (1.1): values >~1.2 push the model so far off
# recently-seen tokens that it produces incoherent "random words" — the very
# failure the old 1.3 setting caused. num_predict caps a runaway's length, but
# the real fix is sampling + the post-hoc degeneration gate below.
TEMPERATURE="${AI_REVIEW_TEMPERATURE:-0.3}"
REPEAT_PENALTY="${AI_REVIEW_REPEAT_PENALTY:-1.1}"
MIN_P="${AI_REVIEW_MIN_P:-0.05}"
NUM_PREDICT="${AI_REVIEW_NUM_PREDICT:-1500}"
CURL_MAX_TIME="${AI_REVIEW_CURL_MAX_TIME:-1000}"
# Diff context width (git default is 3). More surrounding lines let the model
# verify a hunk against its neighbours instead of speculating about code it
# can't see ("not visible here, but…"). Kept modest: wider context grows the
# diff, so it reaches MAX_DIFF_BYTES / num_ctx sooner on large MRs. Full
# changed-file bodies would blow the 16K context window, so -U10 is the middle.
DIFF_CONTEXT="${AI_REVIEW_DIFF_CONTEXT:-10}"
# Self-verify: a second model pass that filters the first pass's findings,
# keeping only those grounded in a quoted diff line. Cuts false positives from
# a weak model. On by default; set AI_REVIEW_SELF_VERIFY=0 to disable. The
# verify persona is shared across all four lenses.
SELF_VERIFY="${AI_REVIEW_SELF_VERIFY:-1}"
VERIFY_PERSONA_FILE="${AI_REVIEW_VERIFY_PERSONA_FILE:-ci/prompts/verify.md}"
# Deterministic post-filter. A single weak model cannot reliably filter its own
# output (the verify pass rubber-stamps its own family's speculation), so these
# guards run in code, not in the model: drop findings phrased as speculation
# (hedge words), cap the number of findings, and cap total report length. These
# are heuristics — they can drop a genuine but tentatively-worded finding — but
# for an advisory check, suppressing confident-sounding noise wins.
MAX_FINDINGS="${AI_REVIEW_MAX_FINDINGS:-5}"
MAX_REPORT_CHARS="${AI_REVIEW_MAX_REPORT_CHARS:-2200}"
BASE_URL="${OLLAMA_URL%/}"
# Lens label shown in report/comment titles (e.g. "Security"). Set per job via
# AI_REVIEW_LABEL; falls back to the report filename stem.
REVIEW_LABEL="${AI_REVIEW_LABEL:-${REPORT_FILE%.md}}"

[ -f "$PERSONA_FILE" ] || { echo "ERROR: persona '$PERSONA_FILE' not found" >&2; exit 1; }

# Write the final report. Used for both success and graceful skips so the
# artifact always exists. Body is a printf arg (never the format string), so
# % / backticks / $ in model output are inert.
emit_report() {  # <status-suffix> <body-text>
  # Title carries the lens label so each report/comment is self-identifying
  # (e.g. "AI review — Security"); $1 is an optional state suffix like " (skipped)".
  # Backticks are literal Markdown; the format string must not expand (values
  # arrive as positional args), so single quotes are intentional.
  # shellcheck disable=SC2016
  printf '# AI review — %s%s\n\n_Model `%s` · MR !%s · %s UTC_\n\n%s\n' \
    "$REVIEW_LABEL" "$1" "$OLLAMA_MODEL" "$CI_MERGE_REQUEST_IID" "$(date -u +%Y-%m-%dT%H:%M:%S)" "$2" \
    > "$REPORT_FILE"
  # Also echo the report into the job log, inside an expanded collapsible GitLab
  # section, so it's readable directly in CI without downloading the artifact.
  local ts; ts=$(date +%s)
  printf '\033[0Ksection_start:%s:ai_review_report[collapsed=false]\r\033[0KAI review — %s\n' "$ts" "$REVIEW_LABEL"
  cat "$REPORT_FILE"
  printf '\033[0Ksection_end:%s:ai_review_report\r\033[0K\n' "$ts"
}

# (a) Compute the MR diff, robust to GitLab's shallow clone.
# CI_MERGE_REQUEST_DIFF_BASE_SHA *is* the merge-base, so a two-dot base..head
# diff needs only the two commit objects (no ancestry walk). A targeted
# depth=1 fetch of the base is far cheaper than GIT_DEPTH:0. Echoes byte count.
compute_diff() {
  local base="${CI_MERGE_REQUEST_DIFF_BASE_SHA:-}" head="${CI_COMMIT_SHA:-HEAD}"
  if [ -n "$base" ] && ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
    git fetch --no-tags --depth=1 origin "$base" 2>/dev/null || true
  fi
  if [ -n "$base" ] && git cat-file -e "${base}^{commit}" 2>/dev/null; then
    git diff --no-color -U"$DIFF_CONTEXT" "$base" "$head" > /tmp/ai-diff.txt
  else
    echo "WARN: MR base SHA unavailable; falling back to HEAD~1" >&2
    git diff --no-color -U"$DIFF_CONTEXT" "HEAD~1" "$head" > /tmp/ai-diff.txt 2>/dev/null || : > /tmp/ai-diff.txt
  fi
  wc -c < /tmp/ai-diff.txt | tr -d ' '
}

# (b) Cap the diff to fit the model context; mark truncation visibly.
truncate_diff() {  # <byte-count>
  if [ "$1" -le "$MAX_DIFF_BYTES" ]; then
    cp /tmp/ai-diff.txt /tmp/ai-capped.txt
    return
  fi
  head -c "$MAX_DIFF_BYTES" /tmp/ai-diff.txt > /tmp/ai-capped.txt
  sed -i '$ d' /tmp/ai-capped.txt 2>/dev/null || true   # drop trailing partial line
  printf '\n\n[... diff truncated at %s of %s bytes; review is partial ...]\n' \
    "$MAX_DIFF_BYTES" "$1" >> /tmp/ai-capped.txt
  echo "WARN: diff truncated ($1 -> $MAX_DIFF_BYTES bytes)" >&2
}

# (c) Build the /api/chat body with jq --rawfile so file content (quotes,
# backticks, newlines, control bytes) can NEVER break the JSON. Both the system
# persona and the user turn are passed as files so the same builder serves the
# review pass and the verify pass.
build_request() {  # <system_file> <user_file>
  jq -n \
    --arg model "$OLLAMA_MODEL" \
    --argjson ctx "$NUM_CTX" \
    --argjson temp "$TEMPERATURE" \
    --argjson predict "$NUM_PREDICT" \
    --argjson rpen "$REPEAT_PENALTY" \
    --argjson minp "$MIN_P" \
    --rawfile sys "$1" \
    --rawfile usr "$2" \
    '{model: $model, stream: false,
      options: {temperature: $temp, num_ctx: $ctx, num_predict: $predict,
                repeat_penalty: $rpen, repeat_last_n: 512, min_p: $minp},
      messages: [
        {role: "system", content: $sys},
        {role: "user", content: $usr}
      ]}' > /tmp/ai-req.json
}

# Compose the review-pass user turn (instruction + fenced diff) into a file.
build_review_user() {  # <out_file>
  { printf 'Review this unified diff. Reply in GitLab-flavored Markdown.\n\n```diff\n';
    cat /tmp/ai-capped.txt;
    printf '\n```\n'; } > "$1"
}

# Compose the verify-pass user turn: the first pass's candidate findings plus
# the same diff, for the model to filter against.
build_verify_user() {  # <candidates_file> <out_file>
  { printf '## Candidate findings (from a first-pass reviewer)\n\n';
    cat "$1";
    printf '\n\n## The unified diff under review\n\n```diff\n';
    cat /tmp/ai-capped.txt;
    printf '\n```\n'; } > "$2"
}

# Heuristic degeneration detector for one model turn's output. Catches the
# repetition-loop mode (a few tokens repeated to the cap) via a low unique-word
# ratio on a long output. Word-salad is harder to detect textually, so it is
# caught upstream by the done_reason=="length" signal (a coherent review stops
# well before the cap). Returns 0 = degenerate, 1 = looks fine.
looks_degenerate() {  # <content_file> <done_reason>
  local words uniq
  words=$(wc -w < "$1" | tr -d ' ')
  [ "${words:-0}" -gt 0 ] || return 1   # empty is handled separately, not "degenerate"
  uniq=$(tr -s '[:space:]' '\n' < "$1" | tr '[:upper:]' '[:lower:]' | sort | uniq | grep -c .)
  # Long output with very low lexical variety => repetition loop.
  if awk -v u="$uniq" -v w="$words" 'BEGIN{ exit !(w>=80 && (u/w)<0.30) }'; then
    echo "WARN: output looks degenerate (repetition): $uniq unique / $words words" >&2
    return 0
  fi
  # Hit the hard token cap without a natural stop => almost certainly runaway.
  if [ "$2" = "length" ] && [ "${words:-0}" -ge 400 ]; then
    echo "WARN: output hit num_predict cap without stopping (done_reason=length, $words words)" >&2
    return 0
  fi
  return 1
}

# Run one model turn. $1=system file, $2=user file. On HTTP/JSON success, writes
# the message content to $3 and the done_reason to global LAST_DONE_REASON, and
# returns 0. Returns non-zero on infra failure (unreachable / non-JSON).
LAST_DONE_REASON=""
run_turn() {  # <system_file> <user_file> <out_content_file>
  build_request "$1" "$2"
  call_ollama || return 1
  if ! jq -e . /tmp/ai-resp.json >/dev/null 2>&1; then
    echo "ERROR: Ollama returned HTTP 200 but the body is not valid JSON:" >&2
    head -c 800 /tmp/ai-resp.json >&2; echo >&2
    return 2
  fi
  LAST_DONE_REASON=$(jq -r '.done_reason // ""' /tmp/ai-resp.json)
  jq -r '.message.content // ""' /tmp/ai-resp.json > "$3"
  return 0
}

# (d) Call Ollama; dt-publish-style status handling with explicit 000/404.
call_ollama() {
  local status
  status=$(curl -sS --max-time "$CURL_MAX_TIME" -o /tmp/ai-resp.json -w '%{http_code}' \
    -X POST "$BASE_URL/api/chat" -H 'Content-Type: application/json' \
    --data-binary @/tmp/ai-req.json) || status="000"
  case "$status" in
    200) return 0 ;;
    000) echo "ERROR: Ollama at $BASE_URL unreachable or timed out" >&2; return 1 ;;
    404) echo "ERROR: $BASE_URL/api/chat returned 404 — is model '$OLLAMA_MODEL' pulled?" >&2; return 1 ;;
    *)   echo "ERROR: Ollama returned HTTP $status:" >&2; cat /tmp/ai-resp.json >&2; return 1 ;;
  esac
}

# (e) Post or UPDATE one MR comment per lens (idempotent via a hidden marker so
# each pipeline updates the same note instead of spamming). Best-effort: a
# posting failure logs but never fails the job. Skipped cleanly when no token,
# so the feature degrades to artifact-only until the secret is configured.
post_or_update_note() {
  [ -n "${AI_REVIEW_GITLAB_TOKEN:-}" ] || { echo "AI_REVIEW_GITLAB_TOKEN unset; artifact-only (no MR comment)"; return 0; }
  local marker="<!-- ai-review:${REPORT_FILE} -->"
  jq -n --arg b "${marker}"$'\n'"$(cat "$REPORT_FILE")" '{body: $b}' > /tmp/ai-note.json

  # Resolve a working API base. Some instances set external_url (hence
  # CI_API_V4_URL) to http while the v4 API answers only over https behind a
  # proxy — every call then route-misses to an HTML 404. Probe the notes
  # endpoint over the configured base and its https variant; use whichever
  # authenticates (HTTP 200). AI_REVIEW_API_URL overrides the base entirely.
  local primary="${AI_REVIEW_API_URL:-$CI_API_V4_URL}"
  local bases=("$primary")
  if [ "${primary/#http:/https:}" != "$primary" ]; then bases+=("${primary/#http:/https:}"); fi

  local base notes_url list_status api="" id=""
  for base in "${bases[@]}"; do
    notes_url="$base/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
    list_status=$(curl -sS --max-time 60 -o /tmp/ai-notes.json -w '%{http_code}' \
      -H "PRIVATE-TOKEN: $AI_REVIEW_GITLAB_TOKEN" "$notes_url?per_page=100") || list_status="000"
    echo "MR note probe: GET $notes_url -> HTTP $list_status"
    if [ "$list_status" = "200" ]; then api="$base"; break; fi
  done
  if [ -z "$api" ]; then
    echo "WARN: no working GitLab API base for MR notes (tried: ${bases[*]}). Check AI_REVIEW_GITLAB_TOKEN (api scope + Reporter/Developer) and CI_API_V4_URL, or set AI_REVIEW_API_URL." >&2
    return 0
  fi

  local url="$api/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
  id=$(jq -r --arg m "$marker" 'if type=="array" then (map(select(.body | startswith($m))) | (.[0].id // empty)) else empty end' /tmp/ai-notes.json 2>/dev/null || true)
  local method="POST" target="$url"
  if [ -n "$id" ]; then method="PUT"; target="$url/$id"; fi

  # curl exits 0 on ANY completed HTTP response — including 401/403/4xx — so we
  # must inspect %{http_code}, not curl's exit, to know if GitLab accepted it.
  # On failure, dump the response body (GitLab returns a JSON {"message": ...}).
  local status
  status=$(curl -sS --max-time 60 -o /tmp/ai-note.out -w '%{http_code}' \
    -X "$method" "$target" \
    -H "PRIVATE-TOKEN: $AI_REVIEW_GITLAB_TOKEN" -H 'Content-Type: application/json' \
    --data-binary @/tmp/ai-note.json) || status="000"
  case "$status" in
    200|201) if [ -n "$id" ]; then echo "MR note updated (id $id, HTTP $status)"; else echo "MR note posted (HTTP $status)"; fi ;;
    000)     echo "WARN: MR note $method unreachable or timed out (curl error)" >&2 ;;
    *)       echo "WARN: MR note $method rejected by GitLab — HTTP $status:" >&2; head -c 800 /tmp/ai-note.out >&2; echo >&2 ;;
  esac
}

# Does the model output contain at least one finding? True if it has a quoted
# diff line (our prompts require findings to quote one) OR a finding-start marker
# (bullet / numbered / header / "Finding|Problem|Issue|Bug" label). This is
# format-independent and stays false for a clean "_No material findings._"
# message, which has none of these. Far more robust than counting one bullet style.
has_findings() {  # <file>; exit 0 if the output contains >=1 finding
  grep -qE '^[[:space:]]*>' "$1" && return 0
  grep -qiE '^[[:space:]]*([-*+] |#{1,6} |[0-9]+[.)] |(finding|problem|issue|bug)[ :0-9])' "$1"
}

# Deterministic finding filter (busybox-awk compatible — no gawk extensions).
# Segments the output into finding blocks, robust to the formats the model
# actually emits ("- bullet", "Finding N:", numbered, header, or a quote-led
# block), drops a block whose prose (non-quote lines) reads as speculation
# rather than a concrete problem, and keeps at most MAX_FINDINGS. Quote lines
# (`> ...`, the cited diff) are exempt from the hedge check — a quoted line may
# contain "may" without the finding being speculative. Echoes filtered Markdown;
# if nothing survives, echoes the single token @@NONE@@.
filter_findings() {  # <file>
  awk -v max="$MAX_FINDINGS" '
    function hedged(s,   l) {
      l = tolower(s)
      return (l ~ /(^|[^a-z])(may|might|could|would|should|possibly|potentially|consider|presumably|seems|appears|perhaps|likely|suggests)([^a-z]|$)/) \
          || (l ~ /(fail silently|increase[sd]? risk|be improved|be better|be more|more robust|more flexible|is inconsistent|no enforcement|no clear|reliance|relies entirely|limiting flex|in theory|can lead to|lack of|hardcoded without|without (a )?(clear|dynamic|proper|explicit)|rather than allowing)/)
    }
    # A new finding starts at a bullet, header, numbered item, a "Finding/Problem/
    # Issue/Bug" label, or a quote line that opens a paragraph (prev line blank).
    # NOT on inline **bold** like **Impact:**, which continues the current finding.
    function is_start(line, pblank,   l) {
      l = tolower(line)
      if (line ~ /^[[:space:]]*[-*+] /) return 1
      if (line ~ /^#{1,6} /) return 1
      if (line ~ /^[[:space:]]*[0-9]+[.)][[:space:]]/) return 1
      if (l ~ /^(finding|problem|issue|bug)[ :0-9]/) return 1
      if (pblank && line ~ /^[[:space:]]*>/) return 1
      return 0
    }
    function flush() {
      if (cur == "") return
      if (kept < max && drop == 0) { printf "%s", cur; kept++ }
      cur = ""; drop = 0
    }
    BEGIN { kept = 0; drop = 0; cur = ""; pblank = 1 }
    {
      line = $0
      if (line ~ /^[[:space:]]*$/)        { if (cur != "") cur = cur line "\n"; pblank = 1; next }
      if (line ~ /^[[:space:]]*-{3,}[[:space:]]*$/) { flush(); pblank = 1; next }  # --- separator
      if (is_start(line, pblank)) flush()
      cur = cur line "\n"
      if (line !~ /^[[:space:]]*>/ && hedged(line)) drop = 1
      pblank = 0
    }
    END { flush(); if (kept == 0) print "@@NONE@@" }
  ' "$1"
}

main() {
  local bytes
  bytes=$(compute_diff)

  if [ "${bytes:-0}" -eq 0 ]; then
    echo "No reviewable diff for MR !$CI_MERGE_REQUEST_IID — skipping model call."
    emit_report " (skipped)" "No code changes detected in this merge request."
    post_or_update_note
    exit 0
  fi

  truncate_diff "$bytes"

  # ── Pass 1: the lens review ────────────────────────────────────────────────
  build_review_user /tmp/ai-user1.txt
  local rc=0
  run_turn "$PERSONA_FILE" /tmp/ai-user1.txt /tmp/ai-content1.txt || rc=$?
  if [ "$rc" -eq 1 ]; then
    emit_report " (unavailable)" \
      "The local LLM at \`$BASE_URL\` could not be reached or returned an error (see job log). This check is advisory and does not block the merge."
    post_or_update_note; exit 0
  fi
  if [ "$rc" -ne 0 ]; then
    emit_report " (bad response)" "Ollama returned a non-JSON response (see job log above)."
    post_or_update_note; exit 0
  fi

  # Degeneration gate: a runaway / word-salad pass-1 is suppressed, never posted
  # as if it were a review. Signal-only philosophy: emit an explanatory artifact.
  if looks_degenerate /tmp/ai-content1.txt "$LAST_DONE_REASON"; then
    emit_report " (low-confidence, suppressed)" \
      "The model produced degenerate output (runaway / repetition; \`done_reason=$LAST_DONE_REASON\`). It was suppressed rather than posted. This check is advisory and does not block the merge."
    post_or_update_note; exit 0
  fi

  local content; content=$(cat /tmp/ai-content1.txt)
  [ -n "$content" ] || { content="_The model returned no content._"; emit_report "" "$content"; post_or_update_note; exit 0; }

  # No quoted findings => a clean "nothing material" result (or prose). Nothing to
  # verify or filter; post it as-is, with no misleading footer.
  if ! has_findings /tmp/ai-content1.txt; then
    emit_report "" "$content"
    post_or_update_note
    echo "AI review report written to $REPORT_FILE (no findings)"
    return 0
  fi

  # ── Pass 2: self-verify — filter pass-1 findings against the diff ───────────
  # The verify output (or pass-1 if verify is unavailable) becomes the working
  # set; the deterministic filter below is the real backstop either way.
  local verified="no"
  cp /tmp/ai-content1.txt /tmp/ai-working.txt
  if [ "$SELF_VERIFY" = "1" ] && [ -f "$VERIFY_PERSONA_FILE" ]; then
    build_verify_user /tmp/ai-content1.txt /tmp/ai-user2.txt
    local vrc=0
    run_turn "$VERIFY_PERSONA_FILE" /tmp/ai-user2.txt /tmp/ai-content2.txt || vrc=$?
    if [ "$vrc" -eq 0 ] && ! looks_degenerate /tmp/ai-content2.txt "$LAST_DONE_REASON" \
       && [ -s /tmp/ai-content2.txt ]; then
      cp /tmp/ai-content2.txt /tmp/ai-working.txt; verified="yes"
    else
      echo "WARN: verify pass unavailable/empty/degenerate; relying on the deterministic filter." >&2
    fi
  elif [ "$SELF_VERIFY" = "1" ]; then
    echo "WARN: verify persona '$VERIFY_PERSONA_FILE' not found; relying on the deterministic filter." >&2
  fi

  # If verification reduced the set to a no-findings / prose result (no quotes),
  # post it clean — no speculation-filter footer on a "nothing found" message.
  if ! has_findings /tmp/ai-working.txt; then
    emit_report "" "$(cat /tmp/ai-working.txt)"
    post_or_update_note
    echo "AI review report written to $REPORT_FILE (no findings after verify)"
    return 0
  fi

  # ── Deterministic filter: drop speculation, cap count ──────────────────────
  filter_findings /tmp/ai-working.txt > /tmp/ai-filtered.txt
  if grep -qx '@@NONE@@' /tmp/ai-filtered.txt; then
    emit_report "" "_No material findings (after verification and speculation filtering)._"
    post_or_update_note
    echo "AI review report written to $REPORT_FILE (all findings filtered out)"
    return 0
  fi
  content=$(cat /tmp/ai-filtered.txt)

  # Cap total length so a stray long finding can't produce a wall of text.
  if [ "${#content}" -gt "$MAX_REPORT_CHARS" ]; then
    content="$(printf '%s' "$content" | head -c "$MAX_REPORT_CHARS")"$'\n\n_[report truncated]_'
  fi

  local footer
  if [ "$verified" = "yes" ]; then
    footer=$'\n\n---\n_Self-verified against the diff, then speculation-filtered (≤'"$MAX_FINDINGS"$' findings)._'
  else
    footer=$'\n\n---\n_Verify pass unavailable; speculation-filtered (≤'"$MAX_FINDINGS"$' findings)._'
  fi

  emit_report "" "${content}${footer}"
  post_or_update_note
  echo "AI review report written to $REPORT_FILE"
}

main "$@"
