#!/usr/bin/env sh
# Run a ZAP scan, retrying ONLY when the ZAP daemon failed to come up.
#
# zap-api-scan.py / zap-full-scan.py start a ZAP daemon inside the job container and wait for it
# to accept connections. Under runner contention that wait sometimes expires:
#
#   I/O error: [Errno 5] Failed to connect to ZAP after 600 seconds
#
# The scanner then exits 1. That is a script_failure, so the pipeline-level
# `retry: when: [runner_system_failure, stuck_or_timeout_failure]` does not cover it, and a
# REQUIRED gate goes red for a reason that has nothing to do with the application. Every
# occurrence so far has needed a manual retry, and every manual retry has passed.
#
# The blunt fix — job-level `retry: when: script_failure` — is deliberately NOT used. These are
# security gates. Re-running one on ANY non-zero exit also re-runs it on a genuine finding, and a
# gate that gets three chances to come back green can be worn down by attrition. A degraded
# security lens must never end up reading as clean.
#
# So this retries on exactly one signature — the daemon-startup timeout — and fails immediately on
# anything else: a real alert, an OpenAPI import error, a gate rejection. Each attempt re-runs the
# scan from scratch, since a half-started daemon leaves no reusable state.
#
# Usage:  sh ci/zap-scan-retry.sh <scan-command> [args...]

set -eu

ATTEMPTS="${ZAP_START_RETRIES:-3}"
STARTUP_FAILURE='Failed to connect to ZAP after'
LOG=/tmp/zap-scan-attempt.log

attempt=1
while :; do
    # Output is captured to a file rather than piped to tee: in a pipeline the shell reports
    # tee's status, not the scanner's, which would make every attempt look like a success. The
    # log is echoed verbatim afterwards so the job trace is unchanged.
    if "$@" >"$LOG" 2>&1; then
        cat "$LOG"
        exit 0
    fi

    cat "$LOG"

    if ! grep -q "$STARTUP_FAILURE" "$LOG"; then
        echo "zap-scan-retry: scan failed for a reason other than daemon startup — not retrying." >&2
        exit 1
    fi

    if [ "$attempt" -ge "$ATTEMPTS" ]; then
        echo "zap-scan-retry: ZAP daemon failed to start on $ATTEMPTS attempt(s) — failing the job." >&2
        exit 1
    fi

    echo "zap-scan-retry: ZAP daemon did not start (attempt $attempt/$ATTEMPTS); retrying." >&2
    attempt=$((attempt + 1))
done
