#!/bin/sh
# Regression suite for ci/image-registry-guard.sh's mirror-host pin. Runs the REAL guard
# against throwaway fixtures: a copy of this repository's .gitlab-ci.yml (verbatim or with its
# DEP_IMAGE_REGISTRY default rewritten) plus a one-line Dockerfile. The fixtures live under
# mktemp -d, outside any git work tree, so the guard takes its `find` discovery path — the
# same path the CI job takes on its alpine image.
#
# POSIX sh, no bashisms: the guard job's image has no bash. Invoked as
# `sh ci/image-registry-guard-test.sh`.
#
# This file is itself a tracked shell script the guard scans, so it never spells out the
# tool invocations that guard looks for outside a comment line.
set -u

GUARD="$(cd "$(dirname "$0")" && pwd)/image-registry-guard.sh"
REAL_YAML="$(dirname "$GUARD")/../.gitlab-ci.yml"
PINNED='dependably.northwardlabs.ca'

TMP_DIR="$(mktemp -d)"
PASS=0
FAIL=0
# A suite that dies before its summary must never read as a pass: completion is tracked
# explicitly and the trap fails closed on anything that did not reach the summary line.
SUITE_COMPLETED=0
# shellcheck disable=SC2154 # rc is assigned inside the trap body itself
trap 'rc=$?
      if [ "${SUITE_COMPLETED:-0}" -ne 1 ]; then
        echo "image-registry-guard-test: FATAL -- aborted before the summary (reported rc=$rc); failing closed" >&2
        rc=1
      fi
      rm -rf "$TMP_DIR"
      exit "$rc"' EXIT

ok() { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1" >&2; }

# check <description> <command...>: records a pass when the command succeeds.
check() {
    desc="$1"
    shift
    if "$@"; then ok "$desc"; else bad "$desc"; fi
}

# check_not <description> <command...>: records a pass when the command fails.
check_not() {
    desc="$1"
    shift
    if "$@"; then bad "$desc"; else ok "$desc"; fi
}

make_fixture() {
    mkdir -p "$1"
    cp "$2" "$1/.gitlab-ci.yml"
    # shellcheck disable=SC2016 # the Dockerfile needs the literal, unexpanded reference
    printf '%s\n' 'FROM ${DEP_IMAGE_REGISTRY}/library/alpine:3' > "$1/Dockerfile"
}

# Sets RC, OUT, ERR for the last run.
run_guard() {
    OUT="$1.out"
    ERR="$1.err"
    if sh "$GUARD" "$1" >"$OUT" 2>"$ERR"; then RC=0; else RC=$?; fi
}

# mutate_default <src> <dst> <value-as-written-in-yaml>
# Rewrites the DEP_IMAGE_REGISTRY default, then proves the rewrite actually landed: exactly
# one such line, whose value is exactly what was written. A pattern that silently matches
# nothing therefore fails here, even for a case whose new value spells the same host as the
# original line, instead of letting a guard case pass vacuously.
mutate_default() {
    sed "s/^\([[:space:]]*DEP_IMAGE_REGISTRY:[[:space:]]*\).*\$/\1$3/" "$1" > "$2"
    n="$(grep -c '^[[:space:]]*DEP_IMAGE_REGISTRY:' "$2" || true)"
    value="$(sed -n 's/^[[:space:]]*DEP_IMAGE_REGISTRY:[[:space:]]*//p' "$2" | head -1)"
    if [ "$n" = "1" ] && [ "$value" = "$3" ]; then
        ok "fixture rewrite landed: the one DEP_IMAGE_REGISTRY line reads $3"
    else
        bad "fixture rewrite landed: the one DEP_IMAGE_REGISTRY line reads $3 (found $n, value '$value')"
    fi
}

# shellcheck disable=SC2329 # invoked through check/check_not
contains() { grep -qF -- "$2" "$1"; }

if [ ! -f "$GUARD" ] || [ ! -f "$REAL_YAML" ]; then
    echo "image-registry-guard-test: FATAL -- guard or .gitlab-ci.yml not found next to $0" >&2
    exit 1
fi

echo "image-registry-guard-test"

# T1 positive control: the verbatim pipeline file passes. Guards the environment — a fixture
# the guard cannot discover files in fails here instead of making the negative cases pass.
d="$TMP_DIR/t1"
make_fixture "$d" "$REAL_YAML"
run_guard "$d"
check "T1 verbatim .gitlab-ci.yml passes (rc=$RC)" [ "$RC" -eq 0 ]
check "T1 prints PASS" contains "$OUT" 'image-registry-guard: PASS'
refs="$(sed -n 's/^image-registry-guard: PASS — \([0-9][0-9]*\) image references.*/\1/p' "$OUT")"
check "T1 checked >= 25 references (got '${refs:-none}')" [ "${refs:-0}" -ge 25 ]

# T2 a changed DEP_IMAGE_REGISTRY default fails, naming both sides of the disagreement.
d="$TMP_DIR/t2"
mutate_default "$REAL_YAML" "$TMP_DIR/t2.yml" '"registry.example.invalid"'
make_fixture "$d" "$TMP_DIR/t2.yml"
run_guard "$d"
check "T2 foreign default fails (rc=$RC)" [ "$RC" -ne 0 ]
check "T2 reports the pin mismatch" contains "$ERR" 'does not match the host pinned'
check "T2 names the YAML value" contains "$ERR" 'registry.example.invalid'
check "T2 names the pinned value" contains "$ERR" "$PINNED"
check_not "T2 is a mismatch, not a failed parse" contains "$ERR" 'could not read'

# T3 a superstring of the pinned host is not the pinned host (prefix is not equality).
d="$TMP_DIR/t3"
mutate_default "$REAL_YAML" "$TMP_DIR/t3.yml" "\"$PINNED.example.com\""
make_fixture "$d" "$TMP_DIR/t3.yml"
run_guard "$d"
check "T3 superstring default fails (rc=$RC)" [ "$RC" -ne 0 ]
check "T3 reports the pin mismatch" contains "$ERR" 'does not match the host pinned'

# T4 must NOT fail: the pinned host unquoted and single-quoted is still the pinned host.
d="$TMP_DIR/t4a"
mutate_default "$REAL_YAML" "$TMP_DIR/t4a.yml" "$PINNED"
make_fixture "$d" "$TMP_DIR/t4a.yml"
run_guard "$d"
check "T4 unquoted pinned host passes (rc=$RC)" [ "$RC" -eq 0 ]
check "T4 unquoted prints PASS" contains "$OUT" 'image-registry-guard: PASS'

d="$TMP_DIR/t4b"
mutate_default "$REAL_YAML" "$TMP_DIR/t4b.yml" "'$PINNED'"
make_fixture "$d" "$TMP_DIR/t4b.yml"
run_guard "$d"
check "T4 single-quoted pinned host passes (rc=$RC)" [ "$RC" -eq 0 ]
check "T4 single-quoted prints PASS" contains "$OUT" 'image-registry-guard: PASS'

# T5 a missing default still fails closed on the parse.
d="$TMP_DIR/t5"
grep -v '^[[:space:]]*DEP_IMAGE_REGISTRY:' "$REAL_YAML" > "$TMP_DIR/t5.yml" || true
make_fixture "$d" "$TMP_DIR/t5.yml"
run_guard "$d"
check "T5 missing default fails (rc=$RC)" [ "$RC" -ne 0 ]
check "T5 reports the failed parse" contains "$ERR" 'could not read'

echo "image-registry-guard-test: $PASS passed, $FAIL failed"
SUITE_COMPLETED=1
[ "$FAIL" -eq 0 ] || exit 1
exit 0
