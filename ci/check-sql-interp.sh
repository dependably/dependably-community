#!/bin/sh
# Fails when a Dapper Execute*/Query* call site interpolates a string ($"…" or $@"…"),
# the classic SQL-injection vector this project bans in favour of @param placeholders.
#
# This is the CI-grep companion to the canonical gate, NoInterpolatedSqlComplianceTests.
# It honours the same `// rawsql: <reason>` opt-out — a compile-time-constant interpolated
# fragment (e.g. a whitelisted view / ORDER BY name) is allowed when the opening line, or one
# of the five lines above it, carries the marker. Keeping the two in lockstep is the whole
# point: without the opt-out this grep is strictly cruder than the test the code is written
# against, so a line the compliance test blesses would still redden the pipeline.
#
# Runs on GitLab (validate stage) and on the GitHub mirror from one script so neither forge
# drifts. POSIX sh: no bashisms, so it runs under Alpine ash and Ubuntu dash alike.
#
# Usage: ci/check-sql-interp.sh [root]   (root defaults to src)
set -eu

root="${1:-src}"

# Dapper method-call sites: ".Execute*(" / ".Execute*<" / ".Query*(" / ".Query*<".
# Anchoring on the leading '.' and a trailing '(' or '<' avoids false positives on
# substrings like "SearchQueryService". Second grep keeps only interpolated ones.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
grep -rnE '\.(Execute|Query)[A-Za-z]*\s*[(<]' "$root" --include="*.cs" 2>/dev/null \
    | grep -E '\$"|\$@"' > "$tmp" || true

status=0
while IFS=: read -r file line _; do
    [ -n "${file:-}" ] || continue

    # Opt-out window: the marker may sit on the hit line or up to five lines above it, since
    # the call often spans `await conn.ExecuteAsync(<newline> $"…")`. Mirrors HasOptOutComment.
    if [ "$line" -gt 5 ]; then start=$((line - 5)); else start=1; fi
    if sed -n "${start},${line}p" "$file" | grep -qi 'rawsql:'; then
        continue
    fi

    echo "ERROR: interpolated string in a Dapper call at $file:$line" >&2
    status=1
done < "$tmp"

if [ "$status" -ne 0 ]; then
    echo "String interpolation detected in a Dapper query call. Use a parameterized query" >&2
    echo "(@name placeholders). If the fragment is a compile-time constant (e.g. a whitelisted" >&2
    echo "view/ORDER BY name), annotate the opening line with '// rawsql: <reason>' — see" >&2
    echo "NoInterpolatedSqlComplianceTests." >&2
fi

exit "$status"
