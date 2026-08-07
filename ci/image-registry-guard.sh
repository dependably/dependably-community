#!/bin/sh
# Image-registry guard: every container image the GitLab pipeline pulls resolves through
# the DEP_IMAGE_REGISTRY mirror, never straight from a public registry.
#
# The rule exists because the runners cannot reach Docker Hub's CDN, but the failures that
# taught us so were not in any `FROM` line — they were implicit pulls made by the build
# tooling itself. `docker buildx create` boots BuildKit from its own image; BuildKit resolves
# a `# syntax=` directive from docker.io before it reads the first instruction. An audit of
# the Dockerfiles came back clean while the job kept failing. So this guard scans every place
# an image reference is minted, not just the obvious ones:
#
#   .gitlab-ci.yml     image: / services: name: / any *IMAGE* variable (YAML or shell) /
#                      `docker run|pull` / `--driver-opt image=` / `buildx create`
#   Dockerfiles        FROM, `# syntax=` directives, and *IMAGE* ARG defaults (the public
#                      fallback a local or GitHub build uses, invisible until you look)
#   compose files      image:
#   tracked shell      `docker run|pull`, `buildx create`
#
# Opt out a deliberate public pull with `# image-registry-ok: <reason>` on the line itself or
# in the five lines above it. The reason is required — a bare marker is rejected as malformed,
# matching the `backcompat-ok` gate. For a `# syntax=` directive the window runs *downward*
# instead: a parser directive is only honoured on line 1, and a comment above it silently
# disables it (the build keeps working, on a different frontend).
#
# .github/workflows/ is deliberately NOT scanned: it runs on GitHub-hosted runners with no
# route to the private registry, publishing to ghcr.io. Mirroring it would break the public
# mirror build, so the exclusion is a decision, not an oversight.
#
# How a reference is judged, in order:
#   1. begins with the mirror host (prefix, never substring — `<host>.evil.com/x` is not the
#      mirror), or mentions $DEP_IMAGE_REGISTRY  -> pass
#   2. is a bare variable expansion -> pass only if that variable is itself declared with a
#      value this guard checked. An unknown variable FAILS: "it starts with a dollar" is not
#      evidence of anything, and treating it as such was a hole wide enough to drive a
#      `docker pull "$SCANNER_REF"` through.
#   3. otherwise -> fail.
#
# Known limit, stated rather than hidden: a reference assembled at runtime from fragments, or
# supplied by a CI/CD variable that exists only in the GitLab UI, is invisible to any static
# scan. Syntax is what a grep can see; that is the honest boundary.
#
# Runs on the GitLab validate stage. POSIX sh, no bashisms — Alpine ash and dash alike.
#
# Usage: ci/image-registry-guard.sh [repo-root]   (defaults to the working directory)
set -eu

root="${1:-.}"
cd "$root"

MIRROR_VAR='DEP_IMAGE_REGISTRY'

# Files outside the pipeline (compose) cannot expand a CI variable, so they name the mirror
# host literally. Read the canonical value out of .gitlab-ci.yml rather than hardcoding it,
# so overriding the mirror in one place keeps this guard honest. Fail closed when it cannot
# be read: without the host every literal reference would be judged against a pattern that
# matches nothing, reddening the pipeline for no reason.
MIRROR_HOST="$(sed -n 's/^[[:space:]]*DEP_IMAGE_REGISTRY:[[:space:]]*//p' .gitlab-ci.yml 2>/dev/null \
    | head -1 | sed -e 's/[[:space:]].*$//' -e 's/^["'\'']//' -e 's/["'\'']$//')"
if [ -z "$MIRROR_HOST" ]; then
    echo "image-registry-guard: FAILED — could not read the $MIRROR_VAR default from .gitlab-ci.yml." >&2
    echo "Literal mirror references cannot be recognised without it." >&2
    exit 1
fi

candidates="$(mktemp)"
imagevars="$(mktemp)"
trap 'rm -f "$candidates" "$imagevars"' EXIT

# Shared awk helpers, textually included by each scanner below.
AWKLIB='
function shaped(s) {
    # An image reference is a digest, a path, or the bare `name:tag` form. That last case is
    # what makes an official-library pull (alpine:3, postgres:16) visible — the commonest way
    # to reach Docker Hub, and the one a slash-or-digest test walks straight past.
    return (s ~ /@sha256:/ || s ~ /\// || s ~ /^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._-]*$/)
}
function unquote(s) {
    gsub(/^["]|["]$/, "", s); gsub(/^\047|\047$/, "", s); return s
}
function cmd_image(line,   n, arr, i, t, seen) {
    # First non-flag token after `run`/`pull`, so
    # `docker run --privileged --rm IMG --install arm64` yields IMG.
    n = split(line, arr, /[[:space:]]+/); seen = 0
    for (i = 1; i <= n; i++) {
        t = arr[i]
        if (t == "") continue
        if (!seen) { if (t == "run" || t == "pull") seen = 1; continue }
        if (substr(t, 1, 1) == "-") continue
        return unquote(t)
    }
    return ""
}
function driver_image(line,   v) {
    if (line !~ /--driver-opt[[:space:]]+image=/) return ""
    v = line
    sub(/.*--driver-opt[[:space:]]+image=/, "", v)
    sub(/[[:space:]].*$/, "", v)
    return unquote(v)
}
'

# --- .gitlab-ci.yml ------------------------------------------------------------------------
# MODE=vars emits the names of *IMAGE* variables; MODE=scan emits "file:line:reference".
scan_ci() {
    [ -f "$1" ] || return 0
    awk -v F="$1" -v MODE="$2" "$AWKLIB"'
        /^[[:space:]]*#/ { next }
        {
            key = ""; val = ""
            if (match($0, /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*:[[:space:]]*[^[:space:]]/)) {
                key = $0; sub(/^[[:space:]]*/, "", key); sub(/:.*$/, "", key)
                val = $0; sub(/^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*:[[:space:]]*/, "", val)
            } else if (match($0, /^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]/)) {
                key = $0; sub(/^[[:space:]]*(export[[:space:]]+)?/, "", key); sub(/=.*$/, "", key)
                val = $0; sub(/^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=/, "", val)
            }
            val = unquote(val)
            # A command substitution is a runtime value, not a reference a scan can judge.
            if (key != "" && val ~ /^\$\(/) key = ""

            # The mirror variable declares the host itself; it is not a reference to an image.
            if (key == "DEP_IMAGE_REGISTRY") next
            if (key != "" && toupper(key) ~ /IMAGE/) {
                if (MODE == "vars") { print key; next }
                # Deliberately not gated on shaped(): an *IMAGE* variable holding something
                # unshaped (FOO_IMAGE: alpine) is exactly the case worth surfacing.
                print F ":" NR ":" val; next
            }
            if (MODE == "vars") next

            if (key == "image") { print F ":" NR ":" val; next }
            if (key == "name" && shaped(val)) { print F ":" NR ":" val; next }
            if (match($0, /^[[:space:]]*-[[:space:]]*name:[[:space:]]*[^[:space:]]/)) {
                v = $0; sub(/^[[:space:]]*-[[:space:]]*name:[[:space:]]*/, "", v); v = unquote(v)
                if (shaped(v)) print F ":" NR ":" v
                next
            }
            if ($0 ~ /docker[[:space:]]+(run|pull)[[:space:]]/) {
                t = cmd_image($0); if (t != "") print F ":" NR ":" t; next
            }
            if ($0 ~ /--driver-opt[[:space:]]+image=/) {
                t = driver_image($0); if (t != "") print F ":" NR ":" t; next
            }
            # `buildx create` with no --driver-opt image= is the failure that started all this:
            # the docker-container driver silently defaults to moby/buildkit on Docker Hub, so
            # the offending pull appears nowhere in the file. Matched without requiring `docker`
            # adjacent, so an interposed global flag cannot slip past.
            if ($0 ~ /buildx[[:space:]]+create/) {
                print F ":" NR ":<buildx create with no --driver-opt image=>"; next
            }
        }
    ' "$1"
}

# --- Dockerfiles ---------------------------------------------------------------------------
scan_dockerfile() {
    awk -v F="$1" "$AWKLIB"'
        /^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]/ {
            for (i = 1; i <= NF; i++) if (toupper($i) == "AS" && (i + 1) <= NF) stages[$(i + 1)] = 1
        }
        { lines[NR] = $0 }
        END {
            for (n = 1; n <= NR; n++) {
                l = lines[n]
                if (l ~ /^[[:space:]]*#[[:space:]]*syntax[[:space:]]*=/) { print F ":" n ":" l; continue }
                # An *IMAGE* ARG default is the public fallback used when CI does not override
                # it with --build-arg. Invisible until you look for it, and a public pull all
                # the same.
                if (l ~ /^[[:space:]]*[Aa][Rr][Gg][[:space:]]+[A-Za-z_][A-Za-z0-9_]*=/) {
                    k = l; sub(/^[[:space:]]*[Aa][Rr][Gg][[:space:]]+/, "", k); sub(/=.*$/, "", k)
                    v = l; sub(/^[[:space:]]*[Aa][Rr][Gg][[:space:]]+[A-Za-z_][A-Za-z0-9_]*=/, "", v)
                    v = unquote(v)
                    if (k == "DEP_IMAGE_REGISTRY") continue
                    if (toupper(k) ~ /IMAGE/ && v != "") print F ":" n ":" v
                    continue
                }
                if (l ~ /^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]/) {
                    split(l, t, /[[:space:]]+/); ref = ""
                    for (i = 1; i <= length(t); i++) {
                        if (toupper(t[i]) == "FROM" || t[i] ~ /^--/ || t[i] == "") continue
                        ref = t[i]; break
                    }
                    if (ref == "" || ref == "scratch" || (ref in stages)) continue
                    print F ":" n ":" ref
                }
            }
        }
    ' "$1"
}

# --- compose --------------------------------------------------------------------------------
scan_compose() {
    [ -f "$1" ] || return 0
    awk -v F="$1" "$AWKLIB"'
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*image:[[:space:]]*[^[:space:]]/ {
            r = $0; sub(/^[[:space:]]*image:[[:space:]]*/, "", r); print F ":" NR ":" unquote(r)
        }
    ' "$1"
}

# --- shell scripts ---------------------------------------------------------------------------
# A `docker pull` that migrates out of .gitlab-ci.yml into ci/*.sh is the natural refactor and
# would otherwise leave the scan entirely.
scan_shell() {
    [ -f "$1" ] || return 0
    awk -v F="$1" "$AWKLIB"'
        /^[[:space:]]*#/ { next }
        $0 ~ /docker[[:space:]]+(run|pull)[[:space:]]/ { t = cmd_image($0); if (t != "") print F ":" NR ":" t; next }
        $0 ~ /--driver-opt[[:space:]]+image=/ { t = driver_image($0); if (t != "") print F ":" NR ":" t; next }
        $0 ~ /buildx[[:space:]]+create/ { print F ":" NR ":<buildx create with no --driver-opt image=>" }
    ' "$1"
}

# Discovery is over the repository's OWN files. Prefer `git ls-files`, which excludes nested
# checkouts and ignored trees by construction — the primary checkout keeps sibling worktrees
# under .claude/worktrees/, and walking into those reports another branch's Dockerfiles as
# violations of this one. The find fallback is what the CI job actually runs (its image is
# alpine + grep, no git), so both paths must stay equivalent and the suite exercises each.
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    tracked() { git ls-files; }
else
    tracked() {
        find . \( -path ./node_modules -o -path ./.git -o -path ./.claude -o -path ./web/node_modules \) -prune -o \
            -type f -print | sed 's|^\./||'
    }
fi

dockerfiles="$(tracked | grep -E '(^|/)(Dockerfile(\..+)?|[^/]+\.Dockerfile)$' | sort || true)"
composefiles="$(tracked | grep -E '(^|/)(docker-)?compose[^/]*\.ya?ml$' | sort || true)"
shellfiles="$(tracked | grep -E '\.sh$' | sort || true)"

if [ -z "$dockerfiles" ]; then
    echo "image-registry-guard: FAILED — found no Dockerfiles to scan." >&2
    echo "Discovery matched nothing, which means this guard is not checking what it claims." >&2
    exit 1
fi

scan_ci .gitlab-ci.yml vars > "$imagevars"
scan_ci .gitlab-ci.yml scan > "$candidates"

# Per-source floors. One global count is not a coverage check: .gitlab-ci.yml alone supplies
# roughly forty-five references, so a total regression of the Dockerfile or compose scanner
# still clears any threshold low enough to be safe. Each source is asserted separately, and
# every discovered Dockerfile must yield at least its own FROM.
ci_found="$(wc -l < "$candidates" | tr -d ' ')"
if [ "$ci_found" -lt 25 ]; then
    echo "image-registry-guard: FAILED — only $ci_found references found in .gitlab-ci.yml." >&2
    echo "That is far below what this pipeline pins; an extraction pattern has broken." >&2
    exit 1
fi

for df in $dockerfiles; do
    before="$(wc -l < "$candidates" | tr -d ' ')"
    scan_dockerfile "$df" >> "$candidates"
    if [ "$(wc -l < "$candidates" | tr -d ' ')" -eq "$before" ]; then
        echo "image-registry-guard: FAILED — $df yielded no image reference." >&2
        echo "Every Dockerfile has at least a FROM; the scanner is not reading this file." >&2
        exit 1
    fi
done

compose_before="$(wc -l < "$candidates" | tr -d ' ')"
for cf in $composefiles; do scan_compose "$cf" >> "$candidates"; done
if [ -n "$composefiles" ] && [ "$(wc -l < "$candidates" | tr -d ' ')" -eq "$compose_before" ]; then
    echo "image-registry-guard: FAILED — compose files were discovered but yielded nothing." >&2
    exit 1
fi

for sf in $shellfiles; do
    # This script's own awk source necessarily contains the command patterns it hunts for,
    # so scanning it would report the detector as the offence.
    case "$sf" in */image-registry-guard.sh|image-registry-guard.sh) continue ;; esac
    scan_shell "$sf" >> "$candidates"
done

found="$(wc -l < "$candidates" | tr -d ' ')"
status=0
violations=0

while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    ref="${rest#*:}"

    verdict=""
    skip=0
    case "$ref" in
        "$MIRROR_HOST"/*) skip=1 ;;
        *"$MIRROR_VAR"*)  skip=1 ;;
        '$'*)
            # A bare variable expansion is only as trustworthy as its declaration.
            name="$(printf '%s' "$ref" | sed -e 's/^\${//' -e 's/}.*$//' -e 's/^\$//' -e 's/[:-].*$//' -e 's/[^A-Za-z0-9_].*$//')"
            if grep -qxF "$name" "$imagevars" 2>/dev/null; then
                skip=1
            else
                verdict="unknown variable \$$name — declare it as an *IMAGE* variable so its value is checked"
            fi
            ;;
    esac
    [ "$skip" -eq 1 ] && continue

    # Opt-out window: the marker on the line itself or in the five lines above it — except for
    # a `# syntax=` parser directive, which BuildKit only honours on line 1. A comment placed
    # above it silently disables the directive, so for that one case the window runs downward.
    if [ "$line" -gt 5 ]; then start=$((line - 5)); else start=1; fi
    end="$line"
    case "$ref" in
        *syntax=*) start="$line"; end=$((line + 5)) ;;
    esac
    marker="$(sed -n "${start},${end}p" "$file" | grep -o 'image-registry-ok:.*' | head -1 || true)"
    if [ -n "$marker" ]; then
        reason="$(printf '%s' "$marker" | sed 's/^image-registry-ok:[[:space:]]*//')"
        if [ -n "$reason" ]; then continue; fi
        echo "ERROR: image-registry-ok marker with no reason at $file:$line" >&2
        echo "       a bare marker is not a decision — say why" >&2
        violations=$((violations + 1)); status=1
        continue
    fi

    if [ -n "$verdict" ]; then
        echo "ERROR: $verdict — at $file:$line" >&2
    else
        echo "ERROR: image not resolved through \$$MIRROR_VAR at $file:$line" >&2
    fi
    echo "       $ref" >&2
    violations=$((violations + 1))
    status=1
done < "$candidates"

if [ "$status" -ne 0 ]; then
    echo "" >&2
    echo "image-registry-guard: FAILED — $violations image reference(s) bypass the mirror." >&2
    echo "The CI runners cannot reach public registry CDNs. Route the image through" >&2
    echo "\${$MIRROR_VAR} (the mirror proxies arbitrary upstream namespaces), or, if the" >&2
    echo "pull is genuinely deliberate, mark it '# image-registry-ok: <reason>' on the line" >&2
    echo "or within the five lines above so the decision is reviewable." >&2
    exit 1
fi

echo "image-registry-guard: PASS — $found image references checked, all resolved through \$$MIRROR_VAR."
