#!/usr/bin/env bash
# Edge dependency-closure guard.
#
# The dependably/edge image ships without the management-plane dependency closure
# — attack-surface reduction by assembly reference graph, not runtime stripping.
# This guard is the machine-checkable exclusion proof: it reads the edge project's
# CycloneDX SBOM and FAILS if any management-plane package (or a transitive of one)
# appears in it. Poisoning the edge closure — a stray reference that drags one of
# these families back in — is caught here on every MR, not at release time.
#
# Scope: the edge project only (src/Dependably.Edge). The community image is
# expected to contain these packages; sbom-backend covers it and is unaffected.
#
# Usage:
#   ci/edge-closure-guard.sh [path/to/sbom-edge.json]
# Defaults to sbom-edge.json in the working directory. The SBOM is a local file
# produced by dotnet CycloneDX; no network access.

set -eu

SBOM="${1:-sbom-edge.json}"

if [ ! -f "$SBOM" ]; then
  echo "edge-closure-guard: SBOM not found: $SBOM" >&2
  exit 2
fi

# Forbidden package families. Each entry is matched case-insensitively against the
# SBOM component name, either exactly or as a prefix followed by a dot (so
# "Microsoft.IdentityModel." catches the whole family without matching an unrelated
# "Microsoft.IdentityModelFoo"). Present-tense rationale per family:
#
#   BCrypt.Net-Next                       — password hashing; edge does no admin
#                                           credential bootstrap (no IAdminBootstrapper).
#   zxcvbn-core                           — password-strength estimation; management-only.
#   ITfoxtec.Identity.Saml2               — SAML SSO; a management-plane login path.
#   Microsoft.IdentityModel               — OIDC/JWT token-handling stack; edge protocol
#                                           auth is the ApiToken scheme, not session JWT.
#   System.IdentityModel.Tokens.Jwt       — JWT token creation/validation; same closure.
#   Microsoft.AspNetCore.Authentication.JwtBearer
#                                         — JWT bearer scheme; management default scheme.
#   StackExchange.Redis                   — HA lock/lockout backing; edge is single-node.
#   Microsoft.AspNetCore.DataProtection.StackExchangeRedis
#                                         — Redis-backed DP ring; edge stays in-process.
#   Microsoft.OpenApi                     — OpenAPI document model; docs are management-only.
#   Microsoft.AspNetCore.OpenApi          — OpenAPI endpoint wiring; docs are management-only.
FORBIDDEN="
BCrypt.Net-Next
zxcvbn-core
ITfoxtec.Identity.Saml2
Microsoft.IdentityModel
System.IdentityModel.Tokens.Jwt
Microsoft.AspNetCore.Authentication.JwtBearer
StackExchange.Redis
Microsoft.AspNetCore.DataProtection.StackExchangeRedis
Microsoft.OpenApi
Microsoft.AspNetCore.OpenApi
"

# Extract every "name" value from the CycloneDX SBOM with grep/sed — the job runs
# in the dotnet SDK image, which ships no python. The SBOM is machine-generated
# JSON with one "name": "..." pair per component; the extraction also picks up
# non-component names (the tool name, the project's own name), which is harmless
# because none of them can match a forbidden package family.
NAMES=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$SBOM" \
  | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/')

violations=""
for pkg in $FORBIDDEN; do
  # Lowercase both sides for a case-insensitive compare. Match an exact name or a
  # family prefix ("<pkg>." ...). awk keeps this POSIX and dependency-free.
  hits=$(printf '%s\n' "$NAMES" | awk -v p="$pkg" '
    BEGIN { lp = tolower(p) }
    { ln = tolower($0) }
    ln == lp || index(ln, lp ".") == 1 { print $0 }
  ')
  if [ -n "$hits" ]; then
    while IFS= read -r h; do
      [ -n "$h" ] && violations="${violations}  ${h}  (matches forbidden family: ${pkg})
"
    done <<EOF
$hits
EOF
  fi
done

if [ -n "$violations" ]; then
  echo "edge-closure-guard: FAILED — forbidden management-plane packages found in $SBOM:" >&2
  printf '%s' "$violations" >&2
  echo "The edge image must exclude the management-plane closure. A reference somewhere in" >&2
  echo "src/Dependably.Edge (or Dependably.Core) is dragging these packages back in." >&2
  exit 1
fi

echo "edge-closure-guard: PASS — no forbidden management-plane packages in $SBOM."
