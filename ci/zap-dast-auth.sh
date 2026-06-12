#!/usr/bin/env sh
# Runs inside the authenticated ZAP DAST jobs AFTER the app is booted and /ready
# on :8080. Logs in as the first-boot admin, clears the forced password-rotation
# flag (PasswordRotationGuard returns 403 for every non-whitelisted /api/v1 route
# until this is done), mints an unrestricted API token, and writes both
# credentials to zap-creds.env for the job to source:
#   ZAP_API_TOKEN      — dpd_… raw token, for the protocol-API scan (Bearer)
#   ZAP_SESSION_COOKIE — dependably_session=<jwt>, for the management-API scan
set -eu

BASE="http://localhost:8080"
ADMIN_EMAIL="${DAST_ADMIN_EMAIL:-admin@dependably.local}"
OLD_PW="$DAST_ADMIN_PASSWORD"
# Throwaway — the DB is wiped with the job. Keeps the source password's strength.
NEW_PW="${DAST_ADMIN_PASSWORD}_Rotated1"
jar="$(mktemp)"

# 1) Login. The JWT is delivered as an HttpOnly Set-Cookie, not in the body.
curl -fsS -c "$jar" -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$OLD_PW\"}" >/dev/null

# 2) Clear must_change_password (whitelisted route — reachable pre-rotation).
curl -fsS -b "$jar" -X POST "$BASE/api/v1/users/me/password" \
  -H 'Content-Type: application/json' \
  -d "{\"currentPassword\":\"$OLD_PW\",\"newPassword\":\"$NEW_PW\"}" >/dev/null

# 3) Re-login with the new password for a clean session (sidesteps any
#    security-stamp invalidation triggered by the password change).
curl -fsS -c "$jar" -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$NEW_PW\"}" >/dev/null

# 4) Mint a token with an explicit capability set. capabilities must be non-empty
#    (the issuance pipeline rejects [] with 422) and every entry must be both a
#    known capability and held by the caller's role. The first-boot admin is org
#    owner, so this read+publish+import+yank set is within its grants and lets the
#    protocol scan reach handlers past authorization instead of collecting 403s.
caps='["read:metadata","read:artifact","read:packages","read:claims","publish:*","import:*","yank:*"]'
token_json="$(curl -sS -w '\n%{http_code}' -b "$jar" -X POST "$BASE/api/v1/tokens" \
  -H 'Content-Type: application/json' \
  -d "{\"description\":\"zap-dast\",\"capabilities\":$caps}")"
token_code="$(printf '%s' "$token_json" | tail -n1)"
token_body="$(printf '%s' "$token_json" | sed '$d')"
[ "$token_code" = "200" ] || { echo "token mint failed ($token_code): $token_body" >&2; exit 1; }
ZAP_API_TOKEN="$(printf '%s' "$token_body" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')"
[ -n "$ZAP_API_TOKEN" ] || { echo "no api token in response: $token_body" >&2; exit 1; }

# 5) Extract the raw session JWT from the cookie jar (Netscape format, field 7).
SESSION_JWT="$(awk '/dependably_session/{print $7}' "$jar")"
[ -n "$SESSION_JWT" ] || { echo "no session cookie captured" >&2; exit 1; }
rm -f "$jar"

{
  echo "ZAP_API_TOKEN=$ZAP_API_TOKEN"
  echo "ZAP_SESSION_COOKIE=dependably_session=$SESSION_JWT"
} > zap-creds.env
echo "DAST auth ready (token + session cookie captured)"
