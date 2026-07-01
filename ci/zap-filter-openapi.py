#!/usr/bin/env python3
"""Drop session-destroying operations from an OpenAPI document before a ZAP scan.

Reads an OpenAPI JSON document from a URL (first argument) or, when no argument is
given, from stdin, and writes it back on stdout with the operations that would revoke
the DAST scanner's OWN authenticated session removed. (Fetching is done here rather
than via a `curl | python3` pipe so the CI config linter doesn't flag a download piped
into an interpreter or an unverified curl download — the source is the job's own app.)

Why this exists: the authenticated management scan injects a real session cookie on
every request. ZAP's OpenAPI import sends one request per documented operation, so it
hits POST /api/v1/auth/logout (and the password/MFA mutations) with that live session.
Logout revokes the session's token_version server-side, after which every remaining
request fails with "Token has been revoked" (HTTP 401) and the rest of the management
surface is scanned unauthenticated. Removing these operations from the spec keeps the
session alive so ZAP exercises the management routes authenticated. The excluded
endpoints are auth-mechanic routes covered by the auth unit/integration tests.

Matched by path SUFFIX so it is robust to whether the server base path (/api/v1) lives
in the OpenAPI `paths` keys or in a `servers` entry. Suffix matching also covers the
system-scoped twins (e.g. /api/v1/system/mfa/disable), which is harmless: a tenant-owner
session cannot invoke them anyway.
"""
import json
import sys
import urllib.request

# Operations the authenticated session can use to revoke/rotate its own
# token_version or security_stamp, terminating the scan session.
SESSION_DESTROYING_SUFFIXES = (
    "/auth/logout",
    "/users/me/password",
    "/mfa/setup/verify",
    "/mfa/disable",
    "/mfa/recovery-codes/regenerate",
)


def _load():
    if len(sys.argv) > 1:
        url = sys.argv[1]
        if not url.startswith(("http://", "https://")):
            sys.exit("zap-filter-openapi: refusing non-http(s) source: " + url)
        with urllib.request.urlopen(url, timeout=30) as resp:  # nosec B310 - http(s) only, job-local app
            return json.load(resp)
    return json.load(sys.stdin)


doc = _load()
paths = doc.get("paths", {})
removed = [p for p in list(paths) if p.endswith(SESSION_DESTROYING_SUFFIXES)]
for p in removed:
    del paths[p]

sys.stderr.write(
    "zap-filter-openapi: removed %d session-destroying path(s): %s\n"
    % (len(removed), ", ".join(sorted(removed)) or "(none)")
)
json.dump(doc, sys.stdout)
