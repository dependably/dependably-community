"""ZAP full-scan hook: protect the authenticated session and scope the active scan.

The authenticated zap-full run injects a session cookie (via the replacer add-on) so the
AJAX spider can crawl the JS-rendered app past the login wall. Its job is coverage of the
SPA and static shell that an unauthenticated spider can't reach — the management API's
attack surface is owned by the dedicated zap-api-management job, which imports the OpenAPI
document and active-scans every /api/v1 route deterministically.

Two exclusions keep that division clean:

1. Session-destroying endpoints (logout, password change, MFA) are excluded from the crawl
   (spider + AJAX spider, via the default context so the in-scope-only AJAX spider won't
   navigate to them) and from the active scanner, so a browser crawl can't revoke its own
   token_version / rotate its security_stamp mid-scan and turn the rest of the run
   unauthenticated (the same self-logout failure the management API scan hit via its OpenAPI
   import).

2. The whole /api/v1 management surface is excluded from the active scanner (but not the
   spider — the SPA still exercises those routes over XHR during the crawl, giving passive
   coverage). Active-scanning it here is redundant with zap-api-management and is the sole
   source of ZAP's boolean-based SQL Injection [40018] false positive on the list endpoints'
   filter/sort parameters: the scanner appends "value AND 1=1 --" and reads the app's row-
   count heuristic as a confirmed injection, even though no user input reaches SQL (values
   are Dapper-bound parameters matched against a column, or sort fields mapped through a
   bounded whitelist — and NoInterpolatedSqlComplianceTests makes an interpolated query a
   build failure). That alert is rate-limiter-gated: ZAP only confirms it when enough probes
   slip past the app's 429s, so it lands on a different parameter run to run — unfixable by
   per-parameter accept-listing. Scoping the active scan away from the API removes the whole
   flaky class at its source while leaving 40018 armed on every other surface.

zap-full-scan.py calls `zap_started(zap, target)` after the daemon is up and before the
spider/ajax/active-scan phases.
"""

# URL patterns the authenticated session can use to revoke/rotate its own token_version or
# security_stamp. Regexes (ZAP exclude APIs take Java regexes matched against the full URL).
SESSION_DESTROYING_REGEXES = [
    r".*/api/v1/auth/logout\b.*",
    r".*/api/v1/users/me/password\b.*",
    r".*/api/v1/mfa/.*",
    r".*/api/v1/system/mfa/.*",
    r".*/api/v1/system/me/password\b.*",
]

# The management API's attack surface belongs to zap-api-management (deterministic OpenAPI
# import). zap-full excludes it from the active scanner so the SPA crawl still exercises it
# passively without producing the rate-limiter-gated 40018 false positive.
API_SURFACE_REGEX = r".*/api/v1/.*"

CONTEXT_NAME = "Default Context"


def zap_started(zap, _target):
    for rx in SESSION_DESTROYING_REGEXES:
        # Traditional spider and active scanner both honor their own exclude lists.
        zap.spider.exclude_from_scan(rx)
        zap.ascan.exclude_from_scan(rx)
        # The AJAX spider crawls in-scope URLs only; excluding from the default context
        # keeps the browser from navigating to (and thus triggering) these endpoints.
        try:
            zap.context.exclude_from_context(CONTEXT_NAME, rx)
        except Exception as exc:  # context may not exist yet on some scan configs
            print("zap-full-hooks: context exclude skipped for %s: %s" % (rx, exc))
    print(
        "zap-full-hooks: excluded %d session-destroying pattern(s) from spider/ajax/ascan"
        % len(SESSION_DESTROYING_REGEXES)
    )

    # Keep the API in the crawl (passive coverage) but out of the active scanner.
    zap.ascan.exclude_from_scan(API_SURFACE_REGEX)
    print("zap-full-hooks: excluded /api/v1 management surface from the active scanner")
