"""ZAP full-scan hook: keep the authenticated SPA crawl from destroying its own session.

The authenticated zap-full run injects a session cookie (via the replacer add-on) so the
AJAX spider can crawl the JS-rendered app past the login wall. A browser crawl would
otherwise navigate to the logout control — or submit a password/MFA change — which revokes
the session's token_version server-side and turns the rest of the scan unauthenticated
(the same self-logout failure the management API scan hit via its OpenAPI import).

Exclude those endpoints from the traversal (spider + AJAX spider, via the default context
so the in-scope-only AJAX spider won't navigate to them) and from the active scanner, so
the authenticated session survives the whole crawl.

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
