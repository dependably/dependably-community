"""ZAP full-scan hook: keep the authenticated crawl on-target and scope the active scan.

The authenticated zap-full run injects a session cookie (via the replacer add-on) so the
AJAX spider can crawl the JS-rendered app past the login wall. Its job is coverage of the
SPA and static shell that an unauthenticated spider can't reach — the management API's
attack surface is owned by the dedicated zap-api-management job, which imports the OpenAPI
document and active-scans every /api/v1 route deterministically.

Domain scope is the primary crawl-boundedness mechanism (see zap_started): the app renders
external links by design (package homepage/source-repository links, reconstructed upstream
registry-page links), and an unscoped spider/AJAX-spider follows any absolute URL it finds in
fetched content, not just clicked <a> tags — confirmed by pointing this hook's flow at a target
with a link to a second, unrelated site: without scope restriction the crawl fully recursed into
that second site's assets; with it, only the seeded target host was crawled. That explains the
3577-URL explosion and its runtime better than a same-origin variant-explosion theory alone:
following external links means unbounded surface, not extra variants of the same surface. The
AJAX-spider bounds below (max duration / max crawl states) remain as a secondary backstop for a
pathological in-domain crawl — sized so they rarely bind once scope is doing its job.

Two further exclusions keep the API-surface division clean:

1. Session-destroying endpoints (logout, password change, MFA) are excluded from the crawl
   (spider + AJAX spider, via the context so the in-scope-only AJAX spider won't navigate to
   them) and from the active scanner, so a browser crawl can't revoke its own token_version /
   rotate its security_stamp mid-scan and turn the rest of the run unauthenticated (the same
   self-logout failure the management API scan hit via its OpenAPI import).

2. The whole /api/v1 management surface is excluded from the active scanner (but not the
   spider — the SPA still exercises those routes over XHR during the crawl, giving passive
   coverage). Active-scanning it here is redundant with zap-api-management, which owns that
   surface deterministically. It was also historically the source of ZAP's boolean-based SQL
   Injection [40018] false positive on the list endpoints' filter/sort parameters: the scanner
   appends "value AND 1=1 --" and reads the app's row-count heuristic as a confirmed injection,
   even though no user input reaches SQL (values are Dapper-bound parameters matched against a
   column, or sort fields mapped through a bounded whitelist — and NoInterpolatedSqlComplianceTests
   makes an interpolated query a build failure). That FP is rate-limiter-gated: it confirms only
   when the app's 429s flip a rule's true/false probe pair, landing on a different parameter run
   to run. The DAST app boot (.app_boot) now raises every request-rate limiter far above the
   scan's request volume, so no 429 boundary exists and 40018 no longer flakes on either scan;
   excluding /api/v1 here remains correct purely for redundancy with zap-api-management, which
   scans it with 40018 armed.

zap-full-scan.py calls `zap_started(zap, target)` after the daemon is up and before the
spider/ajax/active-scan phases, and `zap_pre_shutdown(zap)` once all three phases finish
(right before it shuts the daemon down) — the crawl-coverage bounding and coverage-count
file below hook into those two points.
"""

import os

import zap_common

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

# The AJAX spider's run-to-run swing (measured 106-3577 crawled URLs, same 0 findings every
# time) is dominated by the missing domain-scope restriction (see zap_started) — a bare spider
# will follow any absolute URL an app renders, including a package's external homepage/
# source-repository/registry-page links, and recurse arbitrarily deep into whatever site that
# link lands on. These bounds are a secondary backstop for a pathological *in-domain* crawl once
# scope is enforced, sized comfortably above every healthy run on record (up to 806 URLs) so a
# normal crawl finishes unaffected. Overridable per-pipeline with a CI/CD variable of the same
# name, matching ZAP_FULL_MIN_URLS in .gitlab-ci.yml.
AJAX_SPIDER_MAX_DURATION_MINS = int(os.environ.get("ZAP_FULL_AJAX_MAX_DURATION_MINS", "15"))
AJAX_SPIDER_MAX_CRAWL_STATES = int(os.environ.get("ZAP_FULL_AJAX_MAX_CRAWL_STATES", "1200"))

# Backstop for the active scanner's own wall time, independent of how many URLs the (now
# domain-scoped, state-capped) spider hands it. No measured active-scan-only timing exists to
# calibrate a tighter value against (the 106 URLs->360s / 3577 URLs->2549s figures are whole-job
# wall time, spider+ascan combined), so this sits generously above where the other bounds should
# already keep it — a worst-case ceiling on total job time, not a normal-case constraint.
ASCAN_MAX_DURATION_MINS = int(os.environ.get("ZAP_FULL_ASCAN_MAX_MINS", "20"))

# File the coverage floor in .gitlab-ci.yml reads instead of grepping the scan log for the
# `Total of N URLs` line — that line prints only when zap-full-scan.py runs with -d
# (detailed_output), and -d also floods the job log past GitLab's 4 MB per-job limit. Writing
# the same zap.core.urls() count here from zap_pre_shutdown decouples the floor from -d, so -d
# can be dropped from the invocation without losing the floor's input.
URL_COUNT_FILE = "zap-full-url-count.txt"


def zap_started(zap, target):
    # Domain scope, the primary crawl-boundedness mechanism. No context exists yet at this
    # point in the daemon's lifecycle (confirmed: zap.context.context_list is empty here on a
    # freshly started daemon), so a context call that names one silently no-ops — the ZAPv2
    # client defaults validate_status_code=False and returns the does-not-exist error as plain
    # JSON. Create the context explicitly so it is real before anything below references it.
    context_id = zap.context.new_context(CONTEXT_NAME)
    include_regex = r"\Q" + target + r"\E.*"
    zap.context.include_in_context(CONTEXT_NAME, include_regex)
    zap.context.set_context_in_scope(CONTEXT_NAME, True)
    # zap-full-scan.py's own zap_spider/zap_ajax_spider/zap_active_scan helpers (zap_common.py)
    # only pass a context to the ZAP API when the module-level context_name/context_id globals
    # are set — which otherwise only happens via the CLI's -n context-file flag, not available
    # here. Setting them directly wires this hook's context into those same, already-vendored
    # call sites (`zap.spider.scan(target, contextname=context_name)`, ajaxSpider.scan(...,
    # contextname=context_name), ascan.scan(..., contextid=context_id)) so the traditional
    # spider, AJAX spider, and active scanner all honor the include-in-scope restriction above
    # instead of following any absolute URL they find in fetched content, on- or off-domain.
    zap_common.context_name = CONTEXT_NAME
    zap_common.context_id = context_id
    print(
        "zap-full-hooks: scoped crawl to %s (context id %s)" % (include_regex, context_id)
    )

    for rx in SESSION_DESTROYING_REGEXES:
        # Traditional spider and active scanner both honor their own exclude lists.
        zap.spider.exclude_from_scan(rx)
        zap.ascan.exclude_from_scan(rx)
        # The AJAX spider crawls in-scope URLs only; excluding from the context keeps the
        # browser from navigating to (and thus triggering) these endpoints.
        zap.context.exclude_from_context(CONTEXT_NAME, rx)
    print(
        "zap-full-hooks: excluded %d session-destroying pattern(s) from spider/ajax/ascan"
        % len(SESSION_DESTROYING_REGEXES)
    )

    # Keep the API in the crawl (passive coverage) but out of the active scanner.
    zap.ascan.exclude_from_scan(API_SURFACE_REGEX)
    print("zap-full-hooks: excluded /api/v1 management surface from the active scanner")

    # Secondary backstop: cap the AJAX spider even within the now-enforced domain scope, so a
    # pathological in-domain crawl (e.g. a combinatorial pagination/query-param space) still
    # can't run unbounded. click_elems_once stops the crawler from re-clicking an element it has
    # already fired, a common source of redundant re-crawling independent of domain scope.
    zap.ajaxSpider.set_option_max_duration(AJAX_SPIDER_MAX_DURATION_MINS)
    zap.ajaxSpider.set_option_max_crawl_states(AJAX_SPIDER_MAX_CRAWL_STATES)
    zap.ajaxSpider.set_option_click_elems_once(True)
    print(
        "zap-full-hooks: bounded AJAX spider to max_duration=%dmin max_crawl_states=%d "
        "click_elems_once=true"
        % (AJAX_SPIDER_MAX_DURATION_MINS, AJAX_SPIDER_MAX_CRAWL_STATES)
    )

    # Backstop the active scan's own wall time the same way (see the constant's comment above).
    zap.ascan.set_option_max_scan_duration_in_mins(ASCAN_MAX_DURATION_MINS)
    print("zap-full-hooks: bounded active scan to max_scan_duration=%dmin" % ASCAN_MAX_DURATION_MINS)


def zap_pre_shutdown(zap):
    """Write the final crawl-coverage count to disk before the daemon shuts down.

    zap-full-scan.py calls this after the spider, AJAX spider, and active-scan phases have all
    completed, right before zap.core.shutdown() — the same point it computes
    len(zap.core.urls()) for its own (now -d-gated) 'Total of N URLs' line. Recomputing the
    identical call here gives the coverage floor in .gitlab-ci.yml a count that does not depend
    on -d/detailed_output.
    """
    num_urls = len(zap.core.urls())
    with open(URL_COUNT_FILE, "w") as f:
        f.write(str(num_urls))
    print("zap-full-hooks: wrote crawl coverage (%d URL(s)) to %s" % (num_urls, URL_COUNT_FILE))
