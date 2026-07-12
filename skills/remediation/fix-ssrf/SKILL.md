---
name: fix-ssrf
description: Remediate Server-Side Request Forgery findings (CWE-918/441 — OWASP A01:2025 Broken Access Control) by allowlisting outbound destinations, blocking private/link-local IP ranges, and re-validating across redirects.
category: remediation
cwe:
  - CWE-918
  - CWE-441
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

The server fetches a URL (or connects to a host/port) that is, directly or indirectly, influenced
by untrusted input — a webhook target, an image-fetch-by-URL feature, an "import from URL"
endpoint, an XML parser resolving an external entity. An attacker uses this to make the server
issue requests it shouldn't: to internal-only services, to the cloud metadata endpoint
(`169.254.169.254`), or to a URL scheme (`file://`, `gopher://`) the feature was never meant to
support. CWE-441 (confused deputy / unintended proxy) is the same underlying issue where the
server acts as a proxy for the attacker's chosen destination.

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first. Use this skill when the SSRF is in your own
outbound-request code, or the fixed dependency version still needs its URL-fetching call sites
reviewed.

## Core principle

Validate the *resolved destination*, not just the URL string's syntax — a URL that looks like a
public hostname can still resolve to a private IP (DNS rebinding, or a domain an attacker
controls that they point at `127.0.0.1` or a cloud metadata address).

## Allowlist destinations

The strongest fix: restrict outbound requests to a hardcoded allowlist of hosts/schemes the
feature actually needs, and reject everything else before issuing the request:

```python
ALLOWED_HOSTS = {"api.partner.example.com"}

def fetch(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in ("https",) or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Destination not allowed.")
    return requests.get(url, timeout=5, allow_redirects=False).content
```

When the whole point of the feature is fetching arbitrary user-supplied URLs (a webhook, an image
proxy), an allowlist of hosts isn't available — apply the network-level checks below instead.

## Block private, loopback, and link-local ranges

Resolve the hostname and check the resulting IP before connecting, not just the hostname string:

```python
import ipaddress, socket

def is_blocked(hostname: str) -> bool:
    for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return True
        if str(ip) == "169.254.169.254":   # cloud metadata endpoint, explicit belt-and-suspenders
            return True
    return False
```

This must happen at connection time, using the same DNS resolution the HTTP client will actually
use — validating a hostname once and then trusting it for a later request is vulnerable to DNS
rebinding (the name resolves to a public IP at check time, then to a private one at request time).
Where the HTTP client library supports it, hook its own connect step (a custom transport/adapter)
rather than doing a separate resolve-then-connect, so there's no window between check and use.

## Re-validate across redirects

A request to an allowed destination can 302 to a disallowed one. Either disable automatic redirect
following (`allow_redirects=False` / equivalent) and re-run the full validation on each hop
yourself, or use a client configuration that re-applies the destination check per redirect rather
than only on the initial URL.

## Restrict schemes

Reject anything other than `http`/`https` before connecting — `file://` reads local files instead
of making a network request at all, and `gopher://`/`dict://` can be used to speak raw protocols
to internal services (SMTP, Redis) through a URL-fetch feature.

## Network-level defense in depth

Where available, route outbound fetches for user-supplied URLs through a dedicated egress
proxy/firewall that enforces the same allowlist/private-range block at the network layer — this
catches SSRF from a path in the code that forgot the check, not just the one that was fixed.

## Verify

1. Reproduce the original finding: a payload targeting a private IP, the cloud metadata address, a
   non-http(s) scheme, or a redirect chain into a blocked range should now be rejected.
2. Add a regression test asserting the destination check specifically — including the redirect
   case, since it's the easiest part of the fix to accidentally skip.
3. Run the project's test suite.
4. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the SSRF was in a third-party package (`OSV_ID`, `PACKAGE_PURL`).
