---
name: fix-authentication-failures
description: Remediate broken/missing authentication findings (CWE-287/288/290/294/295/297/300/303/304/305/306/307/346/384/613/620/640/798/940 — OWASP A07:2025 Authentication Failures) by enforcing a real credential/token check on every protected path, rate-limiting attempts, and validating certificates and session lifetime correctly.
category: remediation
cwe:
  - CWE-287
  - CWE-295
  - CWE-306
  - CWE-307
  - CWE-346
  - CWE-384
  - CWE-613
  - CWE-798
  - CWE-940
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

Something that should require proving identity doesn't, or the proof it accepts can be forged,
replayed, or bypassed: a "critical function" endpoint reachable without authentication at all
(CWE-306), a login/session check with a logic error an attacker can route around (CWE-287,
CWE-288, CWE-305), a TLS/mTLS client that accepts an invalid or mismatched certificate (CWE-295,
CWE-297), a login endpoint with no attempt limiting so credentials can be brute-forced (CWE-307),
a session id that's never invalidated or rotated (CWE-384 session fixation, CWE-613 session that
never expires), or a hardcoded credential/API key that grants access to anyone who reads the
source (CWE-798).

This is distinct from authorization (`fix-broken-access-control`): authentication establishes
*who* the caller is; authorization decides *what* that caller may do. A bug here means the
identity claim itself cannot be trusted — the caller might not be who the request claims.

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first. Use this skill when the authentication logic is your own,
or the fixed dependency version still needs its integration reviewed (e.g. it added stricter
certificate validation behind a flag your code must enable).

## Core principle

Every path that should require a proven identity must actually verify one, server-side, on every
request — not once at login and then trusted implicitly, not skippable through an alternate route,
and not satisfied by a credential the server itself hardcodes and therefore already knows.

## Never skip authentication on a "less important" path

```csharp
// Unsafe: this internal-sounding endpoint has no [Authorize] — it's reachable by anyone
// who finds the URL, defeating every check the "real" endpoints enforce.
[HttpPost("internal/reindex")]
public IActionResult Reindex() => Ok(_search.Reindex());

// Safe: every state-changing or data-returning endpoint requires authentication explicitly,
// or the app is configured to require it by default and opts specific routes out.
[HttpPost("internal/reindex")]
[Authorize(Roles = "admin")]
public IActionResult Reindex() => Ok(_search.Reindex());
```

Prefer a framework/middleware configuration where authentication is required by default and a
route explicitly opts out (an allowlist of public routes), rather than the inverse — a new route
added later should fail closed, not silently ship unauthenticated because nobody remembered to add
the check.

## Don't leave an alternate path that bypasses the check

A password-reset flow, an API-key header, or a legacy endpoint that predates the current auth
layer can leave a second way to reach protected functionality that never goes through the main
check. Audit for any route or code path that reaches the same handler/data as an authenticated
route but through a different entry point, and confirm the check is applied there too, not only on
the primary path.

## Validate certificates completely — don't disable the check to "make it work"

```python
# Unsafe: turns off certificate validation entirely — any attacker can MITM this connection.
requests.get(url, verify=False)
# Safe: default verification against the system trust store.
requests.get(url)
```

```java
// Unsafe: a trust manager that accepts any certificate, often added "temporarily" to
// work around a cert error and then never removed.
TrustManager[] trustAll = { new X509TrustManager() {
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    // ...
}};
```

If certificate validation was disabled to get past a self-signed or internal-CA certificate,
install that CA into the trust store instead of disabling validation — a validation bypass added
for a dev/test environment has a way of surviving into production. Also confirm hostname
verification runs (a valid certificate for the *wrong* host is CWE-297, a distinct check from
"is this certificate valid at all").

## Rate-limit and lock out repeated authentication attempts

```csharp
// Unsafe: no limit — an attacker can try unlimited passwords against this endpoint.
[HttpPost("login")]
public IActionResult Login(LoginRequest req) => Authenticate(req);

// Safe: attempts are counted and locked out per account (and/or per source), independent
// of any general-purpose API rate limiter, so credential stuffing is bounded even from
// many different source IPs.
[HttpPost("login")]
[EnableRateLimiting("login-attempts")]
public IActionResult Login(LoginRequest req) => Authenticate(req);
```

Lock out or exponentially back off by account identifier (not only by source IP, which an attacker
distributes across), and return the same response shape for "wrong password" and "account doesn't
exist" — a response that reveals which one occurred is a separate enumeration issue but commonly
ships alongside a missing rate limit.

## Rotate the session id at login, and expire sessions server-side

A session id issued *before* login must not remain valid *after* login (CWE-384: an attacker who
fixates a pre-auth session id and gets the victim to authenticate under it then has a valid
authenticated session too) — issue a fresh session id at the moment authentication succeeds.
Sessions also need a real expiration enforced server-side (an absolute lifetime and an idle
timeout), not just a client-side cookie expiry the client fully controls.

## Never hardcode a credential or API key

Same fix as a hardcoded cryptographic key (`fix-weak-cryptography`): a credential in source is
visible to anyone with repository access, including its full history. Load it from a secrets
manager or environment variable at deploy time, and rotate whatever was exposed.

## Verify

1. Reproduce the original finding: an unauthenticated request to the affected path, an invalid or
   mismatched certificate, an unlimited password-guessing loop, or a pre-login session id reused
   post-login must now be rejected.
2. Add a regression test asserting the specific bypass path is closed — not just that the normal
   login flow still works.
3. Run the project's test suite.
4. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the issue was in a third-party package (`OSV_ID`, `PACKAGE_PURL`).
