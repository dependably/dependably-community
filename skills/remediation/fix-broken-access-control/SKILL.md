---
name: fix-broken-access-control
description: Remediate missing/incorrect authorization and insecure-direct-object-reference findings (CWE-284/285/639/862/863 — OWASP A01:2025 Broken Access Control) by adding a server-side ownership/role check on every access, keyed off the authenticated identity rather than client-supplied state.
category: remediation
cwe:
  - CWE-284
  - CWE-285
  - CWE-639
  - CWE-862
  - CWE-863
inputs:
  - OSV_ID
  - PACKAGE_PURL
  - FIXED_VERSION
---

## When to use this

An endpoint, function, or data access reads or writes a resource without verifying that the
authenticated caller is actually allowed to touch that specific resource — either the check is
missing entirely (CWE-862), or it exists but is wrong (CWE-863: checks that the caller is
logged in, but not that they own the record; checks a role but not the scope). The
insecure-direct-object-reference variant (CWE-639, also called IDOR or BOLA) is the most common
concrete instance: an id in the URL, body, or token is swapped for another tenant's or user's id,
and the resource is served anyway because the lookup trusted the id without confirming the caller
owns it.

This is distinct from authentication (`fix-authentication-failures`): authentication answers "who
is this caller", authorization answers "is this caller allowed to do *this*, to *this*
resource". A request can pass authentication perfectly and still be a broken-access-control bug.
It is also distinct from `fix-path-traversal` (filesystem path containment) and `fix-ssrf`
(server-side request destination) — those are specific access-control failures already carved
out as their own skills; use this one for the general case of a missing or incorrect ownership/role
check on a data or function access.

If the finding is in a third-party dependency and `FIXED_VERSION` is set, apply the
`fix-vulnerable-dependency` skill first. Use this skill when the check is in your own
authorization logic, or the fixed dependency version still needs its call sites reviewed.

## Core principle

Authorize every access, server-side, against the actual resource being touched — not against
whether the caller is logged in, not against a role claimed by client-supplied state, and not by
assuming the frontend already hid the option to request someone else's resource. The check must
compare the authenticated identity to the resource's real owner/tenant, looked up server-side, on
every request that reads or writes it.

## Add an explicit ownership check, keyed off server state

```csharp
// Unsafe: fetches by id alone — any authenticated caller can read any order.
[HttpGet("orders/{id}")]
public async Task<IActionResult> GetOrder(int id) =>
    Ok(await _orders.GetByIdAsync(id));

// Safe: the lookup itself is scoped to the caller's own identity/org — an id for
// another tenant's order simply doesn't match and returns 404, not 403 (403 would
// confirm the id exists, leaking its existence to an attacker probing ids).
[HttpGet("orders/{id}")]
public async Task<IActionResult> GetOrder(int id)
{
    int callerOrgId = User.GetOrgId();
    var order = await _orders.GetByIdAsync(id, callerOrgId);
    return order is null ? NotFound() : Ok(order);
}
```

```python
# Unsafe: role check without resource-ownership check.
@require_role("member")
def get_document(request, doc_id):
    return Document.objects.get(id=doc_id)

# Safe: filter the query by the resource's real owner, not just the caller's role.
@require_role("member")
def get_document(request, doc_id):
    return get_object_or_404(Document, id=doc_id, owner=request.user)
```

The safe shape in both examples is the same: the ownership/tenant check is part of the *query*
that fetches the resource, not a separate `if` after an unscoped fetch — this closes the gap
where a later refactor drops the `if` but the code still compiles and still "works" for the happy
path.

## Never trust a client-supplied role, id, or scope

A role, tenant id, or "isAdmin" flag sent by the client (a form field, a JSON body key, a
non-signed cookie) is not authorization evidence — an attacker can set it to anything. The only
trustworthy source for "who is this caller and what can they do" is server-side state: a
validated session, a signed JWT claim the server issued, or a database lookup keyed by the
caller's authenticated identity.

```csharp
// Unsafe: trusts a client-supplied orgId to decide what's visible.
var items = await _repo.ListAsync(request.OrgId);
// Safe: the org id comes from the caller's own validated session/token claim.
var items = await _repo.ListAsync(User.GetOrgId());
```

## Function-level authorization, not just object-level

The same principle applies to *actions*, not only data: an admin-only endpoint (delete user,
change role, view audit log) must check the caller's privilege server-side on every request, not
rely on the UI simply not rendering the button for non-admins. A caller who knows or guesses the
URL/route can call it directly, bypassing any client-side hiding.

## Deny by default

Structure authorization so that access is denied unless an explicit check grants it, not the
inverse (allowed unless a check denies it) — a new route, a new field, or a refactor that forgets
to add a check should fail closed. A centralized authorization filter/middleware applied at the
routing layer (checked before the handler runs) is harder to accidentally skip on a new endpoint
than a per-handler `if` that has to be remembered every time.

## Verify

1. Reproduce the original finding as a second, unrelated principal: authenticate as user/tenant B
   and attempt the same read/write B has no legitimate claim to (a different user's record, a
   different tenant's data, an admin action from a non-admin account). It must be rejected — a
   404/403, not the resource.
2. Add a regression test asserting the cross-principal case specifically, not just that the
   legitimate owner can still access their own resource — a fix that only re-tests the happy path
   does not pin the bug.
3. Run the project's test suite.
4. Re-run whatever SAST/DAST tool originally flagged the finding, or re-scan the dependency
   through dependably if the issue was in a third-party package (`OSV_ID`, `PACKAGE_PURL`).
