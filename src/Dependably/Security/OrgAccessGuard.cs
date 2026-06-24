using System.Security.Claims;
using Dapper;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Security;

/// <summary>
/// BOLA (Broken Object-Level Authorization) guard — OWASP API1:2023.
/// Returns 404 (not 403) for orgs the principal is not a member of, to prevent slug enumeration.
/// Returns 403 if the principal lacks the required role within a valid org.
///
/// Phase 2: the legacy <c>instance_admin</c> bypass has been removed. system_admin tokens
/// (multi-mode operator identity) carry <c>scope=system</c> and are blocked from tenant routes
/// at the global <c>RouteScopeFilter</c> layer; they never reach this guard. Existing
/// <c>is_admin = 1</c> users still authenticate via tenant login and get tenant JWTs whose
/// access is governed entirely by their <c>org_members</c> row, the same as any other user.
/// </summary>
public sealed class OrgAccessGuard
{
    private readonly IMetadataStore _db;

    public OrgAccessGuard(IMetadataStore db)
    {
        _db = db;
    }

    public enum AccessResult { Allowed, NotFound, Forbidden }

    /// <summary>
    /// Verifies tenant membership (404 invariant preserved) and checks the caller's effective
    /// capability set against <paramref name="requiredCapability"/>. Effective set: explicit
    /// <c>cap</c> claims when present (token-narrowed API tokens) else
    /// <see cref="Capabilities.ForRole"/> based on the user's current DB role.
    /// </summary>
    public async Task<AccessResult> CheckCapAsync(
        ClaimsPrincipal principal,
        string userId,
        string orgId,
        string requiredCapability,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (TenantId, Role) = await conn.QuerySingleOrDefaultAsync<(string? TenantId, string? Role)>(
            "SELECT tenant_id as TenantId, role as Role FROM users WHERE id = @userId AND tenant_id = @orgId",
            new { orgId, userId });

        if (TenantId is null)
        {
            return AccessResult.NotFound;
        }

        var granted = ResolveCallerCapabilities(principal, Role);
        return Capabilities.Grants(granted, requiredCapability)
            ? AccessResult.Allowed
            : AccessResult.Forbidden;
    }

    /// <summary>
    /// Capability-driven authorization for controllers. Reads the resolved
    /// <see cref="TenantContext"/>, verifies tenant membership (404 invariant), then checks
    /// <paramref name="requiredCapability"/> against the caller's effective capability set
    /// (explicit <c>cap</c> claims, else <see cref="Capabilities.ForRole"/>).
    /// Returns an <see cref="IActionResult"/> on failure or <c>null</c> when access is allowed.
    /// </summary>
    public async Task<IActionResult?> AuthorizeCapAsync(
        ClaimsPrincipal principal,
        HttpContext httpContext,
        string requiredCapability,
        CancellationToken ct = default)
    {
        if (httpContext.Items[TenantContext.HttpItemsKey] is not TenantContext ctx || !ctx.IsTenant || ctx.TenantId is null)
        {
            return new NotFoundResult();
        }

        string? userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.FindFirst("sub")?.Value;
        if (userId is null)
        {
            return new UnauthorizedResult();
        }

        var result = await CheckCapAsync(principal, userId, ctx.TenantId, requiredCapability, ct);
        return result switch
        {
            AccessResult.NotFound => new NotFoundResult(),
            AccessResult.Forbidden => new ForbidResult(),
            _ => null,
        };
    }

    /// <summary>
    /// Membership-only authorization for controllers. Reads the resolved
    /// <see cref="TenantContext"/>, verifies the caller is a member of the tenant (404 on
    /// no-match), and returns <c>null</c> on success — no capability comparison is performed.
    /// All four tenant roles (member/admin/owner/auditor) pass. Non-members get 404 so
    /// the org slug is not enumerable.
    /// </summary>
    public async Task<IActionResult?> AuthorizeMemberAsync(
        ClaimsPrincipal principal,
        HttpContext httpContext,
        CancellationToken ct = default)
    {
        if (httpContext.Items[TenantContext.HttpItemsKey] is not TenantContext ctx || !ctx.IsTenant || ctx.TenantId is null)
        {
            return new NotFoundResult();
        }

        string? userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.FindFirst("sub")?.Value;
        if (userId is null)
        {
            return new UnauthorizedResult();
        }

        await using var conn = await _db.OpenAsync(ct);
        string? tenantId = await conn.ExecuteScalarAsync<string?>(
            "SELECT tenant_id FROM users WHERE id = @userId AND tenant_id = @orgId",
            new { userId, orgId = ctx.TenantId });

        return tenantId is null ? new NotFoundResult() : null;
    }

    // Canonical effective-capability resolution, mirroring CapabilityHandler so every
    // authorization surface (route guards and management-API token minting alike) computes
    // the caller's privilege ceiling the same way: explicit cap claims (token-narrowed) win;
    // otherwise the user's current DB role drives. system_admin isn't handled here because
    // RouteScopeFilter already blocks operator tokens from tenant routes before they reach
    // this guard.
    internal static IReadOnlySet<string> ResolveCallerCapabilities(ClaimsPrincipal principal, string? dbRole)
    {
        var explicitCaps = principal.FindAll("cap")
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToHashSet(StringComparer.Ordinal);

        return explicitCaps.Count > 0
            ? explicitCaps
            : Capabilities.ForRole(dbRole ?? "member");
    }
}
