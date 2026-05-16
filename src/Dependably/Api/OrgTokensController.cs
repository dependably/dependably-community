using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// User and CI/CD access tokens. Split out of <see cref="OrgController"/> (#61): tokens are
/// a single REST resource with member-scoped CRUD (user) and admin-scoped CRUD (CI/CD).
/// Capability validation uses the caller's role grants as the ceiling — admins can mint
/// tokens with capabilities they themselves hold, never above.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgTokensController : OrgScopedControllerBase
{
    private readonly TokenRepository _tokens;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly IAuditEmitter _auditEmitter;
    private readonly ProblemResults _problems;

    public OrgTokensController(
        TokenRepository tokens,
        OrgAccessGuard guard,
        AuditRepository audit,
        IAuditEmitter auditEmitter,
        ProblemResults problems)
    {
        _tokens = tokens;
        _guard = guard;
        _audit = audit;
        _auditEmitter = auditEmitter;
        _problems = problems;
    }

    /// <summary>GET /api/v1/orgs/{org}/tokens</summary>
    [HttpGet("api/v1/tokens")]
    public async Task<IActionResult> ListTokens(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ManageOwnTokens, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var userId = GetUserId();
        if (userId is null) return Forbid();
        var list = await _tokens.ListUserTokensAsync(orgId, userId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/tokens</summary>
    [HttpPost("api/v1/tokens")]
    [EnableRateLimiting("token-create")]
    public async Task<IActionResult> CreateToken([FromBody] CreateTokenRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ManageOwnTokens, ct);
        if (result is not null) return result;

        // Retired-field guard: callers updating from the legacy `scope` shorthand get a
        // clear 400 instead of having their intent silently dropped.
        if (req.Scope is not null)
            return _problems.ValidationErrorAction("scope",
                "The 'scope' field is no longer accepted. Send 'capabilities' instead.");

        var orgId = CurrentTenantId();
        var userId = GetUserId();
        if (userId is null) return Forbid();

        var role = User.FindFirst("role")?.Value ?? "member";
        var callerGrants = Capabilities.ForRole(role);

        if (!Capabilities.TryNormalizeAndAuthorize(
                req.Capabilities, callerGrants,
                out var canonicalJson, out var caps, out var error, out var field))
            return _problems.ValidationErrorAction(field ?? "capabilities", error!);

        var (raw, record) = await _tokens.CreateUserTokenAsync(
            orgId, userId, canonicalJson, req.ExpiresAt, ct);

        await _audit.LogAsync("token_created", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                token_id = record.Id,
                capabilities_json = canonicalJson,
                capabilities = caps,
                expires_at = record.ExpiresAt,
            }), ct: ct);
        await _auditEmitter.EmitAsync(
            TenantEvents.TypeTokenCreate,
            orgId, "user", userId, "accepted",
            new TenantEvents.TokenCreate(record.Id, canonicalJson, caps, "user", record.ExpiresAt).ToJson(), ct);

        return Ok(new { token = raw, record });
    }

    /// <summary>DELETE /api/v1/orgs/{org}/tokens/{id} — members may revoke their own; admin/owner may revoke any</summary>
    [HttpDelete("api/v1/tokens/{id}")]
    public async Task<IActionResult> DeleteToken(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ManageOwnTokens, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var userId = GetUserId()!;

        // Admin/owner can revoke any token in the org; members can only revoke their own.
        // tenant:configure is the management-override cap (admin + owner both have it).
        var adminCheck = await _guard.CheckCapAsync(User, userId, orgId, Capabilities.TenantConfigure, ct);
        if (adminCheck != OrgAccessGuard.AccessResult.Allowed)
        {
            var token = await _tokens.GetTokenByIdAsync(id, ct);
            if (token is null || token.UserId != userId)
                return Forbid();
        }

        await _tokens.DeleteTokenAsync(id, ct);

        await _audit.LogAsync("token_revoked", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new { token_id = id }), ct: ct);
        await _auditEmitter.EmitAsync(
            TenantEvents.TypeTokenRevoke,
            orgId, "user", userId, "accepted",
            new TenantEvents.TokenRevoke(id, "user").ToJson(), ct);

        return NoContent();
    }

    /// <summary>GET /api/v1/orgs/{org}/cicd-tokens</summary>
    [HttpGet("api/v1/cicd-tokens")]
    public async Task<IActionResult> ListCicdTokens(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var list = await _tokens.ListCicdTokensAsync(orgId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/cicd-tokens</summary>
    [HttpPost("api/v1/cicd-tokens")]
    [EnableRateLimiting("token-create")]
    public async Task<IActionResult> CreateCicdToken([FromBody] CreateCicdTokenRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.Name))
            return _problems.ValidationErrorAction("name", "Name is required.");

        if (req.Scope is not null)
            return _problems.ValidationErrorAction("scope",
                "The 'scope' field is no longer accepted. Send 'capabilities' instead.");

        // CI/CD tokens are minted under tenant:configure; the caller's role grants form the
        // ceiling. The minted token still gets its own narrowed cap set.
        var role = User.FindFirst("role")?.Value ?? "member";
        var callerGrants = Capabilities.ForRole(role);

        if (!Capabilities.TryNormalizeAndAuthorize(
                req.Capabilities, callerGrants,
                out var canonicalJson, out var caps, out var error, out var field))
            return _problems.ValidationErrorAction(field ?? "capabilities", error!);

        var orgId = CurrentTenantId();
        var (raw, record) = await _tokens.CreateCicdTokenAsync(orgId, req.Name, canonicalJson, req.ExpiresAt, ct);

        await _audit.LogAsync("cicd_token_created", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                token_id = record.Id,
                name = record.Name,
                capabilities_json = canonicalJson,
                capabilities = caps,
                expires_at = record.ExpiresAt,
            }), ct: ct);
        await _auditEmitter.EmitAsync(
            TenantEvents.TypeTokenCreate,
            orgId, "user", GetUserId(), "accepted",
            new TenantEvents.TokenCreate(record.Id, canonicalJson, caps, "cicd", record.ExpiresAt).ToJson(), ct);

        return Ok(new { token = raw, record });
    }

    /// <summary>DELETE /api/v1/orgs/{org}/cicd-tokens/{id}</summary>
    [HttpDelete("api/v1/cicd-tokens/{id}")]
    public async Task<IActionResult> DeleteCicdToken(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        await _tokens.DeleteCicdTokenAsync(id, ct);

        await _audit.LogAsync("cicd_token_revoked", CurrentTenantId(), GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { token_id = id }), ct: ct);
        await _auditEmitter.EmitAsync(
            TenantEvents.TypeTokenRevoke,
            CurrentTenantId(), "user", GetUserId(), "accepted",
            new TenantEvents.TokenRevoke(id, "cicd").ToJson(), ct);

        return NoContent();
    }
}
