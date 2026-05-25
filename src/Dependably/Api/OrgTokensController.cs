using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// User and service access tokens. Split out of <see cref="OrgController"/> (#61): tokens are
/// a single REST resource with member-scoped CRUD (user) and admin-scoped CRUD (service).
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

        if (!TryNormalizeDescription(req.Description, out var description, out var descError))
            return _problems.ValidationErrorAction("description", descError!);

        var (raw, record) = await _tokens.CreateUserTokenAsync(
            orgId, userId, canonicalJson, req.ExpiresAt, description, ct);

        await _audit.LogAsync("token_created", orgId, userId,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                token_id = record.Id,
                capabilities_json = canonicalJson,
                capabilities = caps,
                expires_at = record.ExpiresAt,
                description,
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

    /// <summary>GET /api/v1/orgs/{org}/service-tokens</summary>
    [HttpGet("api/v1/service-tokens")]
    public async Task<IActionResult> ListServiceTokens(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var list = await _tokens.ListServiceTokensAsync(orgId, ct);
        return Ok(list);
    }

    /// <summary>POST /api/v1/orgs/{org}/service-tokens</summary>
    [HttpPost("api/v1/service-tokens")]
    [EnableRateLimiting("token-create")]
    public async Task<IActionResult> CreateServiceToken([FromBody] CreateServiceTokenRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.Name))
            return _problems.ValidationErrorAction("name", "Name is required.");

        if (req.Scope is not null)
            return _problems.ValidationErrorAction("scope",
                "The 'scope' field is no longer accepted. Send 'capabilities' instead.");

        // Service tokens are minted under tenant:configure; the caller's role grants form the
        // ceiling. The minted token still gets its own narrowed cap set.
        var role = User.FindFirst("role")?.Value ?? "member";
        var callerGrants = Capabilities.ForRole(role);

        if (!Capabilities.TryNormalizeAndAuthorize(
                req.Capabilities, callerGrants,
                out var canonicalJson, out var caps, out var error, out var field))
            return _problems.ValidationErrorAction(field ?? "capabilities", error!);

        if (!TryNormalizeDescription(req.Description, out var description, out var descError))
            return _problems.ValidationErrorAction("description", descError!);

        var orgId = CurrentTenantId();
        var (raw, record) = await _tokens.CreateServiceTokenAsync(orgId, req.Name, canonicalJson, req.ExpiresAt, description, ct);

        await _audit.LogAsync("service_token_created", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                token_id = record.Id,
                name = record.Name,
                capabilities_json = canonicalJson,
                capabilities = caps,
                expires_at = record.ExpiresAt,
                description,
            }), ct: ct);
        await _auditEmitter.EmitAsync(
            TenantEvents.TypeTokenCreate,
            orgId, "user", GetUserId(), "accepted",
            new TenantEvents.TokenCreate(record.Id, canonicalJson, caps, "service", record.ExpiresAt).ToJson(), ct);

        return Ok(new { token = raw, record });
    }

    /// <summary>DELETE /api/v1/orgs/{org}/service-tokens/{id}</summary>
    [HttpDelete("api/v1/service-tokens/{id}")]
    public async Task<IActionResult> DeleteServiceToken(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        await _tokens.DeleteServiceTokenAsync(id, ct);

        await _audit.LogAsync("service_token_revoked", CurrentTenantId(), GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { token_id = id }), ct: ct);
        await _auditEmitter.EmitAsync(
            TenantEvents.TypeTokenRevoke,
            CurrentTenantId(), "user", GetUserId(), "accepted",
            new TenantEvents.TokenRevoke(id, "service").ToJson(), ct);

        return NoContent();
    }

    private const int MaxDescriptionLength = 200;

    // Normalize the optional description: trim, treat empty as null, reject control chars
    // (operators see this string in the UI; \r\n in a table cell breaks the row layout) and
    // bound the length so a malicious caller can't pad rows with megabytes of text.
    private static bool TryNormalizeDescription(string? raw, out string? normalized, out string? error)
    {
        normalized = null;
        error = null;
        if (raw is null) return true;
        var trimmed = raw.Trim();
        if (trimmed.Length == 0) return true;
        if (trimmed.Length > MaxDescriptionLength)
        {
            error = $"Description must be {MaxDescriptionLength} characters or fewer.";
            return false;
        }
        if (trimmed.Any(char.IsControl))
        {
            error = "Description must not contain control characters.";
            return false;
        }
        normalized = trimmed;
        return true;
    }
}
