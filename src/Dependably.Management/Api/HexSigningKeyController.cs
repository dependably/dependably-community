using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// The org's Hex registry signing key, as Settings shows it: the public half, its fingerprint,
/// and the rotate action. The private half never leaves the server. Rotation is a
/// client-visible event — every consumer registered the repository with the old public key and
/// verifies each resource against it, so after a rotation they all re-register — which is why
/// it is an explicit operator action rather than a schedule.
/// </summary>
[ApiController]
[Authorize]
public sealed class HexSigningKeyController : OrgScopedControllerBase
{
    private readonly HexSigningKeyRepository _keys;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;

    public HexSigningKeyController(HexSigningKeyRepository keys, OrgAccessGuard guard, AuditRepository audit)
    {
        _keys = keys;
        _guard = guard;
        _audit = audit;
    }

    /// <summary>The wire shape of the key as Settings and the setup page read it (camelCase for the SPA).</summary>
    public sealed record HexSigningKeyView(bool CanSign, bool Exists, string? PublicKeyPem, string? Fingerprint, string? CreatedAt);

    /// <summary>GET /api/v1/hex/signing-key — the public half of the org's key, creating the key on first read when signing is possible.</summary>
    [HttpGet("api/v1/hex/signing-key")]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        if (!_keys.CanSign)
        {
            var existing = await _keys.GetPublicAsync(orgId, ct);
            return Ok(new HexSigningKeyView(false, existing is not null, existing?.PublicKeyPem, existing?.Fingerprint, existing?.CreatedAt));
        }

        using var key = await _keys.GetOrCreateAsync(orgId, ct);
        return Ok(new HexSigningKeyView(true, key is not null, key?.PublicKeyPem, key?.Fingerprint, key?.CreatedAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    }

    /// <summary>POST /api/v1/hex/signing-key/rotate — replaces the org's key; every Hex client must re-register the repository afterwards.</summary>
    [HttpPost("api/v1/hex/signing-key/rotate")]
    public async Task<IActionResult> Rotate(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        if (!_keys.CanSign)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                "Hex registry signing is unavailable: this instance has no DEPENDABLY_MASTER_KEY, so no signing key can be stored.");
        }

        using var rotated = await _keys.RotateAsync(orgId, ct);
        await _audit.LogAsync("hex_signing_key_rotated", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { fingerprint = rotated.Fingerprint },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return Ok(new HexSigningKeyView(true, true, rotated.PublicKeyPem, rotated.Fingerprint, rotated.CreatedAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    }
}
