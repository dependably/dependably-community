using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// The org's SBOM author-signature key(s) (ADR-sbom-author-signature): the public verification
/// surface at <see cref="GetPublicKeys"/>, and the authenticated Settings surface — view/rotate
/// — at <see cref="Get"/>/<see cref="Rotate"/>.
/// </summary>
[ApiController]
public sealed class SbomSigningKeyController : OrgScopedControllerBase
{
    private readonly SbomSigningKeyRepository _keys;
    private readonly SbomAuthorSigner _signer;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;

    public SbomSigningKeyController(
        SbomSigningKeyRepository keys, SbomAuthorSigner signer, OrgAccessGuard guard, AuditRepository audit)
    {
        _keys = keys;
        _signer = signer;
        _guard = guard;
        _audit = audit;
    }

    /// <summary>The wire shape one published key takes (camelCase for the SPA and for external consumers alike).</summary>
    public sealed record SbomSigningPublicKeyView(
        string KeyId, string Algorithm, string PublicKeyPem,
        string CreatedAt, string? RetiredAt, string? RevokedAt);

    /// <summary>
    /// GET /api/v1/sbom-signing-keys — every key the org has ever used to sign an exported
    /// document, active or retired, so a consumer can verify a document signed years ago against
    /// a key this org no longer actively signs with. Deliberately unauthenticated: the recipient
    /// of an SBOM is usually a customer or auditor with no account on the registry that produced
    /// it, and gating this behind a capability would stop exactly the party the element exists to
    /// let verify (ADR-sbom-author-signature, "Publishing the verification key"). Deliberately
    /// does NOT serve the document it verifies — the two are never fetched from the same place.
    /// </summary>
    // authz-ok: public key material only (no secret ever leaves SbomSigningKeyRepository), and
    // gating it would stop the exact party the element exists to let verify — an SBOM recipient
    // with no account on this registry. Resolved by request host like every protocol surface.
    [AllowAnonymous]
    [HttpGet("api/v1/sbom-signing-keys")]
    public async Task<IActionResult> GetPublicKeys(CancellationToken ct)
    {
        if (HttpContext.Items[TenantContext.HttpItemsKey] is not TenantContext { IsTenant: true, TenantId: { } orgId })
        {
            return NotFound();
        }

        var keys = await _keys.ListPublicAsync(orgId, ct);
        return Ok(keys.Select(k => new SbomSigningPublicKeyView(
            k.Id, k.Algorithm, k.PublicKeyPem,
            k.CreatedAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            k.RetiredAt?.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            k.RevokedAt?.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))));
    }

    /// <summary>
    /// The wire shape Settings reads for the active key (camelCase for the SPA). <c>State</c> is
    /// one of <see cref="SbomAuthorSigner.SignedState"/>, <see cref="SbomAuthorSigner.UnsignedNoMasterKeyState"/>,
    /// or <see cref="SbomAuthorSigner.UnsignedKeyUnavailableState"/> — the same vocabulary
    /// <c>dependably:signature-state</c> carries on an exported document, so Settings can say
    /// which of the two unsigned reasons applies instead of collapsing them into one "no key"
    /// panel (ADR-sbom-author-signature, "Publishing the verification key").
    /// </summary>
    public sealed record SbomActiveKeyView(
        bool CanSign, bool Exists, string? KeyId, string? PublicKeyPem, string? CreatedAt, string State);

    /// <summary>GET /api/v1/sbom-signing-key — the org's active key, creating it on first read when signing is possible.</summary>
    [Authorize]
    [HttpGet("api/v1/sbom-signing-key")]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var (key, state, _) = await _signer.ResolveAsync(orgId, ct);
        using (key)
        {
            return key is null
                ? Ok(new SbomActiveKeyView(false, false, null, null, null, state))
                : Ok(await ViewForAsync(orgId, key, state, ct));
        }
    }

    /// <summary>
    /// POST /api/v1/sbom-signing-key/rotate — retires the org's current key and mints a fresh
    /// one. Every document already signed under the retired key stays verifiable: its public
    /// half stays published at <see cref="GetPublicKeys"/> indefinitely.
    /// </summary>
    [Authorize]
    [HttpPost("api/v1/sbom-signing-key/rotate")]
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
                "SBOM signing is unavailable: this instance has no DEPENDABLY_MASTER_KEY, so no signing key can be stored.");
        }

        using var rotated = await _keys.RotateAsync(orgId, ct);
        await _audit.LogAsync("sbom_signing_key_rotated", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { keyId = rotated.Id },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return Ok(await ViewForAsync(orgId, rotated, SbomAuthorSigner.SignedState, ct));
    }

    // Reads the key's real CreatedAt back from ListPublicAsync rather than approximating it with
    // a fresh wall-clock read: SbomSigningKey (the private-key-bearing type GetOrCreateAsync/
    // RotateAsync return) does not carry the instant, unlike HexSigningKey, and the repository's
    // own stored value is the source of truth Settings must display.
    private async Task<SbomActiveKeyView> ViewForAsync(string orgId, SbomSigningKey key, string state, CancellationToken ct)
    {
        var published = await _keys.ListPublicAsync(orgId, ct);
        var self = published.FirstOrDefault(k => k.Id == key.Id);
        string? createdAt = self?.CreatedAt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        return new SbomActiveKeyView(true, true, key.Id, key.PrivateKey.ExportSubjectPublicKeyInfoPem(), createdAt, state);
    }
}
