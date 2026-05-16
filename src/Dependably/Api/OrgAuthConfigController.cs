using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// SAML / auth-config surface — split off OrgController (#61). Owns the tenant's
/// IdP relationship: read the current config + SP info, update toggles + SP fields,
/// upload IdP metadata XML, and wipe the config back to forms-only.
///
/// Routes are unchanged (api/v1/auth-config*) so frontend and integration tests do
/// not need to update.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgAuthConfigController : ControllerBase
{
    private readonly OrgAccessGuard _guard;
    private readonly SamlConfigRepository _samlConfig;
    private readonly AuditRepository _audit;
    private readonly IPublicUrlBuilder _urls;
    private readonly ProblemResults _problems;

    public OrgAuthConfigController(
        OrgAccessGuard guard,
        SamlConfigRepository samlConfig,
        AuditRepository audit,
        IPublicUrlBuilder urls,
        ProblemResults problems)
    {
        _guard = guard;
        _samlConfig = samlConfig;
        _audit = audit;
        _urls = urls;
        _problems = problems;
    }

    /// <summary>GET /api/v1/auth-config — current SAML config + SP info for the IdP admin.</summary>
    [HttpGet("api/v1/auth-config")]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        var cfg = await _samlConfig.GetAsync(orgId, ct);
        var defaultSpEntityId = _urls.Absolute(HttpContext, "/saml/metadata");
        var acsUrl = _urls.Absolute(HttpContext, "/saml/acs");
        var metadataUrl = defaultSpEntityId;

        // Surface the SP-side URLs the IdP admin needs to register, regardless of whether the
        // tenant has uploaded IdP metadata yet.
        return Ok(new
        {
            enabled = cfg?.Enabled ?? false,
            formsLoginEnabled = cfg?.FormsLoginEnabled ?? true,
            idpEntityId = cfg?.IdpEntityId,
            idpSsoUrl = cfg?.IdpSsoUrl,
            idpSigningCertThumbprint = ThumbprintOrNull(cfg?.IdpSigningCert),
            spEntityId = cfg?.SpEntityId ?? defaultSpEntityId,
            nameIdFormat = cfg?.NameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            emailAttribute = cfg?.EmailAttribute,
            buttonLabel = cfg?.ButtonLabel,
            lastTestAt = cfg?.LastTestAt,
            lastTestEmail = cfg?.LastTestEmail,
            spInfo = new { acsUrl, metadataUrl, defaultSpEntityId },
        });
    }

    /// <summary>PUT /api/v1/auth-config — update toggles + SP settings.</summary>
    [HttpPut("api/v1/auth-config")]
    public async Task<IActionResult> Put([FromBody] UpdateAuthConfigRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.NameIdFormat))
            return _problems.ValidationErrorAction("nameIdFormat", "nameIdFormat is required.");

        var orgId = CurrentTenantId();
        var existing = await _samlConfig.GetAsync(orgId, ct);

        // Lockout guard: disabling forms login requires SAML to be enabled AND a successful
        // test within the last 10 minutes. Otherwise a misconfigured IdP locks the tenant out.
        var disablingForms = (existing?.FormsLoginEnabled ?? true) && !req.FormsLoginEnabled;
        if (disablingForms)
        {
            if (!req.Enabled)
                return _problems.ValidationErrorAction("formsLoginEnabled",
                    "Forms login can only be disabled when SAML is enabled.");

            var samlReady = existing is not null
                && !string.IsNullOrWhiteSpace(existing.IdpEntityId)
                && !string.IsNullOrWhiteSpace(existing.IdpSigningCert);
            if (!samlReady)
                return _problems.ValidationErrorAction("formsLoginEnabled",
                    "Upload IdP metadata before disabling forms login.");

            var lastTest = existing!.LastTestAt;
            if (lastTest is null || DateTimeOffset.UtcNow - lastTest.Value > TimeSpan.FromMinutes(10))
                return _problems.ValidationErrorAction("formsLoginEnabled",
                    "Run a successful SAML test within the last 10 minutes before disabling forms login.");
        }

        await _samlConfig.UpsertSettingsAsync(new SamlSettingsUpdate(
            orgId,
            req.Enabled,
            req.FormsLoginEnabled,
            string.IsNullOrWhiteSpace(req.SpEntityId) ? null : req.SpEntityId,
            req.NameIdFormat,
            string.IsNullOrWhiteSpace(req.EmailAttribute) ? null : req.EmailAttribute,
            string.IsNullOrWhiteSpace(req.ButtonLabel) ? null : req.ButtonLabel), ct);

        await _audit.LogAsync("saml.config_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                forms_login_enabled = req.FormsLoginEnabled,
                sp_entity_id = req.SpEntityId,
                name_id_format = req.NameIdFormat,
                email_attribute = req.EmailAttribute,
                button_label = req.ButtonLabel,
            }), ct: ct);

        return NoContent();
    }

    /// <summary>POST /api/v1/auth-config/metadata — upload IdP metadata XML.</summary>
    [HttpPost("api/v1/auth-config/metadata")]
    public async Task<IActionResult> UploadMetadata([FromBody] UploadSamlMetadataRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        if (string.IsNullOrWhiteSpace(req.MetadataXml))
            return _problems.ValidationErrorAction("metadataXml", "metadataXml is required.");

        IdpMetadataParser.ParsedIdp parsed;
        try { parsed = IdpMetadataParser.Parse(req.MetadataXml); }
        catch (Exception ex) { return _problems.ValidationErrorAction("metadataXml", ex.Message); }

        var orgId = CurrentTenantId();
        await _samlConfig.UpsertMetadataAsync(orgId, parsed.EntityId, parsed.SsoUrl, parsed.SigningCertBase64, req.MetadataXml, ct);

        await _audit.LogAsync("saml.metadata_uploaded", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                idp_entity_id = parsed.EntityId,
                idp_sso_url = parsed.SsoUrl,
                cert_thumbprint = ThumbprintOrNull(parsed.SigningCertBase64),
            }), ct: ct);

        return Ok(new
        {
            idpEntityId = parsed.EntityId,
            idpSsoUrl = parsed.SsoUrl,
            idpSigningCertThumbprint = ThumbprintOrNull(parsed.SigningCertBase64),
        });
    }

    /// <summary>DELETE /api/v1/auth-config — wipe SAML config (re-enables forms login).</summary>
    [HttpDelete("api/v1/auth-config")]
    public async Task<IActionResult> Delete(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null) return result;

        var orgId = CurrentTenantId();
        await _samlConfig.DeleteAsync(orgId, ct);
        await _audit.LogAsync("saml.config_deleted", orgId, GetUserId(), ct: ct);
        return NoContent();
    }

    private static string? ThumbprintOrNull(string? base64Cert)
    {
        if (string.IsNullOrWhiteSpace(base64Cert)) return null;
        try
        {
            var bytes = Convert.FromBase64String(base64Cert.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
            var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
            return cert.Thumbprint;
        }
        catch { return null; }
    }

    private string? GetUserId() =>
        User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
        ?? User.FindFirst("sub")?.Value;

    private string CurrentTenantId() =>
        ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;
}

public sealed record UpdateAuthConfigRequest(
    bool Enabled,
    bool FormsLoginEnabled,
    string? SpEntityId,
    string NameIdFormat,
    string? EmailAttribute,
    string? ButtonLabel);

public sealed record UploadSamlMetadataRequest(string MetadataXml);
