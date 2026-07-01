using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// SAML / auth-config surface — split off OrgController. Owns the tenant's
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
    private readonly TimeProvider _time;

    public OrgAuthConfigController(
        OrgAccessGuard guard,
        SamlConfigRepository samlConfig,
        AuditRepository audit,
        IPublicUrlBuilder urls,
        ProblemResults problems,
        TimeProvider time)
    {
        _guard = guard;
        _samlConfig = samlConfig;
        _audit = audit;
        _urls = urls;
        _problems = problems;
        _time = time;
    }

    /// <summary>GET /api/v1/auth-config — current SAML config + SP info for the IdP admin.</summary>
    [HttpGet("api/v1/auth-config")]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var cfg = await _samlConfig.GetAsync(orgId, ct);
        string defaultSpEntityId = _urls.Absolute(HttpContext, "/saml/metadata");
        string acsUrl = _urls.Absolute(HttpContext, "/saml/acs");
        string metadataUrl = defaultSpEntityId;

        // Surface the SP-side URLs the IdP admin needs to register, regardless of whether the
        // tenant has uploaded IdP metadata yet.
        return Ok(new
        {
            enabled = cfg?.Enabled ?? false,
            formsLoginEnabled = cfg?.FormsLoginEnabled ?? true,
            idpEntityId = cfg?.IdpEntityId,
            idpSsoUrl = cfg?.IdpSsoUrl,
            idpSigningCertThumbprint = ThumbprintOrNull(cfg?.IdpSigningCert),
            idpSigningCertOverrideThumbprint = ThumbprintOrNull(cfg?.IdpSigningCertOverride),
            samlIdpCert = BuildCertStatus(cfg, _time.GetUtcNow()),
            spEntityId = cfg?.SpEntityId ?? defaultSpEntityId,
            nameIdFormat = cfg?.NameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            emailAttribute = cfg?.EmailAttribute,
            buttonLabel = cfg?.ButtonLabel,
            lastTestAt = cfg?.LastTestAt,
            lastTestEmail = cfg?.LastTestEmail,
            lastTestClaims = ParseClaimsJson(cfg?.LastTestClaims),
            roleAttribute = cfg?.RoleAttribute,
            roleMapping = cfg?.RoleMapping,
            defaultRole = cfg?.DefaultRole ?? "member",
            idpCanAssignAdmin = cfg?.IdpCanAssignAdmin ?? false,
            spInfo = new { acsUrl, metadataUrl, defaultSpEntityId },
        });
    }

    /// <summary>PUT /api/v1/auth-config — update toggles + SP settings.</summary>
    [HttpPut("api/v1/auth-config")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Put([FromBody] UpdateAuthConfigRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (string.IsNullOrWhiteSpace(req.NameIdFormat))
        {
            return _problems.ValidationErrorAction("nameIdFormat", "nameIdFormat is required.");
        }

        // NameID format must be a valid absolute URI — the SAML 2.0 spec mandates
        // URI-format identifiers for NameID format values.
        if (!Uri.TryCreate(req.NameIdFormat, UriKind.Absolute, out _))
        {
            return _problems.ValidationErrorAction("nameIdFormat",
                "nameIdFormat must be a valid absolute URI (e.g. urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress).");
        }

        string orgId = CurrentTenantId();
        var existing = await _samlConfig.GetAsync(orgId, ct);

        // Lockout guard: disabling forms login requires SAML to be enabled AND a successful
        // test within the last 10 minutes. Otherwise a misconfigured IdP locks the tenant out.
        bool disablingForms = (existing?.FormsLoginEnabled ?? true) && !req.FormsLoginEnabled;
        if (disablingForms)
        {
            var lockoutError = ValidateFormsLoginDisable(existing, req);
            if (lockoutError is not null)
            {
                return lockoutError;
            }
        }

        await _samlConfig.UpsertSettingsAsync(new SamlSettingsUpdate(
            orgId,
            req.Enabled,
            req.FormsLoginEnabled,
            string.IsNullOrWhiteSpace(req.SpEntityId) ? null : req.SpEntityId,
            req.NameIdFormat,
            string.IsNullOrWhiteSpace(req.EmailAttribute) ? null : req.EmailAttribute,
            string.IsNullOrWhiteSpace(req.ButtonLabel) ? null : req.ButtonLabel,
            string.IsNullOrWhiteSpace(req.RoleAttribute) ? null : req.RoleAttribute,
            string.IsNullOrWhiteSpace(req.RoleMapping) ? null : req.RoleMapping,
            string.IsNullOrWhiteSpace(req.DefaultRole) ? "member" : req.DefaultRole,
            req.IdpCanAssignAdmin), ct);

        await _audit.LogAsync("saml.config_updated", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                enabled = req.Enabled,
                forms_login_enabled = req.FormsLoginEnabled,
                sp_entity_id = req.SpEntityId,
                name_id_format = req.NameIdFormat,
                email_attribute = req.EmailAttribute,
                button_label = req.ButtonLabel,
                role_attribute = req.RoleAttribute,
                default_role = req.DefaultRole,
                idp_can_assign_admin = req.IdpCanAssignAdmin,
            }), ct: ct);

        return NoContent();
    }

    /// <summary>POST /api/v1/auth-config/metadata — upload IdP metadata XML.</summary>
    [HttpPost("api/v1/auth-config/metadata")]
    public async Task<IActionResult> UploadMetadata([FromBody] UploadSamlMetadataRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (string.IsNullOrWhiteSpace(req.MetadataXml))
        {
            return _problems.ValidationErrorAction("metadataXml", "metadataXml is required.");
        }

        string orgId = CurrentTenantId();
        var existing = await _samlConfig.GetAsync(orgId, ct);
        bool hasOverride = !string.IsNullOrWhiteSpace(existing?.IdpSigningCertOverride);

        IdpMetadataParser.ParsedIdp parsed;
        try { parsed = IdpMetadataParser.Parse(req.MetadataXml, requireCert: !hasOverride); }
        catch (Exception ex) { return _problems.ValidationErrorAction("metadataXml", ex.Message); }

        await _samlConfig.UpsertMetadataAsync(orgId, parsed.EntityId, parsed.SsoUrl, parsed.SigningCertBase64, req.MetadataXml, ct);
        // Cert changed — reset the alert stage so the sweep re-evaluates against the new cert.
        await _samlConfig.ResetCertExpiryAlertStageAsync(orgId, ct);

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
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        await _samlConfig.DeleteAsync(orgId, ct);
        await _audit.LogAsync("saml.config_deleted", orgId, GetUserId(), ct: ct);
        return NoContent();
    }

    /// <summary>POST /api/v1/auth-config/signing-cert — set the admin-pinned IdP signing certificate override.</summary>
    [HttpPost("api/v1/auth-config/signing-cert")]
    public async Task<IActionResult> SetSigningCert([FromBody] SetSigningCertRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        if (string.IsNullOrWhiteSpace(req.Certificate))
        {
            return _problems.ValidationErrorAction("certificate", "certificate is required.");
        }

        // Accept PEM or raw base64 DER.
        string certBase64;
        try { certBase64 = NormalizeCertInput(req.Certificate); }
        catch (Exception ex) { return _problems.ValidationErrorAction("certificate", ex.Message); }

        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        try
        {
            byte[] bytes = Convert.FromBase64String(certBase64);
            cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
        }
        catch { return _problems.ValidationErrorAction("certificate", "Certificate is not valid base64 X.509."); }

        // Compute summary for response + audit.
        var summary = CertSummary(cert);

        string orgId = CurrentTenantId();
        await _samlConfig.SetSigningCertOverrideAsync(orgId, certBase64, ct);
        // Cert override changed — reset alert stage so the sweep re-evaluates against the new cert.
        await _samlConfig.ResetCertExpiryAlertStageAsync(orgId, ct);
        await _audit.LogAsync("saml.signing_cert_set", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                fingerprint = summary.Fingerprint,
                subject = summary.Subject,
                not_after = summary.NotAfter,
            }), ct: ct);

        return Ok(summary);
    }

    /// <summary>DELETE /api/v1/auth-config/signing-cert — clear the override, reverting to metadata cert.</summary>
    [HttpDelete("api/v1/auth-config/signing-cert")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> ClearSigningCert(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        var existing = await _samlConfig.GetAsync(orgId, ct);
        if (string.IsNullOrWhiteSpace(existing?.IdpSigningCertOverride))
        {
            return NoContent(); // already clear, idempotent
        }

        await _samlConfig.ClearSigningCertOverrideAsync(orgId, ct);
        // Override cleared — reset alert stage so the sweep re-evaluates against the metadata cert.
        await _samlConfig.ResetCertExpiryAlertStageAsync(orgId, ct);
        await _audit.LogAsync("saml.signing_cert_cleared", orgId, GetUserId(), ct: ct);
        return NoContent();
    }

    // Returns null only when the lockout preconditions are met; otherwise the validation
    // error to short-circuit the caller with.
    private IActionResult? ValidateFormsLoginDisable(TenantSamlConfig? existing, UpdateAuthConfigRequest req)
    {
        if (!req.Enabled)
        {
            return _problems.ValidationErrorAction("formsLoginEnabled",
                "Forms login can only be disabled when SAML is enabled.");
        }

        bool samlReady = existing is not null
            && !string.IsNullOrWhiteSpace(existing.IdpEntityId)
            && (!string.IsNullOrWhiteSpace(existing.IdpSigningCert) || !string.IsNullOrWhiteSpace(existing.IdpSigningCertOverride));
        if (!samlReady)
        {
            return _problems.ValidationErrorAction("formsLoginEnabled",
                "Upload IdP metadata before disabling forms login.");
        }

        var lastTest = existing!.LastTestAt;
        return lastTest is null || _time.GetUtcNow() - lastTest.Value > TimeSpan.FromMinutes(10)
            ? _problems.ValidationErrorAction("formsLoginEnabled",
                "Run a successful SAML test within the last 10 minutes before disabling forms login.")
            : null;
    }

    private static readonly System.Text.Json.JsonSerializerOptions ClaimsJsonOptions =
        new() { PropertyNameCaseInsensitive = true };

    private static object[] ParseClaimsJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<object>();
        }

        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<object[]>(json, ClaimsJsonOptions)
                ?? Array.Empty<object>();
        }
        catch { return Array.Empty<object>(); }
    }

    private static string NormalizeCertInput(string input)
    {
        string trimmed = input.Trim();
        // PEM format: strip header/footer and whitespace.
        if (trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
        {
            string[] lines = trimmed.Split('\n');
            string b64 = string.Concat(
                lines
                    .Where(l => !l.StartsWith("-----", StringComparison.Ordinal))
                    .Select(l => l.Trim()));
            return b64;
        }
        // Raw base64 DER: strip any whitespace.
        return new string(trimmed.Where(c => !char.IsWhiteSpace(c)).ToArray());
    }

    private static (string Fingerprint, string Subject, string Issuer, string NotBefore, string NotAfter) CertSummary(
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert) =>
        (
            Fingerprint: cert.Thumbprint,
            Subject: cert.Subject,
            Issuer: cert.Issuer,
            NotBefore: cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            NotAfter: cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        );

    private static string? ThumbprintOrNull(string? base64Cert)
    {
        if (string.IsNullOrWhiteSpace(base64Cert))
        {
            return null;
        }

        try
        {
            byte[] bytes = Convert.FromBase64String(base64Cert.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
            var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
            return cert.Thumbprint;
        }
        catch { return null; }
    }

    // Builds the samlIdpCert status block for the GET /api/v1/auth-config response.
    // Returns null when no cert is configured. The effective cert is the override when set,
    // otherwise the metadata cert. Status is computed on read — not stored.
    private static object? BuildCertStatus(TenantSamlConfig? cfg, DateTimeOffset now)
    {
        if (cfg is null)
        {
            return null;
        }

        string? effectiveCert = !string.IsNullOrWhiteSpace(cfg.IdpSigningCertOverride)
            ? cfg.IdpSigningCertOverride
            : cfg.IdpSigningCert;

        if (string.IsNullOrWhiteSpace(effectiveCert))
        {
            return null;
        }

        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        try
        {
            byte[] bytes = Convert.FromBase64String(
                effectiveCert.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
            cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
        }
        catch { return null; }

        var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        double daysRemaining = (notAfter - now).TotalDays;

        string status = daysRemaining < 0
            ? "expired"
            : daysRemaining <= 7
                ? "expiring"
                : "ok";

        return new
        {
            thumbprint = cert.Thumbprint,
            notBefore = cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            notAfter = notAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            daysRemaining = (int)Math.Floor(daysRemaining),
            status,
        };
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
    string? ButtonLabel,
    string? RoleAttribute,
    string? RoleMapping,
    string? DefaultRole,
    bool IdpCanAssignAdmin = false);

public sealed record UploadSamlMetadataRequest(string MetadataXml);

public sealed record SetSigningCertRequest(string Certificate);
