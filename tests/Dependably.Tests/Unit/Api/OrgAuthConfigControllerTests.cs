using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Coverage for OrgAuthConfigController (SAML config CRUD): Get / Put / UploadMetadata / Delete
/// plus the private ThumbprintOrNull branch matrix. We use the shared ControllerScenario which
/// wires up the controller against an in-memory SQLite DB and a real OrgAccessGuard, so the
/// auth branches exercise the real capability check (owner = TenantConfigure).
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgAuthConfigControllerTests
{
    // A real, parseable self-signed X.509 cert (base64 DER). Reused from SamlTests to keep
    // tests self-contained without generating a cert at runtime.
    private const string SampleIdpCertBase64 =
        "MIIDazCCAlOgAwIBAgIUGEunzZ+OWXdsAtwLqGqshN1cgrEwDQYJKoZIhvcNAQEL" +
        "BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM" +
        "GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTA1MjAyMzAwMDBaFw0zNTA1" +
        "MTgyMzAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw" +
        "HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB" +
        "AQUAA4IBDwAwggEKAoIBAQDFAKvK3iCY7g7kIYwqRjlJjlsuV5l6Y2J0iC3y0Vqg" +
        "Y31xPsixUaPxnFvuGGRRcRgTGTTC6dJUMKJ5e5ifBaBnUFFhTNcGVE0+E8RHxFMy" +
        "M0gP+8wkLcwQDmH5dCEbAfMsTHM7DM8Z79Cy2VxsCcXOyZqI3JOFI9yEjOI3Q+P+" +
        "wmgYwAS5kRDOFtVnQ7AGn+gXkdhDxiazUVoSp/3CAJpJv2OWoR1Q1F4uZ5wMzG5j" +
        "F0VeQc9k1xMTm5UjnZBmIv5g/0E5lJM1VV20G2QwHy7n2D0XlGoT0eP9TyVxRkP5" +
        "0Hu3qHGFEhKyfdR9MCQyOnyGNeWUuQ0cQRy1bz0fyA2BAgMBAAGjUzBRMB0GA1Ud" +
        "DgQWBBSEgu1u3iYJVK9rCC2wTC5gbA8j4DAfBgNVHSMEGDAWgBSEgu1u3iYJVK9r" +
        "CC2wTC5gbA8j4DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCT" +
        "EWLkSCKKE5wOhKqK6CeY9YDw5KxJF8KK/4xpHFKQqQHCRBYpzPSWldHyDt7nHGzD" +
        "X2cwR+UvEx3CExtTpJoLgnv7AGmGGI8hCwSeplmFvT4LpQAJVUOdGdyBCwm4F8wA" +
        "Q1q2zL2yV1HxgyqyW9X9zKtVbq8eNQwJOl0RnvqHk5wsR3qVOXTZAh5+jB8/V/8w" +
        "kcLcSXrCNL7Zr7vHWGqXNlqfXh1y0WBZIHCq+fJxJ7GxMnpJEKxYxFKMVL5tLZdU" +
        "wHqVc+a+0c0r6r5jnIWZ8M3SAtIp1OYxoQc6lYpKVMaT1WGCB0qZ3sNh+gWA8sM5" +
        "vMmsT2vTuxLR3MS0RhJL";

    private static string IdpMetadataXml(string entityId = "https://idp.example.com/entity",
                                          string ssoUrl = "https://idp.example.com/sso") => $"""
        <?xml version="1.0"?>
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entityId}">
          <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <KeyDescriptor use="signing">
              <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                  <X509Certificate>{SampleIdpCertBase64}</X509Certificate>
                </X509Data>
              </KeyInfo>
            </KeyDescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{ssoUrl}"/>
          </IDPSSODescriptor>
        </EntityDescriptor>
        """;

    // ── GET /api/v1/auth-config ───────────────────────────────────────────────

    [Fact]
    public async Task Get_NoConfig_ReturnsDefaultsAndSpInfo()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Get(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);

        // Verify response shape: defaults when no config row exists.
        var enabled = (bool)ok.Value!.GetType().GetProperty("enabled")!.GetValue(ok.Value)!;
        var formsLoginEnabled = (bool)ok.Value.GetType().GetProperty("formsLoginEnabled")!.GetValue(ok.Value)!;
        var nameIdFormat = (string)ok.Value.GetType().GetProperty("nameIdFormat")!.GetValue(ok.Value)!;
        var thumbprint = ok.Value.GetType().GetProperty("idpSigningCertThumbprint")!.GetValue(ok.Value);
        var spInfo = ok.Value.GetType().GetProperty("spInfo")!.GetValue(ok.Value)!;

        Assert.False(enabled);
        Assert.True(formsLoginEnabled);
        Assert.Equal("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", nameIdFormat);
        Assert.Null(thumbprint);
        Assert.NotNull(spInfo);
    }

    [Fact]
    public async Task Get_WithExistingConfig_ReturnsConfigPlusThumbprint()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Seed a config row with metadata so the Thumbprint branch fires.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_saml_config (
                    org_id, enabled, forms_login_enabled,
                    idp_entity_id, idp_sso_url, idp_signing_cert,
                    sp_entity_id, name_id_format, email_attribute, button_label,
                    last_test_at, last_test_email, updated_at)
                VALUES (
                    @org, 1, 1,
                    'idp-entity', 'https://idp/sso', @cert,
                    'sp-entity', 'emailAddress', 'mail', 'SSO',
                    @now, 'tester@x.test', @now)
                """,
                new
                {
                    org = b.PrimaryOrgId,
                    cert = SampleIdpCertBase64,
                    now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }

        var ok = Assert.IsType<OkObjectResult>(
            await b.OrgAuthConfigController.Get(CancellationToken.None));
        var enabled = (bool)ok.Value!.GetType().GetProperty("enabled")!.GetValue(ok.Value)!;
        var idpEntityId = (string?)ok.Value.GetType().GetProperty("idpEntityId")!.GetValue(ok.Value);
        var thumbprint = (string?)ok.Value.GetType().GetProperty("idpSigningCertThumbprint")!.GetValue(ok.Value);

        Assert.True(enabled);
        Assert.Equal("idp-entity", idpEntityId);
        Assert.False(string.IsNullOrEmpty(thumbprint)); // ThumbprintOrNull happy path
    }

    [Fact]
    public async Task Get_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Get(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task Get_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Get(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    // ── PUT /api/v1/auth-config ──────────────────────────────────────────────

    [Fact]
    public async Task Put_ValidUpdate_PersistsAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: false,
                FormsLoginEnabled: true,
                SpEntityId: "https://sp.example.com",
                NameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                EmailAttribute: "mail",
                ButtonLabel: "SSO"),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var sp = await conn.ExecuteScalarAsync<string?>(
            "SELECT sp_entity_id FROM tenant_saml_config WHERE org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.Equal("https://sp.example.com", sp);

        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'saml.config_updated' AND org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task Put_BlankNameIdFormat_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(false, true, null, "   ", null, null),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, obj.StatusCode);
    }

    [Fact]
    public async Task Put_BlankFieldsCoerceToNull()
    {
        // Hits the three string.IsNullOrWhiteSpace ternary branches for SpEntityId/EmailAttribute/ButtonLabel.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: false, FormsLoginEnabled: true,
                SpEntityId: "  ", NameIdFormat: "fmt",
                EmailAttribute: "", ButtonLabel: null),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var sp = await conn.ExecuteScalarAsync<string?>(
            "SELECT sp_entity_id FROM tenant_saml_config WHERE org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.Null(sp);
    }

    [Fact]
    public async Task Put_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(false, true, null, "fmt", null, null),
            CancellationToken.None);
        Assert.False(result is NoContentResult);
    }

    // ── PUT: forms-disabled lockout guard branches ────────────────────────────

    [Fact]
    public async Task Put_DisableFormsLogin_SamlNotEnabled_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // No existing row → forms is implicitly enabled; disable+SAML-off must reject.
        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: false, FormsLoginEnabled: false,
                SpEntityId: null, NameIdFormat: "fmt",
                EmailAttribute: null, ButtonLabel: null),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, obj.StatusCode);
    }

    [Fact]
    public async Task Put_DisableFormsLogin_NoMetadataYet_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Seed an enabled-forms config without any metadata uploaded.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, name_id_format) " +
                "VALUES (@o, 1, 1, 'fmt')",
                new { o = b.PrimaryOrgId });
        }

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: true, FormsLoginEnabled: false,
                SpEntityId: null, NameIdFormat: "fmt",
                EmailAttribute: null, ButtonLabel: null),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, obj.StatusCode);
    }

    [Fact]
    public async Task Put_DisableFormsLogin_NoRecentTest_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // SAML ready but last test is old (or absent) — must reject.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, " +
                "idp_entity_id, idp_signing_cert, name_id_format) " +
                "VALUES (@o, 1, 1, 'idp', 'cert', 'fmt')",
                new { o = b.PrimaryOrgId });
        }

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: true, FormsLoginEnabled: false,
                SpEntityId: null, NameIdFormat: "fmt",
                EmailAttribute: null, ButtonLabel: null),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, obj.StatusCode);
    }

    [Fact]
    public async Task Put_DisableFormsLogin_AllConditionsMet_Succeeds()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var recent = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, " +
                "idp_entity_id, idp_signing_cert, name_id_format, last_test_at) " +
                "VALUES (@o, 1, 1, 'idp', 'cert', 'fmt', @t)",
                new { o = b.PrimaryOrgId, t = recent });
        }

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: true, FormsLoginEnabled: false,
                SpEntityId: null, NameIdFormat: "fmt",
                EmailAttribute: null, ButtonLabel: null),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    // ── POST /api/v1/auth-config/metadata ─────────────────────────────────────

    [Fact]
    public async Task UploadMetadata_Valid_Returns200AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.UploadMetadata(
            new UploadSamlMetadataRequest(IdpMetadataXml()),
            CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        var entityId = (string)ok.Value!.GetType().GetProperty("idpEntityId")!.GetValue(ok.Value)!;
        var thumbprint = (string?)ok.Value.GetType().GetProperty("idpSigningCertThumbprint")!.GetValue(ok.Value);
        Assert.Equal("https://idp.example.com/entity", entityId);
        Assert.False(string.IsNullOrEmpty(thumbprint));

        await using var conn = await b.Db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'saml.metadata_uploaded' AND org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task UploadMetadata_BlankXml_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.UploadMetadata(
            new UploadSamlMetadataRequest("   "),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, obj.StatusCode);
    }

    [Fact]
    public async Task UploadMetadata_InvalidXml_Returns422()
    {
        // Parser throws → controller catches and returns 422 with the parser message.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.UploadMetadata(
            new UploadSamlMetadataRequest("<not><valid-saml/></not>"),
            CancellationToken.None);
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(422, obj.StatusCode);
    }

    [Fact]
    public async Task UploadMetadata_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.UploadMetadata(
            new UploadSamlMetadataRequest(IdpMetadataXml()),
            CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    // ── DELETE /api/v1/auth-config ────────────────────────────────────────────

    [Fact]
    public async Task Delete_Owner_WipesConfigAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Seed a row so Delete has something to wipe.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, name_id_format) " +
                "VALUES (@o, 1, 0, 'fmt')",
                new { o = b.PrimaryOrgId });
        }

        var result = await b.OrgAuthConfigController.Delete(CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var c2 = await b.Db.OpenAsync();
        var remaining = await c2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_saml_config WHERE org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.Equal(0, remaining);

        var auditCount = await c2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'saml.config_deleted' AND org_id = @o",
            new { o = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task Delete_Member_Forbidden()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.OrgAuthConfigController.Delete(CancellationToken.None);
        Assert.False(result is NoContentResult);
    }

    // ── PUT: lockout-guard bypass branches ───────────────────────────────────

    [Fact]
    public async Task Put_FormsAlreadyDisabled_BypassesLockoutGuard()
    {
        // existing.FormsLoginEnabled = false AND req.FormsLoginEnabled = false
        // → disablingForms is false → guard block is skipped entirely. Covers the
        // "left operand false" branch of the disablingForms predicate.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Seed an existing row with forms already disabled and no SAML metadata —
        // a state that would normally fail the lockout guard if the guard ran.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, name_id_format) " +
                "VALUES (@o, 0, 0, 'fmt')",
                new { o = b.PrimaryOrgId });
        }

        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: false, FormsLoginEnabled: false,
                SpEntityId: null, NameIdFormat: "fmt",
                EmailAttribute: null, ButtonLabel: null),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    [Fact]
    public async Task Put_ReenablingForms_BypassesLockoutGuard()
    {
        // existing.FormsLoginEnabled = false (or true) AND req.FormsLoginEnabled = true
        // → disablingForms is false → guard skipped. Covers the "right operand false"
        // branch of the disablingForms predicate.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, name_id_format) " +
                "VALUES (@o, 1, 0, 'fmt')",
                new { o = b.PrimaryOrgId });
        }

        // SAML-on, forms-on (re-enable). No metadata, no recent test — would fail the
        // guard if it ran, but the guard short-circuits before any of those checks.
        var result = await b.OrgAuthConfigController.Put(
            new UpdateAuthConfigRequest(
                Enabled: true, FormsLoginEnabled: true,
                SpEntityId: null, NameIdFormat: "fmt",
                EmailAttribute: null, ButtonLabel: null),
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }

    // ── GetUserId fallback paths (audit actor) ───────────────────────────────

    [Fact]
    public async Task UploadMetadata_NameIdentifierAbsent_AuditsViaSubClaim()
    {
        // GetUserId() falls back to the "sub" claim when NameIdentifier is missing —
        // covers the right-hand side of the ?? expression that ControllerScenario's
        // default principal (which sets both claims) never exercises.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var userId = b.ActorUserId!;
        b.OrgAuthConfigController.ControllerContext.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("sub", userId),
                new System.Security.Claims.Claim("org_id", b.PrimaryOrgId),
                new System.Security.Claims.Claim("tid", b.PrimaryOrgId),
                new System.Security.Claims.Claim("role", "owner"),
                new System.Security.Claims.Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var result = await b.OrgAuthConfigController.UploadMetadata(
            new UploadSamlMetadataRequest(IdpMetadataXml()),
            CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        await using var conn = await b.Db.OpenAsync();
        var actorId = await conn.ExecuteScalarAsync<string?>(
            "SELECT actor_id FROM audit_log WHERE action = 'saml.metadata_uploaded' AND org_id = @o LIMIT 1",
            new { o = b.PrimaryOrgId });
        Assert.Equal(userId, actorId);
    }

    [Fact]
    public async Task Delete_NameIdentifierAbsent_AuditsViaSubClaim()
    {
        // Same sub-claim-fallback path on the Delete handler.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, name_id_format) " +
                "VALUES (@o, 1, 0, 'fmt')",
                new { o = b.PrimaryOrgId });
        }

        var userId = b.ActorUserId!;
        b.OrgAuthConfigController.ControllerContext.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim("sub", userId),
                new System.Security.Claims.Claim("org_id", b.PrimaryOrgId),
                new System.Security.Claims.Claim("tid", b.PrimaryOrgId),
                new System.Security.Claims.Claim("role", "owner"),
                new System.Security.Claims.Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var result = await b.OrgAuthConfigController.Delete(CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var c2 = await b.Db.OpenAsync();
        var actorId = await c2.ExecuteScalarAsync<string?>(
            "SELECT actor_id FROM audit_log WHERE action = 'saml.config_deleted' AND org_id = @o LIMIT 1",
            new { o = b.PrimaryOrgId });
        Assert.Equal(userId, actorId);
    }

    // ── ThumbprintOrNull: malformed-cert branch via Get() ─────────────────────

    [Fact]
    public async Task Get_MalformedCert_ReturnsNullThumbprint()
    {
        // ThumbprintOrNull catches Convert.FromBase64String / X509 load failures and returns null.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, " +
                "idp_signing_cert, name_id_format) " +
                "VALUES (@o, 0, 1, 'not-base64!!!', 'fmt')",
                new { o = b.PrimaryOrgId });
        }

        var ok = Assert.IsType<OkObjectResult>(
            await b.OrgAuthConfigController.Get(CancellationToken.None));
        var thumbprint = ok.Value!.GetType().GetProperty("idpSigningCertThumbprint")!.GetValue(ok.Value);
        Assert.Null(thumbprint);
    }
}
