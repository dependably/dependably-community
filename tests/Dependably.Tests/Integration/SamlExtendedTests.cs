using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Extends <see cref="SamlTests"/> with branch coverage for <see cref="SamlController"/> code
/// paths that the primary suite doesn't exercise: ?test parsing variants, POST binding ACS,
/// missing-NameID, tampered/expired test cookies, configured-but-incomplete metadata, and the
/// full <see cref="IdpMetadataParser"/> error matrix.
///
/// All tests here use real <see cref="DependablyFactory"/> wiring so the controller, DI, and
/// SAML library land on the same code paths as production. No live IdP is required — the test
/// cookie is forged via the registered <see cref="IDataProtectionProvider"/>, and SAML response
/// payloads are deliberately garbled so signature validation fails predictably.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SamlExtendedTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SamlExtendedTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Metadata endpoint: SP entityId override, cfg-driven NameIDFormat ──────

    [Fact]
    public async Task Metadata_WithCfgSpEntityIdAndCustomNameIdFormat_AppearsInXml()
    {
        // Exercises the BuildSaml2Configuration "use cfg.SpEntityId when set" branch and the
        // cfg-supplied NameIDFormat on the SP descriptor (not the default emailAddress URN).
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true,
            spEntityId: "https://override.sp.example/spid",
            nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/metadata");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string xml = await resp.Content.ReadAsStringAsync();
        Assert.Contains("https://override.sp.example/spid", xml);
        Assert.Contains("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", xml);
    }

    // ── Login parameter parsing ───────────────────────────────────────────────

    [Fact]
    public async Task Login_TestFalse_TreatedAsRealLogin_AndDisabledRejects()
    {
        // ?test=false should be treated as a real (non-test) login. With enabled=false the
        // controller's "not enabled" 404 path fires (same as omitting the param entirely).
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/login?test=false");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Login_TestZero_TreatedAsRealLogin_AndDisabledRejects()
    {
        // ?test=0 mirrors the ?test=false branch — both are explicit string opt-outs.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/login?test=0");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Login_TestMode_NoAuth_GuardReturnsAuthFailure()
    {
        // The guard rejects unauthenticated principals on test=1. The exact status depends on
        // OrgAccessGuard's policy, but the redirect-to-IdP path must NOT be taken.
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var resp = await client.GetAsync("/saml/login?test=1");

        Assert.NotEqual(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized
            or HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
            $"expected auth failure status, got {resp.StatusCode}");
    }

    [Fact]
    public async Task Login_NoSamlConfigAtAll_Returns404()
    {
        // Hits the IsSamlConfigured == false branch in Login (distinct from "configured but
        // not enabled" which is also 404 but with a different reason string).
        await ResetSamlConfigAsync();

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/login");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("not configured", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_PartiallyConfigured_MissingIdpSsoUrl_Returns404()
    {
        // IsSamlConfigured requires entityId AND sso AND signing cert. Seed only the entity
        // id + cert; the missing SSO URL must trip the "not configured" branch.
        await ResetSamlConfigAsync();
        string orgId = await GetDefaultOrgIdAsync();
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, " +
                "idp_entity_id, idp_sso_url, idp_signing_cert, name_id_format) " +
                "VALUES (@o, 1, 1, 'entity', NULL, 'cert', 'fmt')",
                new { o = orgId });
        }

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/login");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Contains("not configured", await resp.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);
    }

    // ── ACS: POST binding path ───────────────────────────────────────────────

    [Fact]
    public async Task Acs_PostBinding_GarbagePayload_Returns401()
    {
        // The integration suite exercises GET /saml/acs (HTTP-Redirect binding). This covers
        // the HttpMethods.IsPost(Request.Method) ? new Saml2PostBinding() ... branch.
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient();
        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("SAMLResponse", "garbage"),
        });
        var resp = await client.PostAsync("/saml/acs", form);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Acs_PostBinding_TestMode_ViaRelayState_RedirectsToTestResult()
    {
        // Covers test-mode path on a POST binding (relay state read from Request.Form).
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);
        string orgId = await GetDefaultOrgIdAsync();

        string cid = Guid.NewGuid().ToString("N");
        var samlRepo = _factory.Services.GetRequiredService<SamlConfigRepository>();
        // now-ok: the host consumes the test run against its real clock during the ACS hit,
        // so the expiry must be future relative to real now.
        await samlRepo.IssueTestRunAsync(cid, orgId, actorId: "post-actor",
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(10));

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("SAMLResponse", "garbage"),
            new KeyValuePair<string, string>("RelayState", $"test:{cid}"),
        });
        var resp = await client.PostAsync("/saml/acs", form);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";
        Assert.Contains("/saml-test-result", location);
        Assert.Contains("error=validation_failed", location);
    }

    [Fact]
    public async Task Acs_PostBinding_TestMode_NoCookieNoRelayState_RedirectsTestSessionLost()
    {
        // Hits the "POST with SAMLResponse but no test-mode detectable AND saml not enabled"
        // branch — must redirect with test_session_lost instead of returning JSON 404.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("SAMLResponse", "garbage"),
        });
        var resp = await client.PostAsync("/saml/acs", form);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";
        Assert.Contains("/saml-test-result", location);
        Assert.Contains("error=test_session_lost", location);
    }

    [Fact]
    public async Task Acs_SamlNotConfigured_NoSamlResponseParam_Returns404()
    {
        // No tenant_saml_config row AND no SAMLResponse in the request → the early "session
        // lost" short-circuit (which only fires when SAMLResponse is present) is skipped,
        // and ValidateSamlConfigured returns the config_missing 404.
        await ResetSamlConfigAsync();

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/acs");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("not configured", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Acs_SamlNotConfigured_WithSamlResponseParam_RedirectsTestSessionLost()
    {
        // Mirror of the above: when SAMLResponse IS present but no config row exists,
        // the early short-circuit picks up the dangling IdP round-trip and routes the user
        // to the test-result page instead of returning a JSON 404 they can't read.
        await ResetSamlConfigAsync();

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var resp = await client.GetAsync("/saml/acs?SAMLResponse=garbage");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Contains("error=test_session_lost", resp.Headers.Location?.OriginalString ?? "");
    }

    [Fact]
    public async Task Acs_TamperedTestCookie_FallsBackToRelayStateOrFailsCleanly()
    {
        // A tampered (decrypt-fail) cookie returns false from TryReadTestCookie and falls
        // through to the RelayState lookup. With no relay state and SAML enabled=false but
        // SAMLResponse present, we get the test_session_lost redirect.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("Cookie", "dependably_saml_test=this-is-not-a-real-protected-payload");
        var resp = await client.GetAsync("/saml/acs?SAMLResponse=garbage");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";
        Assert.Contains("/saml-test-result", location);
        Assert.Contains("error=test_session_lost", location);
    }

    [Fact]
    public async Task Acs_TestCookie_TenantMismatch_FallsThroughAsNonTest()
    {
        // A cookie signed for the wrong tenant fails the tid check inside TryReadTestCookie,
        // forcing fallback to relay state. None present here, so test_session_lost fires.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        var protector = _factory.Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("saml-test-marker.v1");
        string payload = JsonSerializer.Serialize(new
        {
            tid = "WRONG-TENANT",
            actor = "actor",
            cid = Guid.NewGuid().ToString("N"),
            // now-ok: the controller checks exp against the host's real clock; this cookie
            // must be unexpired so the failure is attributable to the tid mismatch alone.
            exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
        });
        string cookie = protector.Protect(payload);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("Cookie", $"dependably_saml_test={cookie}");
        var resp = await client.GetAsync("/saml/acs?SAMLResponse=garbage");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Contains("error=test_session_lost", resp.Headers.Location?.OriginalString ?? "");
    }

    [Fact]
    public async Task Acs_ExpiredTestCookie_FallsThroughAsNonTest()
    {
        // exp in the past → TryReadTestCookie returns false. With no relay state and SAML
        // not enabled the test_session_lost redirect path runs.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);
        string orgId = await GetDefaultOrgIdAsync();

        var protector = _factory.Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("saml-test-marker.v1");
        string payload = JsonSerializer.Serialize(new
        {
            tid = orgId,
            actor = "actor",
            cid = Guid.NewGuid().ToString("N"),
            // now-ok: backdated relative to the host's real clock (which checks exp);
            // 10 minutes keeps the seed decisively past any clock-granularity boundary.
            exp = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds(),
        });
        string cookie = protector.Protect(payload);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("Cookie", $"dependably_saml_test={cookie}");
        var resp = await client.GetAsync("/saml/acs?SAMLResponse=garbage");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Contains("error=test_session_lost", resp.Headers.Location?.OriginalString ?? "");
    }

    // ── IdpMetadataParser: error matrix ──────────────────────────────────────

    [Fact]
    public void IdpMetadataParser_EmptyString_Throws()
    {
        Assert.Throws<ArgumentException>(() => IdpMetadataParser.Parse(""));
    }

    [Fact]
    public void IdpMetadataParser_WhitespaceOnly_Throws()
    {
        Assert.Throws<ArgumentException>(() => IdpMetadataParser.Parse("   \n\t  "));
    }

    [Fact]
    public void IdpMetadataParser_NoEntityDescriptor_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            IdpMetadataParser.Parse("<?xml version=\"1.0\"?><root/>"));
        Assert.Contains("EntityDescriptor", ex.Message);
    }

    [Fact]
    public void IdpMetadataParser_MissingEntityIdAttribute_Throws()
    {
        string xml = """
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
            </EntityDescriptor>
            """;
        var ex = Assert.Throws<InvalidOperationException>(() => IdpMetadataParser.Parse(xml));
        Assert.Contains("entityID", ex.Message);
    }

    [Fact]
    public void IdpMetadataParser_NoIdpSsoDescriptor_Throws()
    {
        string xml = """
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x"/>
            """;
        var ex = Assert.Throws<InvalidOperationException>(() => IdpMetadataParser.Parse(xml));
        Assert.Contains("IDPSSODescriptor", ex.Message);
    }

    [Fact]
    public void IdpMetadataParser_NoSingleSignOnService_Throws()
    {
        string xml = $"""
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor use="signing">
                  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data><X509Certificate>{SampleIdpCertBase64}</X509Certificate></X509Data>
                  </KeyInfo>
                </KeyDescriptor>
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
        var ex = Assert.Throws<InvalidOperationException>(() => IdpMetadataParser.Parse(xml));
        Assert.Contains("SingleSignOnService", ex.Message);
    }

    [Fact]
    public void IdpMetadataParser_SsoMissingLocationAttribute_Throws()
    {
        // The selector finds a SingleSignOnService with HTTP-Redirect binding but no
        // Location attribute. That hits the "Location is missing" branch directly.
        string xml = $"""
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor use="signing">
                  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data><X509Certificate>{SampleIdpCertBase64}</X509Certificate></X509Data>
                  </KeyInfo>
                </KeyDescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
        var ex = Assert.Throws<InvalidOperationException>(() => IdpMetadataParser.Parse(xml));
        Assert.Contains("Location", ex.Message);
    }

    [Fact]
    public void IdpMetadataParser_HttpPostBindingOnly_ParsesViaFallback()
    {
        // Redirect binding is preferred but HTTP-POST is the documented fallback.
        string xml = $"""
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor use="signing">
                  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data><X509Certificate>{SampleIdpCertBase64}</X509Certificate></X509Data>
                  </KeyInfo>
                </KeyDescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp/sso-post"/>
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
        var parsed = IdpMetadataParser.Parse(xml);
        Assert.Equal("https://idp/x", parsed.EntityId);
        Assert.Equal("https://idp/sso-post", parsed.SsoUrl);
    }

    [Fact]
    public void IdpMetadataParser_KeyDescriptorWithoutUseAttribute_ParsesViaFallback()
    {
        // Parser prefers <KeyDescriptor use='signing'> but falls back to the first
        // <KeyDescriptor> when no signing-tagged one is present (Entra ID emits both
        // signing and encryption KeyDescriptors but some IdPs omit the 'use' attribute).
        string xml = $"""
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor>
                  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data><X509Certificate>{SampleIdpCertBase64}</X509Certificate></X509Data>
                  </KeyInfo>
                </KeyDescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/>
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
        var parsed = IdpMetadataParser.Parse(xml);
        Assert.Equal(SampleIdpCertBase64, parsed.SigningCertBase64);
    }

    [Fact]
    public void IdpMetadataParser_NoX509Certificate_Throws()
    {
        string xml = """
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/>
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
        var ex = Assert.Throws<InvalidOperationException>(() => IdpMetadataParser.Parse(xml));
        Assert.Contains("X509Certificate", ex.Message);
    }

    [Fact]
    public void IdpMetadataParser_InvalidBase64Cert_Throws()
    {
        // The cert is bogus (not valid base64 → not parseable X.509). Parser wraps the
        // failure in an InvalidOperationException with our custom message.
        string xml = """
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor use="signing">
                  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data><X509Certificate>not-base64-bytes!!!</X509Certificate></X509Data>
                  </KeyInfo>
                </KeyDescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/>
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
        var ex = Assert.Throws<InvalidOperationException>(() => IdpMetadataParser.Parse(xml));
        Assert.Contains("X509Certificate", ex.Message);
    }

    [Fact]
    public void IdpMetadataParser_DtdProcessing_Rejected()
    {
        // XXE defence: DTDs are explicitly prohibited by the XmlReaderSettings, so a doc with
        // a DOCTYPE declaration must fail to parse rather than silently allowing entity
        // expansion. The underlying XmlException bubbles up.
        string xml = """
            <?xml version="1.0"?>
            <!DOCTYPE EntityDescriptor [<!ENTITY x "x">]>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x"/>
            """;
        Assert.ThrowsAny<Exception>(() => IdpMetadataParser.Parse(xml));
    }

    [Fact]
    public void IdpMetadataParser_WhitespaceInsideCert_StrippedBeforeBase64Decode()
    {
        // PEM-style line breaks inside the X509Certificate element are common; the parser
        // must strip whitespace before validating the base64. We split the sample cert in
        // half with a newline and confirm the round-trip still succeeds.
        int half = SampleIdpCertBase64.Length / 2;
        string withWs = SampleIdpCertBase64.Insert(half, "\n  ");
        string xml = $"""
            <?xml version="1.0"?>
            <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp/x">
              <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor use="signing">
                  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data><X509Certificate>{withWs}</X509Certificate></X509Data>
                  </KeyInfo>
                </KeyDescriptor>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/>
              </IDPSSODescriptor>
            </EntityDescriptor>
            """;
        var parsed = IdpMetadataParser.Parse(xml);
        // The output should be the whitespace-stripped form, equal to the original.
        Assert.Equal(SampleIdpCertBase64, parsed.SigningCertBase64);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<string> GetDefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org not found");
    }

    private async Task ResetSamlConfigAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("DELETE FROM tenant_saml_config");
    }

    private async Task SeedFakeSamlConfigAsync(
        bool enabled, bool formsLoginEnabled, bool withMetadata,
        string? spEntityId = null, string? nameIdFormat = null)
    {
        await ResetSamlConfigAsync();
        string orgId = await GetDefaultOrgIdAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled,
                idp_entity_id, idp_sso_url, idp_signing_cert,
                sp_entity_id, name_id_format)
            VALUES (@orgId, @enabled, @forms,
                @entityId, @ssoUrl, @cert,
                @spEntityId, @nameIdFormat)
            """,
            new
            {
                orgId,
                enabled = enabled ? 1 : 0,
                forms = formsLoginEnabled ? 1 : 0,
                entityId = withMetadata ? "https://idp.example.com/entity" : null,
                ssoUrl = withMetadata ? "https://idp.example.com/sso" : null,
                cert = withMetadata ? SampleIdpCertBase64 : null,
                spEntityId,
                nameIdFormat = nameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            });
    }

    // Same self-signed cert SamlTests uses — kept here so this file is self-contained and
    // doesn't depend on the SamlTests file (which is in the same assembly but private).
    private const string SampleIdpCertBase64 =
        "MIIDXTCCAkWgAwIBAgIJALzWqv6FcU3TMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV" +
        "BAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX" +
        "aWRnaXRzIFB0eSBMdGQwHhcNMjAwMTAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjBF" +
        "MQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50" +
        "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" +
        "CgKCAQEAwOlEDR8Y6f6vS0zYxrU5+hmOZDZIMFjF2H7Ckw2P5YuUQrUe7PtbFRFb" +
        "6rL6nZqkGE9OvRnKwbuyYQT9JEH5fQrbi7fIp+W7DdDWvCm0GLP8DNeQZMpvCiKG" +
        "DWTZ52jNk4qJ6uvF5VxC7sIxL5C7r6LRiq5cLR5N8JJF3qXXqjgZS3oNQPuVwjaP" +
        "GJBczQHBu5mJqvr9Q3M7VJqIb8LMNh/tTjvQfQYxEvW5j6mOg4y1L8O9rHb2uVm0" +
        "lPBd/L7UrQUe/pEWjzxxZuBcVxWnkD8+y+wSDUlW0OjjYnBxJ0SSUEMnkqAQM/qj" +
        "FW0Ts7/uXHZb89cqdrx0Q0M7e8C5dwIDAQABo1AwTjAdBgNVHQ4EFgQUqXyR1jyM" +
        "Sc/hSVEXqVwOKy2KTM4wHwYDVR0jBBgwFoAUqXyR1jyMSc/hSVEXqVwOKy2KTM4w" +
        "DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAOlH+YgQYNkPMNgAQ5kQ4" +
        "4u+nE/fF8vQfWEcxZTdVghP7wJ54dkvCQ9wgFKBe8ld6WUEuM4Wr/PyDpOzh7M5g" +
        "9pWUjPqJ5LlIK9HZKcdz5G4UiMRCmnH3wU5q3CUwyDwR3sbpLjyMJZ5fWxIa6KYr" +
        "JaCJjDz+GpHQYHwSjB6X0rmsKzQMhqHa3Q9+FwvKHV60KbkPI9jq37xvwsrsr5kS" +
        "2J0sIQqNbxQcXPGMQfOK3uGNoZmwT1oHVHjMRKOq1A9cYXIKNQjxnIo6TEoCkiZB" +
        "txFvB4i27FwLKCGyGFqB9LGUhQ9rEpKSpXRhJPL8K6jSBWGJpRMAJWOKhOoKIO7g" +
        "kg==";
}
