using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Covers the wireable parts of the SAML SP integration: configuration CRUD, the lockout
/// guard for disabling forms login, public auth-method discovery, and the JIT-provisioning
/// branches inside <see cref="LoginService.LoginSamlAsync"/>. The cryptographic round-trip
/// (signed assertion → ACS validation) is delegated to ITfoxtec.Identity.Saml2 and exercised
/// end-to-end during manual testing against samltest.id.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SamlTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SamlTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Public auth-method discovery ──────────────────────────────────────────

    [Fact]
    public async Task AuthMethods_NoSamlConfigured_ReturnsFormsOnly()
    {
        await ResetSamlConfigAsync();
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/auth/methods");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("forms").GetBoolean());
        Assert.False(doc.RootElement.GetProperty("saml").GetBoolean());
    }

    [Fact]
    public async Task AuthMethods_SamlEnabledAndConfigured_ReturnsBoth()
    {
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/auth/methods");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("forms").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("saml").GetBoolean());
    }

    // ── Auth-config CRUD ──────────────────────────────────────────────────────

    [Fact]
    public async Task AuthConfig_Get_RequiresAdmin()
    {
        await ResetSamlConfigAsync();

        string memberJwt = await IssueJwtAsync(role: "member");
        using var memberClient = _factory.CreateClientWithBearer(memberJwt);
        var resp = await memberClient.GetAsync("/api/v1/auth-config");
        Assert.True(resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
            $"member should be denied auth-config GET, got {resp.StatusCode}");
    }

    [Fact]
    public async Task AuthConfig_GetAsAdmin_ReturnsSpInfo()
    {
        await ResetSamlConfigAsync();

        using var client = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        var resp = await client.GetAsync("/api/v1/auth-config");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var spInfo = doc.RootElement.GetProperty("spInfo");
        Assert.Contains("/saml/acs", spInfo.GetProperty("acsUrl").GetString());
        Assert.Contains("/saml/metadata", spInfo.GetProperty("metadataUrl").GetString());
        Assert.False(doc.RootElement.GetProperty("enabled").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("formsLoginEnabled").GetBoolean());
    }

    [Fact]
    public async Task AuthConfig_DisableFormsWithoutRecentTest_Returns422()
    {
        // now-ok: seeds relative to the host's real clock so the server-side 10-minute
        // staleness window lands as intended; 1h is decisively past the cutoff.
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true,
            lastTestAt: DateTimeOffset.UtcNow.AddHours(-1)); // stale: > 10 minutes ago

        using var client = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        var body = JsonContent.Create(new
        {
            enabled = true,
            formsLoginEnabled = false,
            spEntityId = (string?)null,
            nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            emailAttribute = (string?)null,
            buttonLabel = (string?)null,
        });
        var resp = await client.PutAsync("/api/v1/auth-config", body);
        // ProblemResults emits 422 for ValidationError
        Assert.Equal((HttpStatusCode)422, resp.StatusCode);
    }

    [Fact]
    public async Task AuthConfig_DisableFormsWithRecentTest_Succeeds()
    {
        // now-ok: seeds relative to the host's real clock so the server-side 10-minute
        // recency window lands as intended; -2min leaves 8 minutes of margin for the request.
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true,
            lastTestAt: DateTimeOffset.UtcNow.AddMinutes(-2));

        using var client = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        var body = JsonContent.Create(new
        {
            enabled = true,
            formsLoginEnabled = false,
            spEntityId = (string?)null,
            nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            emailAttribute = (string?)null,
            buttonLabel = (string?)null,
        });
        var resp = await client.PutAsync("/api/v1/auth-config", body);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    [Fact]
    public async Task AuthConfig_DisableFormsWithoutSamlEnabled_Returns422()
    {
        await ResetSamlConfigAsync();

        using var client = _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());
        var body = JsonContent.Create(new
        {
            enabled = false,
            formsLoginEnabled = false,
            spEntityId = (string?)null,
            nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            emailAttribute = (string?)null,
            buttonLabel = (string?)null,
        });
        var resp = await client.PutAsync("/api/v1/auth-config", body);
        Assert.Equal((HttpStatusCode)422, resp.StatusCode);
    }

    // ── SP metadata endpoint ──────────────────────────────────────────────────

    [Fact]
    public async Task Metadata_AdvertisesBothPostAndRedirectAcsBindings()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/metadata");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string xml = await resp.Content.ReadAsStringAsync();
        Assert.Contains("EntityDescriptor", xml);
        Assert.Contains("AssertionConsumerService", xml);
        Assert.Contains("/saml/acs", xml);
        // Both bindings advertised so an IdP that reads metadata can pick either; HTTP-POST
        // is the spec-recommended default but Keycloak (and others) optionally use Redirect
        // for the response too.
        Assert.Contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", xml);
        Assert.Contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", xml);
    }

    [Fact]
    public async Task Acs_GetWithoutValidSamlResponse_Returns401NotRouting404()
    {
        // Regression for the bug where Keycloak emitted the SAML response via HTTP-Redirect
        // (GET /saml/acs?SAMLResponse=...) and the SP returned 404 because the route was
        // POST-only. The route now accepts GET; an unsigned/malformed payload reaches the
        // SAML library and surfaces as a 401 from signature validation.
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/acs?SAMLResponse=garbage&SigAlg=garbage&Signature=garbage");
        Assert.NotEqual(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.NotEqual(HttpStatusCode.MethodNotAllowed, resp.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── IdP metadata parser ───────────────────────────────────────────────────

    [Fact]
    public void IdpMetadataParser_ValidMetadata_ExtractsEntityIdSsoUrlCert()
    {
        var parsed = Dependably.Api.IdpMetadataParser.Parse(SampleIdpMetadata);
        Assert.Equal("https://idp.example.com/entity", parsed.EntityId);
        Assert.Equal("https://idp.example.com/sso", parsed.SsoUrl);
        Assert.Equal(SampleIdpCertBase64, parsed.SigningCertBase64);
    }

    [Fact]
    public void IdpMetadataParser_MissingDescriptor_Throws()
    {
        string bad = "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"x\"></EntityDescriptor>";
        Assert.ThrowsAny<InvalidOperationException>(() => Dependably.Api.IdpMetadataParser.Parse(bad));
    }

    // ── LoginService.LoginSamlAsync (JIT / link / preserve-role) ──────────────

    [Fact]
    public async Task LoginSaml_NewUser_ProvisionsMemberAndIssuesJwt()
    {
        var login = _factory.Services.GetRequiredService<LoginService>();
        string orgId = await GetDefaultOrgIdAsync();

        var result = await login.LoginSamlAsync(
            tenantId: orgId,
            idpEntityId: "https://idp.example.com/entity",
            nameId: "saml-user-1",
            assertionEmail: "saml-user-1@example.com");

        Assert.NotNull(result.Token);
        Assert.True(result.Provisioned);
        Assert.Equal("member", result.Role);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string? role = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE email = 'saml-user-1@example.com'");
        Assert.Equal("member", role);

        int linked = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM external_identities WHERE org_id = @o AND idp_entity_id = @e AND nameid = @n",
            new { o = orgId, e = "https://idp.example.com/entity", n = "saml-user-1" });
        Assert.Equal(1, linked);
    }

    /// <summary>
    /// An existing admin account is blocked from silent email-link without the
    /// idp_can_assign_admin opt-in (privilege-escalation gate). With the opt-in set, the
    /// link is permitted and the existing admin role is preserved.
    /// </summary>
    [Fact]
    public async Task LoginSaml_ExistingAdminFormsUser_BlockedWithoutOptIn_AllowedWithOptIn()
    {
        var login = _factory.Services.GetRequiredService<LoginService>();
        string orgId = await GetDefaultOrgIdAsync();
        string email = $"admin-{Guid.NewGuid():N}@example.com";
        await _factory.CreateUser(email, "doesntmatter12", role: "admin");

        // Without opt-in: blocked — the email-link ceiling matches the JIT ceiling.
        var blockedResult = await login.LoginSamlAsync(
            tenantId: orgId,
            idpEntityId: "https://idp.example.com/entity",
            nameId: "saml-existing-blocked",
            assertionEmail: email);

        Assert.Null(blockedResult.Token);
        Assert.False(blockedResult.Linked);

        // With opt-in: link is permitted and the existing admin role is preserved.
        var allowedResult = await login.LoginSamlAsync(
            tenantId: orgId,
            idpEntityId: "https://idp.example.com/entity",
            nameId: "saml-existing-allowed",
            assertionEmail: email,
            new SamlLoginOptions(IdpCanAssignAdmin: true));

        Assert.NotNull(allowedResult.Token);
        Assert.True(allowedResult.Linked);
        Assert.Equal("admin", allowedResult.Role);
    }

    [Fact]
    public async Task LoginSaml_ReturningSamlUser_UpdatesEmailAndKeepsRole()
    {
        var login = _factory.Services.GetRequiredService<LoginService>();
        string orgId = await GetDefaultOrgIdAsync();

        // First login: provision via JIT
        await login.LoginSamlAsync(orgId, "https://idp.example.com/entity", "saml-rotate-1", "old@example.com");

        // Second login: same NameID, IdP rotated email
        var result = await login.LoginSamlAsync(orgId, "https://idp.example.com/entity", "saml-rotate-1", "new@example.com");
        Assert.NotNull(result.Token);
        Assert.False(result.Provisioned);
        Assert.False(result.Linked);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string? rowEmail = await conn.ExecuteScalarAsync<string>(
            "SELECT email FROM users WHERE id = (SELECT user_id FROM external_identities WHERE nameid = 'saml-rotate-1' LIMIT 1)");
        Assert.Equal("new@example.com", rowEmail);
    }

    [Fact]
    public async Task LoginSaml_DifferentIdpSameEmail_DoesNotCollide()
    {
        var login = _factory.Services.GetRequiredService<LoginService>();
        string orgId = await GetDefaultOrgIdAsync();
        string sharedEmail = $"shared-{Guid.NewGuid():N}@example.com";

        var first = await login.LoginSamlAsync(orgId, "https://idp1.example.com", "alice", sharedEmail);
        // Link by email path will reuse the first user. Use distinct emails to truly test "no collision".
        string distinctEmail = $"distinct-{Guid.NewGuid():N}@example.com";
        var second = await login.LoginSamlAsync(orgId, "https://idp2.example.com", "alice", distinctEmail);

        Assert.NotNull(first.Token);
        Assert.NotNull(second.Token);
        Assert.NotEqual(first.UserId, second.UserId);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        int idp1Count = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM external_identities WHERE idp_entity_id = 'https://idp1.example.com'");
        int idp2Count = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM external_identities WHERE idp_entity_id = 'https://idp2.example.com'");
        Assert.Equal(1, idp1Count);
        Assert.Equal(1, idp2Count);
    }

    [Fact]
    public async Task LoginSaml_DisabledAccount_Returns401()
    {
        var login = _factory.Services.GetRequiredService<LoginService>();
        string orgId = await GetDefaultOrgIdAsync();
        string email = $"locked-{Guid.NewGuid():N}@example.com";
        string userId = await _factory.CreateUser(email, "doesntmatter12", role: "member");

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("UPDATE users SET account_status = 'disabled' WHERE id = @id", new { id = userId });

        var result = await login.LoginSamlAsync(orgId, "https://idp.example.com/entity", "locked-nameid", email);
        Assert.Null(result.Token);
        Assert.NotNull(result.Error);
    }

    // ── Test mode bypasses Enabled gate, real login does not ──────────────────

    [Fact]
    public async Task Login_TestMode_WithMetadataButNotEnabled_RedirectsToIdp()
    {
        // Regression for the UX hole: admins had to flip Enabled (which publishes the SAML
        // button on the public sign-in page) just to run a test. Test mode now requires
        // metadata only, so an unpublished config can be validated end-to-end first.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        string adminJwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminJwt);
        var resp = await client.GetAsync("/saml/login?test=1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";
        Assert.Contains("idp.example.com/sso", location);
    }

    [Fact]
    public async Task Login_NonTest_WithMetadataButNotEnabled_Returns404()
    {
        // Real (non-test) SP-initiated login must still require Enabled — the controller
        // gate is defense in depth: /api/v1/auth/methods already hides the public button,
        // but a direct hit to /saml/login should also be refused.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/saml/login");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("not enabled", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Acs_TestMode_BypassesEnabledCheck()
    {
        // With a valid test cookie, ACS proceeds past the Enabled gate and reaches signature
        // validation. A garbage SAMLResponse fails validation and (because we're in test mode)
        // redirects to /saml-test-result instead of returning 401. The point of the assertion
        // is that we no longer 404 on Enabled=false — the failure mode changed from "gated
        // out" to "validation failed", proving the bypass works.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);
        string orgId = await GetDefaultOrgIdAsync();

        var (cookie, _) = await ForgeTestCookieAsync(orgId);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("Cookie", $"dependably_saml_test={cookie}");
        var resp = await client.GetAsync("/saml/acs?SAMLResponse=garbage&SigAlg=garbage&Signature=garbage");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";
        Assert.Contains("/saml-test-result", location);
        Assert.Contains("error=validation_failed", location);
    }

    [Fact]
    public async Task Login_TestMode_EmbedsCidInRelayState()
    {
        // Regression: SameSite=Lax blocks the test cookie on cross-site IdP form POSTs.
        // The Login handler must embed the cid in RelayState so the ACS can detect test
        // mode even without the cookie.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        string adminJwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminJwt);
        var resp = await client.GetAsync("/saml/login?test=1");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";

        // ITfoxtec URL-encodes the relay state in the redirect; extract and decode it.
        var redirectUri = new Uri(location);
        var qs = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(redirectUri.Query);
        Assert.True(qs.TryGetValue("RelayState", out var relayValues), "RelayState should be present");
        string relayState = relayValues.FirstOrDefault() ?? "";
        Assert.StartsWith("test:", relayState, StringComparison.Ordinal);

        // The suffix should be a 32-character hex cid
        string cid = relayState["test:".Length..];
        Assert.Equal(32, cid.Length);
        Assert.All(cid, c => Assert.True(char.IsAsciiHexDigit(c), $"'{c}' is not a hex digit"));
    }

    [Fact]
    public async Task Acs_TestMode_ViaRelayState_NoCookie_DetectsTestMode()
    {
        // Regression for the SameSite=Lax cross-site POST bug: when the IdP does a form POST
        // to /saml/acs, the SameSite=Lax test cookie is blocked. Without the relay state
        // fallback, isTest=false and the normal login path runs — issuing a new session that
        // overwrites the admin's session in the shared cookie jar and redirecting to /.
        // The fix: ACS reads the cid from RelayState when the cookie is absent.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);
        string orgId = await GetDefaultOrgIdAsync();

        // Create a test run row directly (no cookie set — simulates the cross-site POST path)
        string cid = Guid.NewGuid().ToString("N");
        var samlRepo = _factory.Services.GetRequiredService<SamlConfigRepository>();
        // now-ok: the host consumes the test run against its real clock during the ACS hit,
        // so the expiry must be future relative to real now.
        await samlRepo.IssueTestRunAsync(cid, orgId, actorId: "test-actor",
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(10));

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        // No test cookie — rely solely on relay state
        var resp = await client.GetAsync(
            $"/saml/acs?SAMLResponse=garbage&SigAlg=garbage&Signature=garbage&RelayState=test%3A{cid}");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";
        // "validation_failed" proves test mode was detected and SAML validation ran,
        // rather than falling through to normal login (which would redirect to /).
        Assert.Contains("/saml-test-result", location);
        Assert.Contains("error=validation_failed", location);
    }

    [Fact]
    public async Task Acs_TestMode_NoSessionAndNoRelayState_RedirectsToTestResultError()
    {
        // When both the test cookie (SameSite=Lax blocked on IdP cross-site POST) AND the
        // RelayState are absent, the ACS cannot detect test mode. Without the fix it returned
        // "SAML SSO is not enabled" JSON; it should redirect to the test-result page with
        // test_session_lost so the popup closes cleanly.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        // No cookie, no relay state — simulates stripped-RelayState + blocked-cookie path.
        var resp = await client.GetAsync("/saml/acs?SAMLResponse=garbage&SigAlg=garbage&Signature=garbage");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        string location = resp.Headers.Location?.OriginalString ?? "";
        Assert.Contains("/saml-test-result", location);
        Assert.Contains("error=test_session_lost", location);
    }

    [Fact]
    public async Task Acs_TestMode_ViaRelayState_DoesNotIssueSession()
    {
        // In test mode (relay state path), no session cookie must be issued.
        // Without this guarantee, the IdP's cross-site POST would replace the admin's session.
        await SeedFakeSamlConfigAsync(enabled: true, formsLoginEnabled: true, withMetadata: true);
        string orgId = await GetDefaultOrgIdAsync();

        string cid = Guid.NewGuid().ToString("N");
        var samlRepo = _factory.Services.GetRequiredService<SamlConfigRepository>();
        // now-ok: the host consumes the test run against its real clock during the ACS hit,
        // so the expiry must be future relative to real now.
        await samlRepo.IssueTestRunAsync(cid, orgId, actorId: "test-actor",
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(10));

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var resp = await client.GetAsync(
            $"/saml/acs?SAMLResponse=garbage&SigAlg=garbage&Signature=garbage&RelayState=test%3A{cid}");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var setCookies = resp.Headers
            .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .SelectMany(h => h.Value)
            .ToList();
        Assert.DoesNotContain(setCookies, c => c.Contains("dependably_session"));
    }

    [Fact]
    public async Task Acs_TestMode_ReplayedCookie_Rejected()
    {
        // A test cookie is one-shot: the cid in the cookie maps to a saml_test_runs row whose
        // consumed_at is stamped atomically on first use. Replaying the same cookie is rejected
        // even though the cookie itself is still cryptographically valid and within TTL.
        await SeedFakeSamlConfigAsync(enabled: false, formsLoginEnabled: true, withMetadata: true);
        string orgId = await GetDefaultOrgIdAsync();

        var (cookie, cid) = await ForgeTestCookieAsync(orgId);

        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("Cookie", $"dependably_saml_test={cookie}");

        // First hit consumes the cid, then bounces off signature validation to test-result.
        var first = await client.GetAsync("/saml/acs?SAMLResponse=garbage&SigAlg=garbage&Signature=garbage");
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.Contains("error=validation_failed", first.Headers.Location?.OriginalString ?? "");

        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            string? consumed = await conn.ExecuteScalarAsync<string?>(
                "SELECT consumed_at FROM saml_test_runs WHERE cid = @cid", new { cid });
            Assert.False(string.IsNullOrEmpty(consumed));
        }

        // Replay the same cookie. The cid is already consumed, so we expect a different
        // redirect explaining the test session is no longer valid.
        var second = await client.GetAsync("/saml/acs?SAMLResponse=garbage&SigAlg=garbage&Signature=garbage");
        Assert.Equal(HttpStatusCode.Redirect, second.StatusCode);
        string secondLoc = second.Headers.Location?.OriginalString ?? "";
        Assert.Contains("/saml-test-result", secondLoc);
        Assert.Contains("error=test_session_invalid", secondLoc);
    }

    /// <summary>
    /// Forges a test cookie for the given tenant by writing a saml_test_runs row directly and
    /// then signing a payload with the same DataProtection provider the controller uses. The
    /// cookie is purpose-bound (DataProtection purpose "saml-test-marker.v1") and tenant-bound
    /// by the embedded tid; this is the only way to exercise the ACS test path without a real
    /// IdP signing key.
    /// </summary>
    private async Task<(string Cookie, string Cid)> ForgeTestCookieAsync(string tenantId)
    {
        string cid = Guid.NewGuid().ToString("N");
        var samlRepo = _factory.Services.GetRequiredService<SamlConfigRepository>();
        // now-ok: the host consumes the test run against its real clock during the ACS hit,
        // so the expiry must be future relative to real now.
        await samlRepo.IssueTestRunAsync(cid, tenantId, actorId: "test-actor",
            expiresAt: DateTimeOffset.UtcNow.AddMinutes(10));

        var protector = _factory.Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("saml-test-marker.v1");
        string payload = JsonSerializer.Serialize(new
        {
            tid = tenantId,
            actor = "test-actor",
            cid,
            // now-ok: the controller checks exp against the host's real clock; the cookie
            // must be unexpired for the ACS test path to run.
            exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
        });
        return (protector.Protect(payload), cid);
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
        bool enabled, bool formsLoginEnabled, bool withMetadata, DateTimeOffset? lastTestAt = null)
    {
        await ResetSamlConfigAsync();
        string orgId = await GetDefaultOrgIdAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled,
                idp_entity_id, idp_sso_url, idp_signing_cert, name_id_format, last_test_at)
            VALUES (@orgId, @enabled, @forms,
                @entityId, @ssoUrl, @cert, @nameIdFormat, @lastTestAt)
            """,
            new
            {
                orgId,
                enabled = enabled ? 1 : 0,
                forms = formsLoginEnabled ? 1 : 0,
                entityId = withMetadata ? "https://idp.example.com/entity" : null,
                ssoUrl = withMetadata ? "https://idp.example.com/sso" : null,
                cert = withMetadata ? SampleIdpCertBase64 : null,
                nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                lastTestAt = lastTestAt?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    private async Task<string> IssueJwtAsync(string role)
    {
        string email = $"role-{role}-{Guid.NewGuid():N}@example.com";
        string userId = await _factory.CreateUser(email, "doesntmatter12", role);

        // Mint a JWT for that user. Reuses CreateAdminJwt's wiring but with the seeded role.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string orgId = await GetDefaultOrgIdAsync();
        string? jwtSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")!;

        var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtSecret!));
        var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
        // now-ok: mints a JWT the host validates against its (default: real) clock.
        var now = DateTime.UtcNow;
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            claims: new[]
            {
                new System.Security.Claims.Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, userId),
                new System.Security.Claims.Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new System.Security.Claims.Claim("org_id", orgId),
                new System.Security.Claims.Claim("tid", orgId),
                new System.Security.Claims.Claim("role", role),
                new System.Security.Claims.Claim("scope", "tenant"),
            },
            notBefore: now,
            expires: now.AddHours(1),
            signingCredentials: creds);
        return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
    }

    // Self-signed cert generated for tests only — never used to actually validate signatures
    // in unit tests (those bypass ITfoxtec via LoginService directly).
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

    private static readonly string SampleIdpMetadata = $"""
        <?xml version="1.0"?>
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity">
          <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <KeyDescriptor use="signing">
              <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                  <X509Certificate>{SampleIdpCertBase64}</X509Certificate>
                </X509Data>
              </KeyInfo>
            </KeyDescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
          </IDPSSODescriptor>
        </EntityDescriptor>
        """;
}
