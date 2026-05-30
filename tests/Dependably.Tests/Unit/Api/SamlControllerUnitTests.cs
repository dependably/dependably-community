using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Sociable unit coverage for <see cref="SamlController"/>. The integration suite already
/// exercises the cryptographic round-trip via a real <c>WebApplicationFactory</c>; these
/// tests drive the controller directly against an in-memory SQLite store + an ephemeral
/// data-protection provider so we can cover apex/no-tenant branches, query-string parsing
/// matrices, and the test-mode cookie/RelayState plumbing without spinning up the host.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SamlControllerUnitTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly EphemeralDataProtectionProvider _dataProtection = new();
    private readonly IAuditEmitter _auditEmitter = Substitute.For<IAuditEmitter>();

    public SamlControllerUnitTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // Real, parseable self-signed cert reused from SamlTests so BuildSaml2Configuration's
    // X509CertificateLoader.LoadCertificate(...) accepts it on the requireIdp=true path.
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

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SamlController NewControllerForTenant(
        string tenantId,
        string tenantSlug,
        ClaimsPrincipal? user = null,
        string method = "GET",
        Dictionary<string, string>? cookies = null,
        Dictionary<string, string>? queryParams = null,
        Dictionary<string, string>? formFields = null)
    {
        var samlConfig = new SamlConfigRepository(_fixture.Store);
        var orgs = new OrgRepository(_fixture.Store);
        var systemAdmins = new SystemAdminRepository(_fixture.Store);
        var audit = new AuditRepository(_fixture.Store);
        var external = new ExternalIdentityRepository(_fixture.Store);
        var lockout = new SqliteLockoutStore(_fixture.Store);
        var guard = new OrgAccessGuard(_fixture.Store);
        var login = new LoginService(_fixture.Store, orgs, systemAdmins, lockout, audit, external, _auditEmitter);
        var urls = new RequestPublicUrlBuilder(new ConfigurationBuilder().Build());

        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString($"{tenantSlug}.example.test");
        http.Request.Method = method;

        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(tenantId, tenantSlug);

        if (cookies is not null)
        {
            var raw = string.Join("; ", cookies.Select(kv => $"{kv.Key}={kv.Value}"));
            http.Request.Headers.Cookie = raw;
        }

        if (queryParams is not null && queryParams.Count > 0)
        {
            var qs = string.Join("&", queryParams.Select(kv =>
                $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
            http.Request.QueryString = new QueryString("?" + qs);
        }

        if (formFields is not null)
        {
            http.Request.ContentType = "application/x-www-form-urlencoded";
            var dict = formFields.ToDictionary(
                kv => kv.Key,
                kv => new Microsoft.Extensions.Primitives.StringValues(kv.Value));
            http.Request.Form = new FormCollection(dict);
        }

        if (user is not null)
        {
            http.User = user;
        }

        return new SamlController(samlConfig, login, guard, _dataProtection,
            NullLogger<SamlController>.Instance, urls)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private SamlController NewControllerWithoutTenant(TenantContext? tenant = null)
    {
        var samlConfig = new SamlConfigRepository(_fixture.Store);
        var orgs = new OrgRepository(_fixture.Store);
        var systemAdmins = new SystemAdminRepository(_fixture.Store);
        var audit = new AuditRepository(_fixture.Store);
        var external = new ExternalIdentityRepository(_fixture.Store);
        var lockout = new SqliteLockoutStore(_fixture.Store);
        var guard = new OrgAccessGuard(_fixture.Store);
        var login = new LoginService(_fixture.Store, orgs, systemAdmins, lockout, audit, external, _auditEmitter);
        var urls = new RequestPublicUrlBuilder(new ConfigurationBuilder().Build());

        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("apex.example.test");
        if (tenant is not null) http.Items[TenantContext.HttpItemsKey] = tenant;

        return new SamlController(samlConfig, login, guard, _dataProtection,
            NullLogger<SamlController>.Instance, urls)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private async Task<string> SeedTenantAsync(string slug)
    {
        return await OrgSeeder.InsertAsync(_fixture.Store, $"{slug}-{Guid.NewGuid():N}");
    }

    private async Task SeedSamlConfigAsync(
        string orgId,
        bool enabled = true,
        bool formsLoginEnabled = true,
        bool withMetadata = true,
        string? spEntityId = null,
        string? nameIdFormat = null,
        string? lastTestAt = null,
        string? emailAttribute = null)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM tenant_saml_config WHERE org_id = @o", new { o = orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (
                org_id, enabled, forms_login_enabled,
                idp_entity_id, idp_sso_url, idp_signing_cert,
                sp_entity_id, name_id_format, email_attribute, last_test_at)
            VALUES (
                @o, @en, @forms,
                @entity, @sso, @cert,
                @sp, @nameFmt, @emailAttr, @lastTest)
            """,
            new
            {
                o = orgId,
                en = enabled ? 1 : 0,
                forms = formsLoginEnabled ? 1 : 0,
                entity = withMetadata ? "https://idp.example.com/entity" : null,
                sso = withMetadata ? "https://idp.example.com/sso" : null,
                cert = withMetadata ? SampleIdpCertBase64 : null,
                sp = spEntityId,
                nameFmt = nameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                emailAttr = emailAttribute,
                lastTest = lastTestAt,
            });
    }

    private static ClaimsPrincipal BuildPrincipal(string userId, string orgId, string role = "owner")
    {
        return new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim("sub", userId),
                new Claim("org_id", orgId),
                new Claim("tid", orgId),
                new Claim("role", role),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Metadata_ApexContext_ReturnsNotFound()
    {
        var sut = NewControllerWithoutTenant(TenantContext.Apex);
        var result = await sut.Metadata(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Metadata_NoTenantContext_ReturnsNotFound()
    {
        var sut = NewControllerWithoutTenant(tenant: null);
        var result = await sut.Metadata(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Metadata_UninitializedContext_ReturnsNotFound()
    {
        var sut = NewControllerWithoutTenant(TenantContext.Uninitialized);
        var result = await sut.Metadata(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Metadata_TenantWithoutConfig_ReturnsXmlWithDefaultNameIdFormat()
    {
        var orgId = await SeedTenantAsync("acme");
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Metadata(CancellationToken.None);
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal("application/samlmetadata+xml", content.ContentType);
        Assert.Contains("EntityDescriptor", content.Content);
        // Default NameID format (Email) appears when no config row is present.
        Assert.Contains("nameid-format:emailAddress", content.Content);
    }

    [Fact]
    public async Task Metadata_TenantWithConfiguredNameIdFormat_EmitsConfiguredFormat()
    {
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Metadata(CancellationToken.None);
        var content = Assert.IsType<ContentResult>(result);
        Assert.Contains("nameid-format:transient", content.Content);
    }

    // ── Login: query-string parsing ───────────────────────────────────────────

    [Theory]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("True")]
    [InlineData("yes")]    // anything not "0"/"false" is truthy
    [InlineData("")]        // empty string is still non-null → test mode
    public async Task Login_TestParam_TruthyValues_RequireAuthGuard(string testValue)
    {
        // No principal → guard should reject before any redirect happens. The exact failure
        // type isn't fixed (UnauthorizedResult / NotFoundResult depending on tenant context),
        // but the redirect path MUST NOT be taken — that would prove the guard ran.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: true);
        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["test"] = testValue });

        var result = await sut.Login(test: testValue, ct: CancellationToken.None);
        Assert.IsNotType<RedirectResult>(result);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("false")]
    [InlineData("False")]
    [InlineData("FALSE")]
    public async Task Login_TestParam_FalsyValues_TreatedAsRealLogin(string testValue)
    {
        // ?test=0 / ?test=false should NOT trigger test mode — the controller should fall
        // through to the Enabled gate. With enabled=false this produces a 404 Problem.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["test"] = testValue });

        var result = await sut.Login(test: testValue, ct: CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, problem.StatusCode);
    }

    [Fact]
    public async Task Login_NullTest_TreatedAsRealLogin()
    {
        // Default param value (null) is the real-login path.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Login(test: null, ct: CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, problem.StatusCode);
    }

    // ── Login: tenant context branches ────────────────────────────────────────

    [Fact]
    public async Task Login_ApexContext_ReturnsNotFound()
    {
        var sut = NewControllerWithoutTenant(TenantContext.Apex);
        var result = await sut.Login(test: null, ct: CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Login_NoConfigRow_ReturnsNotConfigured404()
    {
        var orgId = await SeedTenantAsync("acme");
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Login(test: null, ct: CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, problem.StatusCode);
        var pd = Assert.IsType<ProblemDetails>(problem.Value);
        Assert.Contains("not configured", pd.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_PartiallyConfigured_NoSsoUrl_Returns404()
    {
        // IsSamlConfigured requires entityId AND ssoUrl AND signing cert. Hits the
        // ssoUrl-missing predicate in the && chain.
        var orgId = await SeedTenantAsync("acme");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, " +
                "idp_entity_id, idp_signing_cert, name_id_format) VALUES (@o, 1, 1, 'e', 'c', 'f')",
                new { o = orgId });
        }
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Login(test: null, ct: CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, problem.StatusCode);
    }

    [Fact]
    public async Task Login_ConfiguredButDisabled_NonTest_Returns404Disabled()
    {
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Login(test: null, ct: CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, problem.StatusCode);
        var pd = Assert.IsType<ProblemDetails>(problem.Value);
        Assert.Contains("not enabled", pd.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_TestMode_Unauthenticated_GuardReturnsNotAuthorized()
    {
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: true);
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Login(test: "1", ct: CancellationToken.None);
        // Guard returns UnauthorizedResult when there's no NameIdentifier/sub claim.
        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task Login_TestMode_Member_GuardForbids()
    {
        // tenant:configure capability is owner/admin only — a 'member' principal is rejected.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: true);
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"member-{Guid.NewGuid():N}@x.test", role: "member");
        var sut = NewControllerForTenant(orgId, "acme",
            user: BuildPrincipal(userId, orgId, role: "member"));

        var result = await sut.Login(test: "1", ct: CancellationToken.None);
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Login_TestMode_Owner_RedirectsToIdpAndIssuesTestRun()
    {
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true); // disabled but allowed in test
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"owner-{Guid.NewGuid():N}@x.test", role: "owner");
        var sut = NewControllerForTenant(orgId, "acme",
            user: BuildPrincipal(userId, orgId, role: "owner"));

        var result = await sut.Login(test: "1", ct: CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("idp.example.com/sso", redirect.Url);
        Assert.Contains("RelayState=test%3A", redirect.Url);

        // A saml_test_runs row was issued — covers IssueTestRunAsync wiring + SetTestCookieAsync.
        await using var conn = await _fixture.Store.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM saml_test_runs WHERE tenant_id = @o", new { o = orgId });
        Assert.Equal(1, count);

        // Cookie also set (Set-Cookie header). dependably_saml_test cookie has a protected payload.
        var setCookie = sut.ControllerContext.HttpContext.Response.Headers.SetCookie.ToString();
        Assert.Contains("dependably_saml_test=", setCookie);
    }

    [Fact]
    public async Task Login_TestMode_OwnerWithOnlySubClaim_StillSucceeds()
    {
        // Covers the User.FindFirst("sub") fallback in SetTestCookieAsync when
        // NameIdentifier is absent — the actor still resolves and Login returns a redirect.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: true);
        var userId = await UserSeeder.InsertAsync(_fixture.Store, orgId,
            $"sub-{Guid.NewGuid():N}@x.test", role: "owner");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                // No NameIdentifier — only "sub" so the OrgAccessGuard's `sub` fallback path
                // is exercised AND SetTestCookieAsync reads actorId via the same fallback.
                new Claim("sub", userId),
                new Claim("org_id", orgId),
                new Claim("tid", orgId),
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));
        var sut = NewControllerForTenant(orgId, "acme", user: principal);

        var result = await sut.Login(test: "1", ct: CancellationToken.None);
        Assert.IsType<RedirectResult>(result);

        await using var conn = await _fixture.Store.OpenAsync();
        var actor = await conn.ExecuteScalarAsync<string?>(
            "SELECT actor_id FROM saml_test_runs WHERE tenant_id = @o", new { o = orgId });
        Assert.Equal(userId, actor);
    }

    [Fact]
    public async Task Login_NonTest_ConfiguredAndEnabled_RedirectsToIdpWithoutRelayState()
    {
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: true);
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Login(test: null, ct: CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("idp.example.com/sso", redirect.Url);
        // Non-test path: no test relay state attached.
        Assert.DoesNotContain("RelayState=test", redirect.Url);
    }

    // ── ACS: tenant resolution ────────────────────────────────────────────────

    [Fact]
    public async Task Acs_ApexContext_ReturnsNotFound()
    {
        var sut = NewControllerWithoutTenant(TenantContext.Apex);
        var result = await sut.Acs(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Acs_NoTenantContext_ReturnsNotFound()
    {
        var sut = NewControllerWithoutTenant(tenant: null);
        var result = await sut.Acs(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── ACS: ResolveTestMode replay/expiry branches ──────────────────────────

    [Fact]
    public async Task Acs_TestMode_RelayStateForConsumedCid_RedirectsTestSessionInvalid()
    {
        // Forge a test_runs row that's ALREADY been consumed. TryConsumeTestRunAsync
        // returns false → controller redirects with test_session_invalid.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var cid = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var expires = DateTimeOffset.UtcNow.AddMinutes(10).ToString("yyyy-MM-ddTHH:mm:ssZ");
            await conn.ExecuteAsync(
                "INSERT INTO saml_test_runs (cid, tenant_id, actor_id, issued_at, expires_at, consumed_at) " +
                "VALUES (@cid, @tid, @actor, @issued, @expires, @consumed)",
                new
                {
                    cid,
                    tid = orgId,
                    actor = "actor-x",
                    issued = now,
                    expires,
                    consumed = now, // already consumed
                });
        }

        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["RelayState"] = $"test:{cid}", ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("/saml-test-result", redirect.Url);
        Assert.Contains("test_session_invalid", redirect.Url);
    }

    [Fact]
    public async Task Acs_TestMode_RelayStateForExpiredCid_RedirectsTestSessionInvalid()
    {
        // expires_at in the past — UPDATE matches zero rows.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var cid = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO saml_test_runs (cid, tenant_id, actor_id, issued_at, expires_at) " +
                "VALUES (@cid, @tid, @actor, @issued, @expires)",
                new
                {
                    cid,
                    tid = orgId,
                    actor = "actor-x",
                    issued = DateTimeOffset.UtcNow.AddMinutes(-30).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    expires = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }

        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["RelayState"] = $"test:{cid}", ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("test_session_invalid", redirect.Url);
    }

    [Fact]
    public async Task Acs_TestMode_UnknownRelayCid_RedirectsTestSessionInvalid()
    {
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["RelayState"] = "test:" + Guid.NewGuid().ToString("N"),
                                  ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("test_session_invalid", redirect.Url);
    }

    [Fact]
    public async Task Acs_TestMode_NonTestRelayState_TreatedAsRealLogin()
    {
        // RelayState that doesn't start with "test:" is a regular SP-initiated relay token —
        // isTest stays false. With saml enabled=false + SAMLResponse present, the early
        // shortcut redirects to test_session_lost.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["RelayState"] = "/some-deep-link",
                                  ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("test_session_lost", redirect.Url);
    }

    [Fact]
    public async Task Acs_TestMode_CookiePresent_ClearsCookieAfterRead()
    {
        // Forge a valid cookie + matching saml_test_runs row. ResolveTestModeAsync should
        // (a) succeed, (b) call ClearTestCookie which sends a Set-Cookie deleting the test cookie.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);

        var cid = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO saml_test_runs (cid, tenant_id, actor_id, issued_at, expires_at) " +
                "VALUES (@cid, @tid, @actor, @issued, @expires)",
                new
                {
                    cid,
                    tid = orgId,
                    actor = "actor",
                    issued = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    expires = DateTimeOffset.UtcNow.AddMinutes(10).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }

        var protector = _dataProtection.CreateProtector("saml-test-marker.v1");
        var payload = JsonSerializer.Serialize(new
        {
            tid = orgId,
            actor = "actor",
            cid,
            exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
        });
        var cookie = protector.Protect(payload);

        var sut = NewControllerForTenant(orgId, "acme",
            cookies: new() { ["dependably_saml_test"] = cookie },
            queryParams: new() { ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        // garbage payload → ParseSamlResponse fails inside; test-mode redirect to /saml-test-result.
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("/saml-test-result", redirect.Url);
        Assert.Contains("validation_failed", redirect.Url);

        // ClearTestCookie was called — Set-Cookie deleting the cookie is in the response.
        var setCookies = sut.ControllerContext.HttpContext.Response.Headers.SetCookie.ToString();
        Assert.Contains("dependably_saml_test=", setCookies);
    }

    // ── ACS: ValidateSamlConfigured short-circuit ────────────────────────────

    [Fact]
    public async Task Acs_NoConfig_NoSamlResponse_Returns404()
    {
        var orgId = await SeedTenantAsync("acme");
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Acs(CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, problem.StatusCode);
    }

    [Fact]
    public async Task Acs_DisabledNoTestMode_WithSamlResponseQuery_RedirectsTestSessionLost()
    {
        // SAMLResponse present in QUERY (not form) + saml disabled + no test mode → early redirect.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("/saml-test-result", redirect.Url);
        Assert.Contains("test_session_lost", redirect.Url);
    }

    [Fact]
    public async Task Acs_DisabledNoTestMode_WithSamlResponseForm_RedirectsTestSessionLost()
    {
        // Same as above but the SAMLResponse arrives via FORM body (POST binding).
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: false, withMetadata: true);
        var sut = NewControllerForTenant(orgId, "acme",
            method: "POST",
            formFields: new() { ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("test_session_lost", redirect.Url);
    }

    [Fact]
    public async Task Acs_NoConfig_WithSamlResponse_RedirectsTestSessionLost()
    {
        // cfg is null (no row at all) — the early shortcut still fires because cfg?.Enabled != true
        // is true for both "disabled" and "no row".
        var orgId = await SeedTenantAsync("acme");
        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Contains("test_session_lost", redirect.Url);
    }

    [Fact]
    public async Task Acs_EnabledButPartiallyConfigured_NoSsoUrl_Returns404()
    {
        // Hits ValidateSamlConfigured's IsSamlConfigured==false branch when SAML is "enabled"
        // (the early shortcut is skipped) but metadata is incomplete.
        var orgId = await SeedTenantAsync("acme");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled, " +
                "idp_entity_id, idp_signing_cert, name_id_format) VALUES (@o, 1, 1, 'e', 'c', 'fmt')",
                new { o = orgId });
        }
        var sut = NewControllerForTenant(orgId, "acme");

        var result = await sut.Acs(CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, problem.StatusCode);
    }

    [Fact]
    public async Task Acs_EnabledFullConfig_GarbageGetResponse_Returns401Problem()
    {
        // Real (non-test) ACS path: enabled config + non-parseable SAMLResponse → ParseSamlResponse
        // catch block returns SamlFailure(isTest=false, ...) which produces a 401 Problem.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: true);
        var sut = NewControllerForTenant(orgId, "acme",
            queryParams: new() { ["SAMLResponse"] = "garbage", ["SigAlg"] = "garbage", ["Signature"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(401, problem.StatusCode);
    }

    [Fact]
    public async Task Acs_EnabledFullConfig_GarbagePostResponse_Returns401Problem()
    {
        // Covers the HttpMethods.IsPost(Request.Method) ternary branch.
        var orgId = await SeedTenantAsync("acme");
        await SeedSamlConfigAsync(orgId, enabled: true);
        var sut = NewControllerForTenant(orgId, "acme",
            method: "POST",
            formFields: new() { ["SAMLResponse"] = "garbage" });

        var result = await sut.Acs(CancellationToken.None);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(401, problem.StatusCode);
    }
}
