using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Saml2Id = Microsoft.IdentityModel.Tokens.Saml2.Saml2Id;
using Saml2NameIdentifier = Microsoft.IdentityModel.Tokens.Saml2.Saml2NameIdentifier;

namespace Dependably.Tests.Integration;

/// <summary>
/// The negative twin of <see cref="SsoOnlyLoginEnforcementTests"/>: on the very tenant whose
/// password grant is refused, the SAML door still opens. The enforcement reads the tenant's
/// SAML config on the password path only; a real, signed assertion posted to the ACS on an
/// SSO-only tenant must still mint a session, and the pre-login probe must still advertise SAML
/// as the way in. Without this pair, a refusal that accidentally closed both doors — or a
/// readiness predicate that drifted so the ACS and the password path disagreed — would pass
/// every test that only ever asserts the 401.
/// </summary>
[Trait("Category", "Integration")]
public sealed partial class SsoOnlySamlLoginUnaffectedTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string SpEntityId = "https://sp.sso-only-test/saml/metadata";
    private const string IdpEntityId = "https://idp.sso-only-test/entity";
    private const string IdpSsoUrl = "https://idp.sso-only-test/sso";
    private const string AcsUrl = "https://sp.sso-only-test/saml/acs";
    private const string EmailNameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    // test-only placeholder password
    private const string TestPassword = "SsoTwinTest1!";

    private readonly DependablyFactory _factory;
    private readonly X509Certificate2 _idpCert;
    private readonly string _idpPublicCertBase64;

    public SsoOnlySamlLoginUnaffectedTests(DependablyFactory factory)
    {
        _factory = factory;
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=sso-only-test-idp", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        // now-ok: ITfoxtec validates the signing-cert window against the real clock inside
        // the host, so the validity period must straddle real now.
        _idpCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        _idpPublicCertBase64 = Convert.ToBase64String(_idpCert.Export(X509ContentType.Cert));
    }

    public async Task InitializeAsync()
    {
        await ((IAsyncLifetime)_factory).InitializeAsync();
        await ResetSamlStateAsync();
        await SeedSsoOnlyConfigAsync();
    }

    public Task DisposeAsync()
    {
        _idpCert.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Same tenant, same client: the password door is shut and the SAML door is open. The
    /// probe the SPA renders from says so too, so the user who just saw the password refused
    /// is being pointed at a door that actually works. The SAML identity is a fresh
    /// JIT-provisioned member rather than the password-backed one: an assertion for a
    /// password-backed account's email is refused by the takeover guard regardless of this
    /// setting (a password user is never silently auto-linked to an IdP identity), which is a
    /// different decision from the one under test here.
    /// </summary>
    [Fact]
    public async Task SsoOnlyTenant_PasswordRefused_SignedAssertionStillMintsSession()
    {
        string email = $"sso-twin-{Guid.NewGuid():N}@sso-only-test.example";
        await _factory.CreateUser(email, TestPassword);
        string samlNameId = $"sso-jit-{Guid.NewGuid():N}@sso-only-test.example";

        using var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

        var probe = JsonDocument.Parse(await client.GetStringAsync("/api/v1/auth/methods")).RootElement;
        Assert.False(probe.GetProperty("forms").GetBoolean());
        Assert.True(probe.GetProperty("saml").GetBoolean());

        var password = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, password.StatusCode);
        Assert.DoesNotContain(SetCookies(password), c => c.Contains("dependably_session", StringComparison.OrdinalIgnoreCase));

        string requestId = "_" + Guid.NewGuid().ToString("N");
        await IssuePendingRequestAsync(requestId);
        var saml = await PostAcsAsync(client, BuildSignedSamlResponse(requestId, samlNameId));

        Assert.Equal(HttpStatusCode.Redirect, saml.StatusCode);
        Assert.Equal("/", saml.Headers.Location?.OriginalString);
        Assert.Contains(SetCookies(saml), c => c.Contains("dependably_session", StringComparison.OrdinalIgnoreCase));
    }

    // ── IdP-side signed-response construction (mirrors SamlAcsHardeningTests) ──

    private string BuildSignedSamlResponse(string inResponseTo, string nameId)
    {
        var idpConfig = new Saml2Configuration
        {
            Issuer = IdpEntityId,
            SigningCertificate = _idpCert,
        };

        var response = new Saml2AuthnResponse(idpConfig)
        {
            Status = Saml2StatusCodes.Success,
            Destination = new Uri(AcsUrl),
            InResponseTo = new Saml2Id(inResponseTo),
            NameId = new Saml2NameIdentifier(nameId, new Uri(EmailNameIdFormat)),
            ClaimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, nameId),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", nameId),
            }),
        };

        response.CreateSecurityToken(SpEntityId);

        var binding = new Saml2PostBinding();
        binding.Bind(response);

        var match = SamlResponseNameFirstRegex().Match(binding.PostContent);
        if (!match.Success)
        {
            match = SamlResponseValueFirstRegex().Match(binding.PostContent);
        }

        Assert.True(match.Success, "Could not extract SAMLResponse from PostContent:\n" + binding.PostContent);
        return WebUtility.HtmlDecode(match.Groups["v"].Value);
    }

    [GeneratedRegex("name=\"SAMLResponse\"[^>]*value=\"(?<v>[^\"]+)\"",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex SamlResponseNameFirstRegex();

    [GeneratedRegex("value=\"(?<v>[^\"]+)\"[^>]*name=\"SAMLResponse\"",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex SamlResponseValueFirstRegex();

    private static async Task<HttpResponseMessage> PostAcsAsync(HttpClient client, string samlResponse)
    {
        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("SAMLResponse", samlResponse),
        });
        return await client.PostAsync("/saml/acs", form);
    }

    private static List<string> SetCookies(HttpResponseMessage resp) => resp.Headers
        .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
        .SelectMany(h => h.Value)
        .ToList();

    // ── Seeding / state reset ──────────────────────────────────────────────────

    private async Task<string> GetDefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org not found");
    }

    private async Task ResetSamlStateAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("DELETE FROM tenant_saml_config");
        await conn.ExecuteAsync("DELETE FROM saml_pending_requests");
        await conn.ExecuteAsync("DELETE FROM saml_consumed_assertions");
    }

    // SAML-ready AND SSO-only: the state the admin guard only lets a tenant reach after a
    // successful SAML test, seeded directly so the twin pins the enforcement, not the guard.
    private async Task SeedSsoOnlyConfigAsync()
    {
        string orgId = await GetDefaultOrgIdAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled,
                idp_entity_id, idp_sso_url, idp_signing_cert, sp_entity_id,
                name_id_format, default_role)
            VALUES (@orgId, 1, 0,
                @entityId, @ssoUrl, @cert, @spEntityId,
                @nameIdFormat, 'member')
            """,
            new
            {
                orgId,
                entityId = IdpEntityId,
                ssoUrl = IdpSsoUrl,
                cert = _idpPublicCertBase64,
                spEntityId = SpEntityId,
                nameIdFormat = EmailNameIdFormat,
            });
    }

    private async Task IssuePendingRequestAsync(string requestId)
    {
        string orgId = await GetDefaultOrgIdAsync();
        // now-ok: the DI-resolved repository consumes this window against the host's real
        // clock during the ACS round-trip, so the expiry must be future relative to real now.
        await _factory.Services.GetRequiredService<SamlConfigRepository>()
            .IssuePendingRequestAsync(requestId, orgId, DateTimeOffset.UtcNow.AddMinutes(10));
    }
}
