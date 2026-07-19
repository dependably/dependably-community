using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
/// Pins that an assertion signed by an EXPIRED pinned IdP signing cert never mints a session on
/// the production ACS path. This is the security boundary the expiry gate exists to close: an
/// IdP-initiated POST goes straight to /saml/acs and never touches the Login initiate path, so a
/// refusal at Login alone would not stop an expired-and-retired (potentially leaked) signing key
/// from being used to log in.
///
/// The response built here is otherwise fully valid — correct issuer, audience, Success status,
/// and a matching pending request — so a 401 can only come from the expiry gate, not from any
/// other ACS hardening check.
/// </summary>
[Trait("Category", "Integration")]
public sealed partial class SamlExpiredIdpCertTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string SpEntityId = "https://sp.expired-cert-test/saml/metadata";
    private const string IdpEntityId = "https://idp.expired-cert-test/entity";
    private const string IdpSsoUrl = "https://idp.expired-cert-test/sso";
    private const string AcsUrl = "https://sp.expired-cert-test/saml/acs";
    private const string EmailNameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    private readonly DependablyFactory _factory;

    // A self-signed RSA signing cert whose validity window (2020-2021) is entirely in the past
    // relative to any clock this suite runs under. Fixed dates keep the fixture deterministic and
    // avoid a wall-clock read.
    private readonly X509Certificate2 _expiredIdpCert;
    private readonly string _expiredIdpPublicCertBase64;

    public SamlExpiredIdpCertTests(DependablyFactory factory)
    {
        _factory = factory;
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=expired-idp", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _expiredIdpCert = req.CreateSelfSigned(
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _expiredIdpPublicCertBase64 = Convert.ToBase64String(_expiredIdpCert.Export(X509ContentType.Cert));
    }

    public async Task InitializeAsync()
    {
        await ((IAsyncLifetime)_factory).InitializeAsync();
        await ResetSamlStateAsync();
        await SeedSamlConfigAsync();
    }

    public Task DisposeAsync()
    {
        _expiredIdpCert.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Regression: a fully valid, correctly signed assertion whose signing cert has expired must be
    /// refused at ACS and must not set a session cookie.
    /// </summary>
    [Fact]
    public async Task Acs_ValidResponseSignedByExpiredCert_RefusesAndIssuesNoSession()
    {
        string requestId = "_" + Guid.NewGuid().ToString("N");
        await IssuePendingRequestAsync(requestId);

        string samlResponse = BuildSignedSamlResponse(inResponseTo: requestId, nameId: UniqueNameId());

        using var client = CreateNoRedirectClient();
        var resp = await PostAcsAsync(client, samlResponse);

        var setCookies = resp.Headers
            .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .SelectMany(h => h.Value)
            .ToList();

        Assert.DoesNotContain(setCookies, c => c.Contains("dependably_session", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── IdP-side signed-response construction ──────────────────────────────────

    private string BuildSignedSamlResponse(string? inResponseTo, string nameId)
    {
        var idpConfig = new Saml2Configuration
        {
            Issuer = IdpEntityId,
            SigningCertificate = _expiredIdpCert,
        };

        var response = new Saml2AuthnResponse(idpConfig)
        {
            Status = Saml2StatusCodes.Success,
            Destination = new Uri(AcsUrl),
        };
        if (inResponseTo is not null)
        {
            response.InResponseTo = new Saml2Id(inResponseTo);
        }

        response.NameId = new Saml2NameIdentifier(nameId, new Uri(EmailNameIdFormat));
        response.ClaimsIdentity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, nameId),
            new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", nameId),
        });

        response.CreateSecurityToken(SpEntityId);

        var binding = new Saml2PostBinding();
        binding.Bind(response);

        return ExtractSamlResponseValue(binding.PostContent);
    }

    private static string ExtractSamlResponseValue(string postContent)
    {
        var match = SamlResponseNameFirstRegex().Match(postContent);
        if (!match.Success)
        {
            match = SamlResponseValueFirstRegex().Match(postContent);
        }

        Assert.True(match.Success, "Could not extract SAMLResponse from PostContent:\n" + postContent);
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

    private HttpClient CreateNoRedirectClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static string UniqueNameId() => $"user-{Guid.NewGuid():N}@expired-cert-test.example";

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

    private async Task SeedSamlConfigAsync()
    {
        string orgId = await GetDefaultOrgIdAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled,
                idp_entity_id, idp_sso_url, idp_signing_cert, sp_entity_id,
                name_id_format, default_role)
            VALUES (@orgId, 1, 1,
                @entityId, @ssoUrl, @cert, @spEntityId,
                @nameIdFormat, 'member')
            ON CONFLICT(org_id) DO UPDATE SET
                enabled = 1, forms_login_enabled = 1,
                idp_entity_id = @entityId, idp_sso_url = @ssoUrl, idp_signing_cert = @cert,
                sp_entity_id = @spEntityId, name_id_format = @nameIdFormat, default_role = 'member'
            """,
            new
            {
                orgId,
                entityId = IdpEntityId,
                ssoUrl = IdpSsoUrl,
                cert = _expiredIdpPublicCertBase64,
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
