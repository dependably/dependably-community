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
/// End-to-end coverage of the SAML ACS hardening gates that run AFTER ITfoxtec signature
/// validation: the unsolicited-response reject (empty InResponseTo), the one-shot
/// pending-request bind (TryConsumePendingRequestAsync), and the assertion replay guard
/// (TryConsumeAssertionAsync). The existing SamlTests suite only ever posts garbage
/// SAMLResponse payloads, which fail inside ITfoxtec's Unbind BEFORE these gates run — so
/// the wiring is exercised here with a real, signed SAML response that passes signature
/// validation and reaches the gates.
///
/// The SP validates against a fixed sp_entity_id (audience), idp_entity_id (issuer), and the
/// IdP public signing cert. The IdP side below builds and signs responses with a freshly
/// generated RSA key and seeds the matching public cert into tenant_saml_config.
/// </summary>
[Trait("Category", "Integration")]
public sealed partial class SamlAcsHardeningTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string SpEntityId = "https://sp.acs-test/saml/metadata";
    private const string IdpEntityId = "https://idp.acs-test/entity";
    private const string IdpSsoUrl = "https://idp.acs-test/sso";
    private const string AcsUrl = "https://sp.acs-test/saml/acs";
    private const string EmailNameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    private readonly DependablyFactory _factory;

    // A self-signed RSA signing cert (with private key) generated per test class instance. The
    // public-cert base64 is seeded into tenant_saml_config so the SP trusts assertions this
    // class signs; the private key signs the IdP-side responses.
    private readonly X509Certificate2 _idpCert;
    private readonly string _idpPublicCertBase64;

    public SamlAcsHardeningTests(DependablyFactory factory)
    {
        _factory = factory;
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=acs-test-idp", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _idpCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        _idpPublicCertBase64 = Convert.ToBase64String(_idpCert.Export(X509ContentType.Cert));
    }

    public async Task InitializeAsync()
    {
        await ((IAsyncLifetime)_factory).InitializeAsync();
        await ResetSamlStateAsync();
        await SeedSamlConfigAsync();
    }

    public Task DisposeAsync()
    {
        _idpCert.Dispose();
        return Task.CompletedTask;
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Acs_UnsolicitedResponse_NoInResponseTo_Returns401()
    {
        // No InResponseTo at all → unsolicited / IdP-initiated → rejected before any
        // pending-request lookup. Signature still validates, so we know the 401 comes from
        // the hardening gate, not from Unbind.
        string samlResponse = BuildSignedSamlResponse(inResponseTo: null, nameId: UniqueNameId());

        using var client = CreateNoRedirectClient();
        var resp = await PostAcsAsync(client, samlResponse);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Acs_ValidResponse_MatchingPendingRequest_IssuesSession()
    {
        string requestId = "_" + Guid.NewGuid().ToString("N");
        await IssuePendingRequestAsync(requestId);

        string samlResponse = BuildSignedSamlResponse(inResponseTo: requestId, nameId: UniqueNameId());

        using var client = CreateNoRedirectClient();
        var resp = await PostAcsAsync(client, samlResponse);

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal("/", resp.Headers.Location?.OriginalString);

        var setCookies = resp.Headers
            .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .SelectMany(h => h.Value)
            .ToList();
        Assert.Contains(setCookies, c => c.Contains("dependably_session"));
    }

    [Fact]
    public async Task Acs_ReplayedResponse_Returns401()
    {
        string requestId = "_" + Guid.NewGuid().ToString("N");
        await IssuePendingRequestAsync(requestId);

        string samlResponse = BuildSignedSamlResponse(inResponseTo: requestId, nameId: UniqueNameId());

        using var client = CreateNoRedirectClient();

        // First POST succeeds and consumes the pending row.
        var first = await PostAcsAsync(client, samlResponse);
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.Equal("/", first.Headers.Location?.OriginalString);

        // Replay the exact same SAMLResponse: the pending row is already consumed, so the
        // InResponseTo bind fails → 401. (The assertion replay guard would also catch it, but
        // the pending-request gate runs first.)
        using var replayClient = CreateNoRedirectClient();
        var second = await PostAcsAsync(replayClient, samlResponse);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
    }

    [Fact]
    public async Task Acs_UnknownInResponseTo_Returns401()
    {
        // InResponseTo is a valid, fresh id but no pending row was ever issued for it.
        string unknownId = "_" + Guid.NewGuid().ToString("N");
        string samlResponse = BuildSignedSamlResponse(inResponseTo: unknownId, nameId: UniqueNameId());

        using var client = CreateNoRedirectClient();
        var resp = await PostAcsAsync(client, samlResponse);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── IdP-side signed-response construction ──────────────────────────────────

    /// <summary>
    /// Builds a base64 SAML Response (HTTP-POST binding form value) signed by the IdP cert and
    /// shaped so the SP accepts it: Issuer = idp_entity_id, audience = sp_entity_id, Status =
    /// Success, NameID in email format. When <paramref name="inResponseTo"/> is null the response
    /// carries no InResponseTo (unsolicited).
    /// </summary>
    private string BuildSignedSamlResponse(string? inResponseTo, string nameId)
    {
        var idpConfig = new Saml2Configuration
        {
            Issuer = IdpEntityId,
            SigningCertificate = _idpCert,
        };

        var response = new Saml2AuthnResponse(idpConfig)
        {
            Status = Saml2StatusCodes.Success,
            // ITfoxtec needs a non-null Destination to populate SubjectConfirmationData.Recipient
            // when building the security token. The SP doesn't validate Recipient against the ACS
            // URL (BuildSaml2Configuration sets no destination on the response side), but the
            // value must be present for token creation.
            Destination = new Uri(AcsUrl),
        };
        if (inResponseTo is not null)
        {
            response.InResponseTo = new Saml2Id(inResponseTo);
        }

        response.NameId = new Saml2NameIdentifier(nameId, new Uri(EmailNameIdFormat));

        // CreateSecurityToken reads the assertion's subject + claims from ClaimsIdentity. Carry
        // the NameID and an email claim so EmailAttributeResolver finds an address (JIT
        // provisioning in LoginSamlAsync requires an email for the happy-path session).
        response.ClaimsIdentity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, nameId),
            new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", nameId),
        });

        // appliesToAddress becomes the assertion's AudienceRestriction, which the SP validates
        // against AllowedAudienceUris = [sp_entity_id]. Lifetimes left at the ITfoxtec defaults
        // (5-min subject confirmation, 60-min token) so timing validation passes.
        response.CreateSecurityToken(SpEntityId);

        var binding = new Saml2PostBinding();
        binding.Bind(response);

        return ExtractSamlResponseValue(binding.PostContent);
    }

    // ITfoxtec's PostContent is an HTML auto-submit form; pull the SAMLResponse hidden input's
    // value out of it. The value is HTML-attribute-encoded base64 (no '<'/'>'), so a non-greedy
    // capture up to the closing quote is sufficient.
    private static string ExtractSamlResponseValue(string postContent)
    {
        var match = SamlResponseNameFirstRegex().Match(postContent);
        if (!match.Success)
        {
            // Fall back to attribute-order-independent extraction.
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

    private static string UniqueNameId() => $"user-{Guid.NewGuid():N}@acs-test.example";

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
                cert = _idpPublicCertBase64,
                spEntityId = SpEntityId,
                nameIdFormat = EmailNameIdFormat,
            });
    }

    private async Task IssuePendingRequestAsync(string requestId)
    {
        string orgId = await GetDefaultOrgIdAsync();
        await _factory.Services.GetRequiredService<SamlConfigRepository>()
            .IssuePendingRequestAsync(requestId, orgId, DateTimeOffset.UtcNow.AddMinutes(10));
    }
}
