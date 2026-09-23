using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class PolicyControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public PolicyControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"polm-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    private async Task<HttpClient> PullTokenClient()
    {
        // "Pull-scoped": a read-only PAT carrying exactly the capability this route requires,
        // the same shape EcosystemsApiTests.PullClient uses for every other read:packages
        // surface — including the MCP's own pull-scoped token.
        string pat = await _factory.CreateAdminUserToken("""["read:packages"]""");
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);
        return client;
    }

    // ── Auth ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Get_Member_Returns200()
    {
        using var c = await MemberClient();
        var resp = await c.GetAsync("/api/v1/policies");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Get_PullToken_Returns200()
    {
        using var c = await PullTokenClient();
        var resp = await c.GetAsync("/api/v1/policies");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Get_TokenWithoutReadPackages_Returns403()
    {
        // Carries a different read leaf only — proves the capability gate, not just the scheme.
        string pat = await _factory.CreateAdminUserToken("""["read:audit"]""");
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);

        var resp = await c.GetAsync("/api/v1/policies");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Get_Anonymous_Rejected()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/policies");
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Get_SetsCacheControlNoStore()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/policies");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("no-store", resp.Headers.CacheControl?.ToString() ?? "");
    }

    // ── Shape / defaults ─────────────────────────────────────────────────────

    [Fact]
    public async Task Get_Default_ReturnsExpectedDefaultsAndAllControls()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/policies");
        resp.EnsureSuccessStatusCode();
        var root = (await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync())).RootElement;

        Assert.Equal("off", root.GetProperty("allowlistMode").GetString());
        Assert.True(root.GetProperty("proxyPassthroughEnabled").GetBoolean());

        var license = root.GetProperty("license");
        Assert.Equal("off", license.GetProperty("installMode").GetString());
        Assert.Equal("off", license.GetProperty("publishMode").GetString());
        Assert.Equal(JsonValueKind.Array, license.GetProperty("allowlist").ValueKind);
        Assert.Equal(JsonValueKind.Array, license.GetProperty("blocklist").ValueKind);

        var controls = root.GetProperty("controls");
        string[] expectedKeys =
        [
            "malicious", "malicious_live", "kev", "kev_ransomware", "deprecated", "revoked",
            "install_script", "ssvc_exploitation", "release_age", "vuln_score", "epss",
            "epss_percentile", "provenance", "license",
        ];
        foreach (string key in expectedKeys)
        {
            Assert.True(controls.TryGetProperty(key, out _), $"missing controls.{key}");
        }

        var malicious = controls.GetProperty("malicious");
        Assert.Equal("block", malicious.GetProperty("mode").GetString());
        Assert.Equal("block", malicious.GetProperty("effect").GetString());

        // vuln_score's exact default (10.0 -> "off") is asserted precisely by
        // PolicySummaryBuilderTests against a pristine (null) settings row; this shared-fixture
        // class fixture's org is also mutated by Get_ReflectsProxySettingsWrite_RoundTrip below,
        // so only the shape is asserted here rather than a specific value.
        var vulnScore = controls.GetProperty("vuln_score");
        Assert.Equal(JsonValueKind.Number, vulnScore.GetProperty("maxScore").ValueKind);
        Assert.Contains(vulnScore.GetProperty("effect").GetString(), new[] { "off", "block" });

        var provenance = controls.GetProperty("provenance");
        foreach (string ecosystem in new[] { "npm", "nuget", "pypi", "rpm", "maven", "terraform" })
        {
            Assert.True(provenance.TryGetProperty(ecosystem, out _), $"missing provenance.{ecosystem}");
        }
    }

    [Fact]
    public async Task Get_ReflectsProxySettingsWrite_RoundTrip()
    {
        using var c = await AdminClient();

        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 7.5,
            minReleaseAgeHours = 48,
            blockKev = "warn",
            maxEpssTolerance = 0.4,
        });
        put.EnsureSuccessStatusCode();

        var resp = await c.GetAsync("/api/v1/policies");
        resp.EnsureSuccessStatusCode();
        var controls = (await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("controls");

        Assert.Equal(7.5, controls.GetProperty("vuln_score").GetProperty("maxScore").GetDouble());
        Assert.Equal("block", controls.GetProperty("vuln_score").GetProperty("effect").GetString());
        Assert.Equal(48, controls.GetProperty("release_age").GetProperty("minHours").GetInt32());
        Assert.Equal("block", controls.GetProperty("release_age").GetProperty("effect").GetString());
        Assert.Equal("warn", controls.GetProperty("kev").GetProperty("mode").GetString());
        Assert.Equal(0.4, controls.GetProperty("epss").GetProperty("maxProbability").GetDouble());
    }

    [Fact]
    public async Task Get_ReflectsAddedLicenseEntries()
    {
        using var c = await AdminClient();
        string allow = $"POLTEST-{Guid.NewGuid():N}"[..14];

        (await c.PostAsJsonAsync("/api/v1/license-policy/allowlist", new { licenseSpdx = allow }))
            .EnsureSuccessStatusCode();

        var resp = await c.GetAsync("/api/v1/policies");
        resp.EnsureSuccessStatusCode();
        var license = (await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("license");

        Assert.Contains(license.GetProperty("allowlist").EnumerateArray(),
            e => e.GetProperty("licenseSpdx").GetString() == allow);
    }

    // ── Adversarial twin: no read:tenant-only data leaks through ────────────────

    /// <summary>
    /// Seeds one real sentinel for each read:tenant-only category <see cref="PolicySummaryBuilder"/>
    /// says it excludes — an upstream URL, an upstream credential, an install-script allowlist
    /// entry, trust-anchor material, and a PURL pattern — then asserts none of the five sentinel
    /// values appear anywhere in the raw <c>GET /api/v1/policies</c> body. Real seeded values
    /// rather than guessed top-level key names: a guessed-key check (<c>root.TryGetProperty("anchors")</c>)
    /// passes trivially if the leak lands under a differently-named or nested property, which is
    /// exactly the shape a real regression would take.
    /// </summary>
    [Fact]
    public async Task Get_NeverExposesUpstreamUrlsCredentialsAnchorsOrPurlPatterns()
    {
        // Upstream URL + credential need a master key (secrets are envelope-encrypted at rest),
        // so this sentinel set runs on its own keyed factory rather than the shared fixture.
        string masterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyFactory { MasterKey = masterKey };
        using var c = factory.CreateClient();
        string jwt = await factory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        string upstreamHost = $"nexus-{Guid.NewGuid():N}.example.test";
        string upstreamCredential = $"cred-{Guid.NewGuid():N}";
        (await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "npm",
            url = $"https://{upstreamHost}/npm",
            authType = "bearer",
            secret = upstreamCredential,
        })).EnsureSuccessStatusCode();

        string installScriptName = $"install-sentinel-{Guid.NewGuid():N}";
        (await c.PostAsJsonAsync("/api/v1/install-script-allowlist", new
        {
            ecosystem = "npm",
            name = installScriptName,
        })).EnsureSuccessStatusCode();

        using var rsa = RSA.Create(2048);
        string anchorPem = rsa.ExportSubjectPublicKeyInfoPem();
        var anchorAdd = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "apk",
            anchorKind = "rsa",
            material = anchorPem,
        });
        anchorAdd.EnsureSuccessStatusCode();
        string anchorKeyId = (await JsonDocument.ParseAsync(await anchorAdd.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("keyId").GetString()!;

        string purlPattern = $"purl-sentinel-{Guid.NewGuid():N}";
        (await c.PostAsJsonAsync("/api/v1/allowlist", new { purlPattern }))
            .EnsureSuccessStatusCode();

        var resp = await c.GetAsync("/api/v1/policies");
        resp.EnsureSuccessStatusCode();
        string body = await resp.Content.ReadAsStringAsync();

        Assert.DoesNotContain(upstreamHost, body, StringComparison.Ordinal);
        Assert.DoesNotContain(upstreamCredential, body, StringComparison.Ordinal);
        Assert.DoesNotContain(installScriptName, body, StringComparison.Ordinal);
        // A PEM's own delimiter line is a giveaway on its own; check the actual key material too.
        Assert.DoesNotContain("BEGIN PUBLIC KEY", body, StringComparison.Ordinal);
        Assert.DoesNotContain(
            Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())[..40], body, StringComparison.Ordinal);
        Assert.DoesNotContain(anchorKeyId, body, StringComparison.Ordinal);
        Assert.DoesNotContain(purlPattern, body, StringComparison.Ordinal);

        using var doc = JsonDocument.Parse(body);
        var provenance = doc.RootElement.GetProperty("controls").GetProperty("provenance");
        foreach (var ecosystem in provenance.EnumerateObject())
        {
            // Only mode/effect/anchorsConfigured — never the anchor material itself.
            var keys = ecosystem.Value.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
            Assert.Equal(
                new HashSet<string>(StringComparer.Ordinal) { "mode", "effect", "anchorsConfigured" }, keys);
        }
    }
}

/// <summary>
/// Cross-tenant BOLA coverage for <c>GET /api/v1/policies</c>, mirroring
/// <see cref="PackageLookupTenantPolicyTests"/>'s multi-mode harness: two tenants with different
/// gate policy get different verdicts for the identical endpoint, proving one tenant's owner
/// token can never read the other tenant's policy summary.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PolicyControllerCrossTenantTests : IClassFixture<DependablyMultiUpstreamFactory>
{
    private readonly DependablyMultiUpstreamFactory _factory;
    public PolicyControllerCrossTenantTests(DependablyMultiUpstreamFactory factory) => _factory = factory;

    [Fact]
    public async Task TwoTenantsWithDifferentKevPolicy_EachSeesOnlyItsOwn()
    {
        var strict = await _factory.CreateTenantAsync("polstrict");
        var lenient = await _factory.CreateTenantAsync("pollenient");

        await SetBlockKev(strict, "block");
        await SetBlockKev(lenient, "off");

        using var strictClient = await TenantOwnerClient(strict);
        using var lenientClient = await TenantOwnerClient(lenient);

        var strictResp = await strictClient.GetAsync("/api/v1/policies");
        var lenientResp = await lenientClient.GetAsync("/api/v1/policies");
        strictResp.EnsureSuccessStatusCode();
        lenientResp.EnsureSuccessStatusCode();

        using var strictDoc = JsonDocument.Parse(await strictResp.Content.ReadAsStringAsync());
        using var lenientDoc = JsonDocument.Parse(await lenientResp.Content.ReadAsStringAsync());

        string strictKevMode = strictDoc.RootElement.GetProperty("controls").GetProperty("kev")
            .GetProperty("mode").GetString()!;
        string lenientKevMode = lenientDoc.RootElement.GetProperty("controls").GetProperty("kev")
            .GetProperty("mode").GetString()!;

        Assert.Equal("block", strictKevMode);
        Assert.Equal("off", lenientKevMode);
        Assert.NotEqual(strictKevMode, lenientKevMode);
    }

    /// <summary>
    /// A service token minted for one tenant, presented against a different tenant's own host,
    /// must not read that tenant's policy — the same 404-not-403 BOLA posture
    /// <see cref="Dependably.Security.OrgAccessGuard"/> documents for every other org-scoped route
    /// (an org the token is not a member of is invisible, not merely forbidden).
    /// </summary>
    [Fact]
    public async Task ServiceTokenFromOneTenant_AgainstAnotherTenantsHost_IsNotAllowed()
    {
        var (_, strictTenantId, _) = await _factory.CreateTenantAsync("polxtoken1");
        var (lenientSlug, _, _) = await _factory.CreateTenantAsync("polxtoken2");

        var tokens = _factory.Services.GetRequiredService<Dependably.Infrastructure.TokenRepository>();
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            strictTenantId, $"xtenant-{Guid.NewGuid():N}", """["read:packages"]""", expiresAt: null);

        using var client = _factory.CreateTenantClient(lenientSlug);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);

        var resp = await client.GetAsync("/api/v1/policies");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>
    /// A query-string <c>org</c> parameter must never override the host-resolved tenant. The
    /// controller only ever reads <c>TenantContext</c> for its <c>orgId</c>; this test pins that
    /// so a future edit that starts reading <c>Request.Query["org"]</c> (a textbook BOLA
    /// parameter-override) fails here instead of shipping.
    /// </summary>
    [Fact]
    public async Task OrgQueryStringParameter_NeverOverridesTheHostResolvedTenant()
    {
        var strict = await _factory.CreateTenantAsync("polxquery1");
        var lenient = await _factory.CreateTenantAsync("polxquery2");
        await SetBlockKev(strict, "block");
        await SetBlockKev(lenient, "off");

        using var strictClient = await TenantOwnerClient(strict);

        var resp = await strictClient.GetAsync($"/api/v1/policies?org={lenient.TenantId}");
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        string kevMode = doc.RootElement.GetProperty("controls").GetProperty("kev")
            .GetProperty("mode").GetString()!;

        // Still strict's own "block", never lenient's "off" — the query string had no effect.
        Assert.Equal("block", kevMode);
    }

    private async Task SetBlockKev((string Slug, string TenantId, string OwnerId) tenant, string mode)
    {
        string jwt = await _factory.CreateTenantJwt(tenant.OwnerId, tenant.TenantId);
        using var admin = _factory.CreateTenantClient(tenant.Slug);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await admin.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockKev = mode,
        });
        resp.EnsureSuccessStatusCode();
    }

    private async Task<HttpClient> TenantOwnerClient((string Slug, string TenantId, string OwnerId) tenant)
    {
        string jwt = await _factory.CreateTenantJwt(tenant.OwnerId, tenant.TenantId);
        var client = _factory.CreateTenantClient(tenant.Slug);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }
}
