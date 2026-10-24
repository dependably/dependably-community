using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// The surfaces beyond the read plane that read a Hex upstream through the shared verified
/// fetcher: the latest-version resolver (versions-behind), the lookup endpoint, and the
/// retirement-as-deprecation mapping they both derive from the signed package resource.
/// </summary>
[Trait("Category", "Integration")]
public sealed class HexRefreshSurfacesTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    };

    private readonly RSA _upstreamKey = RSA.Create(2048);

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        string orgId = await OrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'hex'", new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, public_key_pem) VALUES (@id, @orgId, 'hex', @url, 0, @pem)",
            new { id = Guid.NewGuid().ToString("N"), orgId, url = _factory.MockUpstream.Urls[0], pem = HexRegistrySigner.ExportPublicKeyPem(_upstreamKey) });
    }

    public async Task DisposeAsync()
    {
        _upstreamKey.Dispose();
        await _factory.DisposeAsync();
    }

    private static readonly DateTimeOffset Epoch = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private void StubPackage(string name)
    {
        static HexRelease Release(string v, int day, HexRetirementStatus? retired = null) =>
            new(v, new byte[32], Array.Empty<HexDependency>(), retired, new byte[32], null, HexTimestamp.FromDateTimeOffset(Epoch.AddDays(day)));
        var package = new HexPackage(name, "upstream-repo", new[]
        {
            Release("1.0.0", 1),
            Release("1.1.0", 2, new HexRetirementStatus(HexRetirementReason.Security, "CVE-2026-9")),
            Release("2.0.0-rc.1", 3),
            Release("1.2.0", 4),
        }, Array.Empty<HexSecurityAdvisory>());
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/packages/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody(HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), _upstreamKey)));
    }

    private async Task<string> OrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private static string NewName() => $"hexref{Guid.NewGuid():N}"[..14];

    // The lookup endpoint is a management surface: a signed-in member, not a service token.
    private async Task<HttpClient> MemberClientAsync()
    {
        string userId = await _factory.CreateUser($"hex-lookup-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwt(userId, "member"));
    }

    [Fact]
    public async Task LatestResolver_SkipsRetiredAndPreReleases_AndCarriesThePublishTime()
    {
        string name = NewName();
        StubPackage(name);
        var resolver = _factory.Services.GetRequiredService<IUpstreamLatestVersionResolver>();

        var latest = await resolver.ResolveAsync("hex", await OrgIdAsync(), name);

        Assert.Equal("1.2.0", latest.Version);
        Assert.Equal(Epoch.AddDays(4), latest.PublishedAt);
        Assert.Equal(new[] { "1.2.0", "1.0.0" }, latest.StableVersionsDescending);
    }

    [Fact]
    public async Task LatestResolver_UnknownPackage_IsNone()
    {
        var resolver = _factory.Services.GetRequiredService<IUpstreamLatestVersionResolver>();
        var latest = await resolver.ResolveAsync("hex", await OrgIdAsync(), NewName());
        Assert.Null(latest.Version);
    }

    [Fact]
    public async Task Lookup_ResolvesTheLatestStableRelease_AndBlocksARetiredOneUnderBlockDeprecated()
    {
        string name = NewName();
        StubPackage(name);
        string orgId = await OrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE org_settings SET block_deprecated = 'block_all' WHERE org_id = @orgId", new { orgId });
        }

        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        using var client = await MemberClientAsync();

        var latest = await client.GetAsync($"/api/v1/lookup?ecosystem=hex&name={name}");
        Assert.Equal(HttpStatusCode.OK, latest.StatusCode);
        using var latestDoc = JsonDocument.Parse(await latest.Content.ReadAsStringAsync());
        Assert.Equal("1.2.0", latestDoc.RootElement.GetProperty("version").GetString());
        Assert.True(latestDoc.RootElement.GetProperty("versionInferred").GetBoolean());
        Assert.Equal($"pkg:hex/{name}@1.2.0", latestDoc.RootElement.GetProperty("purl").GetString());
        Assert.Equal("allowed", latestDoc.RootElement.GetProperty("verdict").GetString());

        // The retirement is the deprecation signal the block gate reads.
        var retired = await client.GetAsync($"/api/v1/lookup?ecosystem=hex&name={name}&version=1.1.0");
        Assert.Equal(HttpStatusCode.OK, retired.StatusCode);
        using var retiredDoc = JsonDocument.Parse(await retired.Content.ReadAsStringAsync());
        Assert.Equal("blocked", retiredDoc.RootElement.GetProperty("verdict").GetString());
        Assert.Contains("deprecat", retiredDoc.RootElement.GetProperty("blockedReason").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RefreshPass_RetirementUpstreamAfterCaching_ReachesTheServedIndex_AndBlockAllHidesIt()
    {
        // A release cached before upstream retired it: the org's own signed /packages resource
        // advertises what hex_release records for a held release, so the retirement reaches Mix
        // and Rebar3 only once the refresh writes it there.
        string name = NewName();
        StubPackage(name);
        string orgId = await OrgIdAsync();
        await SeedCachedReleaseAsync(orgId, name, "1.1.0");
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        using var orgKey = HexRegistrySigner.ParsePublicKeyPem(await client.GetStringAsync("/hex/public_key"));

        Assert.Null((await ServedReleaseAsync(client, orgKey, name, "1.1.0"))!.Retired);

        await RefreshServiceForTest().RunRefreshPassAsync(CancellationToken.None);

        var served = await ServedReleaseAsync(client, orgKey, name, "1.1.0");
        Assert.Equal(new HexRetirementStatus(HexRetirementReason.Security, "CVE-2026-9"), served!.Retired);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE org_settings SET block_deprecated = 'block_all' WHERE org_id = @orgId", new { orgId });
        }

        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        Assert.Null(await ServedReleaseAsync(client, orgKey, name, "1.1.0"));
    }

    // The background job is disabled in the test host; this builds the same service from the
    // host's own registrations with the job enabled and no delay between groups.
    private DeprecationRefreshService RefreshServiceForTest()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0" })
            .Build();
        return ActivatorUtilities.CreateInstance<DeprecationRefreshService>(
            _factory.Services, NSubstitute.Substitute.For<IAirGapMode>(), (IConfiguration)config);
    }

    private async Task SeedCachedReleaseAsync(string orgId, string name, string version)
    {
        string caId = Guid.NewGuid().ToString("N");
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
                VALUES (@id, 'hex', @name, @version, @filename, @blobKey, @contentHash, @purl)
                """,
                new
                {
                    id = caId,
                    name,
                    version,
                    filename = $"{name}-{version}.tar",
                    blobKey = $"proxy/{caId}/{name}-{version}.tar",
                    contentHash = new string('a', 64),
                    purl = $"pkg:hex/{name}@{version}",
                });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)", new { orgId, caId });
        }

        await _factory.Services.GetRequiredService<Dependably.Infrastructure.Hex.HexReleaseRepository>().UpsertCachedAsync(caId,
            new Dependably.Infrastructure.Hex.HexReleaseFacts(new string('b', 64), [], name, ["mix"], null, null, null, false, null));
    }

    private static async Task<HexRelease?> ServedReleaseAsync(HttpClient client, RSA orgKey, string name, string version)
    {
        var resp = await client.GetAsync($"/hex/packages/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var package = HexRegistryCodec.DecodePackage(HexRegistrySigner.OpenResource(await resp.Content.ReadAsByteArrayAsync(), orgKey));
        return package.Releases.SingleOrDefault(r => r.Version == version);
    }

    [Fact]
    public async Task Lookup_UnknownHexPackage_IsAFoundFalseAnswer()
    {
        using var client = await MemberClientAsync();
        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=hex&name={NewName()}&version=1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.False(doc.RootElement.GetProperty("found").GetBoolean());
    }
}
