using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for the local_only claim / proxy cache-hit gap: <c>local_only</c> is
/// supposed to force a name to serve only the org's hosted artifacts and never a proxied
/// upstream copy (dependency-confusion defense). Before this fix, the claim was consulted only
/// on the proxy MISS/upstream-fetch path — the cache-HIT serve helpers
/// (<see cref="Dependably.Api.NpmProtocol.NpmTarballHandler"/>,
/// <see cref="Dependably.Api.PyPiProtocol.PyPiDownloadHandler"/>) never rechecked the claim
/// before streaming an already-cached <c>cache_artifact</c> row back to the client. A
/// <c>cache_artifact</c> + <c>tenant_artifact_access</c> row that survives a local_only
/// transition — either because an in-flight proxy fetch raced the transition's purge and
/// re-inserted the row afterward, or because air-gap mode's implicit local_only never purges at
/// all — would therefore serve forever despite the claim.
///
/// These tests simulate that surviving row directly (bypassing the purge/race entirely) and
/// assert the download is refused (404), proving the serve-path recheck fires purely because a
/// cache row exists, independent of whatever purge history led to it. They fail on pre-fix code
/// (the seeded row serves 200) and pass once the cache-hit helpers recheck the claim.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxyClaimLocalOnlySurvivingCacheRowTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ProxyClaimLocalOnlySurvivingCacheRowTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> GetDefaultOrgIdAsync()
    {
        using var bootClient = _factory.CreateClient();
        await bootClient.GetAsync("/health");
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    // Directly persists a local_only claim, bypassing ClaimsController's purge entirely — the
    // whole point of these tests is that the cache row survives regardless of purge history
    // (race-losing in-flight fetch, or air-gap mode which never purges at all).
    private async Task CreateLocalOnlyClaimAsync(string orgId, string ecosystem, string name)
    {
        var claims = _factory.Services.GetRequiredService<ClaimRepository>();
        var time = _factory.Services.GetRequiredService<TimeProvider>();
        await claims.ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString("D"),
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = orgId,
            Ecosystem = ecosystem,
            Name = name,
            PriorState = null,
            NewState = ClaimStateMachine.LocalOnly,
            Reason = "surviving-row regression test",
            ActorId = null,
            OccurredAt = time.GetUtcNow(),
            PurgedCount = 0,
        });
    }

    // Seeds a cache_artifact + tenant_artifact_access row directly — simulating the row that
    // survives a local_only transition (either the purge/race window, or air-gap mode which
    // never purges) without needing to reproduce the race itself.
    private async Task SeedSurvivingCacheRowAsync(
        string orgId, string ecosystem, string name, string version, string filename, byte[] bytes)
    {
        string sha256Hex = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256Hex);
        string cacheArtifactId = $"ca-survivor-{Guid.NewGuid():N}";

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
                VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, @sha, @size)
                """,
                new
                {
                    id = cacheArtifactId,
                    ecosystem,
                    name,
                    version,
                    filename,
                    blobKey,
                    sha = sha256Hex,
                    size = bytes.LongLength,
                });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @cacheArtifactId)",
                new { orgId, cacheArtifactId });
        }

        var blobs = _factory.Services.GetRequiredService<IBlobStore>();
        await blobs.PutAsync(blobKey, new MemoryStream(bytes));
    }

    // ── npm ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Npm_LocalOnlyClaim_SurvivingCacheArtifactRow_RefusesServe_404()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"survivor-npm-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        const string version = "1.0.0";
        string file = $"{name}-{version}.tgz";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);

        await CreateLocalOnlyClaimAsync(orgId, "npm", name);
        await SeedSurvivingCacheRowAsync(orgId, "npm", name, version, file, bytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{file}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // HEAD shares the same TryServe-style helper shape (HeadProxyCachedTarballAsync) and is an
    // oracle in its own right (200 vs 404 reveals whether the coordinate is cached) — assert it
    // refuses too, not just the GET download path.
    [Fact]
    public async Task Npm_LocalOnlyClaim_SurvivingCacheArtifactRow_HeadAlsoRefuses_404()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"survivor-npmh-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        const string version = "1.0.0";
        string file = $"{name}-{version}.tgz";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);

        await CreateLocalOnlyClaimAsync(orgId, "npm", name);
        await SeedSurvivingCacheRowAsync(orgId, "npm", name, version, file, bytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var req = new HttpRequestMessage(HttpMethod.Head, $"/npm/tarballs/{name}/{file}");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // Control: local_only must never block the org's own hosted (published) artifact — only
    // proxy-origin cache rows are claim-gated. Pins that the fix is scoped correctly.
    [Fact]
    public async Task Npm_LocalOnlyClaim_HostedVersion_StillServes_200()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"survivor-npm-hosted-{Guid.NewGuid():N}"[..30].ToLowerInvariant();
        const string version = "1.0.0";

        await _factory.PushNpmPackage(name, version);
        await CreateLocalOnlyClaimAsync(orgId, "npm", name);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{name}-{version}.tgz");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── PyPI ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPi_LocalOnlyClaim_SurvivingCacheArtifactRow_RefusesServe_404()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"survivor-pypi-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        const string version = "1.0.0";
        string filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";
        var (bytes, _) = PyPiFixtures.BuildWheel(name, version);

        await CreateLocalOnlyClaimAsync(orgId, "pypi", name);
        await SeedSurvivingCacheRowAsync(orgId, "pypi", name, version, filename, bytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/packages/{filename}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task PyPi_LocalOnlyClaim_SurvivingCacheArtifactRow_HeadAlsoRefuses_404()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"survivor-pypih-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        const string version = "1.0.0";
        string filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";
        var (bytes, _) = PyPiFixtures.BuildWheel(name, version);

        await CreateLocalOnlyClaimAsync(orgId, "pypi", name);
        await SeedSurvivingCacheRowAsync(orgId, "pypi", name, version, filename, bytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var req = new HttpRequestMessage(HttpMethod.Head, $"/packages/{filename}");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── mixed partial-failure: one name local_only + surviving row, another name unaffected ──

    // Two names in the same request wave: one is local_only with a surviving proxy row (must
    // refuse), the other has no claim at all and its own surviving proxy row (must still serve).
    // Pins that the recheck is per-name, not a global proxy-cache kill switch.
    [Fact]
    public async Task Npm_MixedNames_LocalOnlyRefuses_UnclaimedNameStillServes()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string blockedName = $"survivor-mix-blocked-{Guid.NewGuid():N}"[..30].ToLowerInvariant();
        string openName = $"survivor-mix-open-{Guid.NewGuid():N}"[..30].ToLowerInvariant();
        const string version = "1.0.0";
        string blockedFile = $"{blockedName}-{version}.tgz";
        string openFile = $"{openName}-{version}.tgz";
        var (blockedBytes, _, _) = NpmFixtures.BuildTarball(blockedName, version);
        var (openBytes, _, _) = NpmFixtures.BuildTarball(openName, version);

        await CreateLocalOnlyClaimAsync(orgId, "npm", blockedName);
        await SeedSurvivingCacheRowAsync(orgId, "npm", blockedName, version, blockedFile, blockedBytes);
        // openName has no claim row at all — implicit "unclaimed" (no hosted versions), so its
        // proxy cache row must keep serving normally.
        await SeedSurvivingCacheRowAsync(orgId, "npm", openName, version, openFile, openBytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var blockedResp = await client.GetAsync($"/npm/tarballs/{blockedName}/{blockedFile}");
        var openResp = await client.GetAsync($"/npm/tarballs/{openName}/{openFile}");

        Assert.Equal(HttpStatusCode.NotFound, blockedResp.StatusCode);
        Assert.Equal(HttpStatusCode.OK, openResp.StatusCode);
    }

    // ── NuGet ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NuGet_LocalOnlyClaim_SurvivingCacheArtifactRow_RefusesServe_404()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string id = $"survivornuget{Guid.NewGuid():N}"[..20];
        string lowerId = id.ToLowerInvariant();
        const string version = "1.0.0";
        string filename = $"{lowerId}.{version}.nupkg";
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);

        await CreateLocalOnlyClaimAsync(orgId, "nuget", lowerId);
        await SeedSurvivingCacheRowAsync(orgId, "nuget", lowerId, version, filename, bytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Cargo ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Cargo_LocalOnlyClaim_SurvivingCacheArtifactRow_RefusesServe_404()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"survivorcargo{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        const string version = "1.0.0";
        string filename = $"{name}-{version}.crate";
        byte[] bytes = "surviving-crate-bytes"u8.ToArray();

        await CreateLocalOnlyClaimAsync(orgId, "cargo", name);
        await SeedSurvivingCacheRowAsync(orgId, "cargo", name, version, filename, bytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
