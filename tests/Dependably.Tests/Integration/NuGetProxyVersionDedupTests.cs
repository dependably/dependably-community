using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression tests for issue #395: a NuGet proxy first-fetch mirrors the flatcontainer trio
/// (<c>.nupkg</c>, <c>.nuspec</c>, <c>.sha512</c>) into three <c>cache_artifact</c> rows sharing
/// one version string. Before the fix, every version-level NuGet renderer treated
/// <c>ArtifactInventoryRepository.ListServeableVersionsAsync</c>'s return as already
/// one-entry-per-version and listed that version three times: the registration index, search,
/// and the management package page.
///
/// Each test seeds the three sidecar rows directly (mirroring exactly what the real proxy
/// first-fetch write path produces) alongside a distinct uploaded version, then asserts the
/// proxied version appears exactly once while the uploaded version is still present — the
/// mixed-batch case the fix must not regress.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetProxyVersionDedupTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NuGetProxyVersionDedupTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> GetDefaultOrgIdAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    // Seeds one cache_artifact + tenant_artifact_access row, mirroring the real proxy
    // first-fetch write path (CacheAccessRecorder.RecordAccessAsync). sizeBytes distinguishes
    // the .nupkg row from its sidecars in assertions below.
    private async Task<string> SeedProxyFileAsync(
        string orgId, string name, string version, string filename, long sizeBytes)
    {
        byte[] fakeBytes = new byte[sizeBytes];
        Array.Fill(fakeBytes, (byte)0x5A);
        string sha256 = Convert.ToHexString(SHA256.HashData(fakeBytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);

        await _factory.BlobStore.PutAsync(
            BlobKeys.StoreKey(blobKey), new MemoryStream(fakeBytes), CancellationToken.None);

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        string? caId = await recorder.RecordAccessAsync(new CacheAccess(
            orgId, "nuget", name, version, filename,
            Sha256: sha256, SizeBytes: sizeBytes,
            BlobKey: $"{blobKey}/{filename}",
            UpstreamUrl: $"https://upstream.example/{filename}", Origin: CacheAccessOrigin.FirstFetch));
        Assert.NotNull(caId);

        // Real proxy first-fetch also creates the per-tenant packages row; mirror that here
        // since these tests seed the global plane directly rather than driving a real fetch.
        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgId, "nuget", name, name, isProxy: true, CancellationToken.None);
        return caId!;
    }

    // Seeds the three sidecar rows a single proxied NuGet version casts, matching
    // NuGetFlatContainerHandler's proxy first-fetch coordinates.
    private async Task SeedProxiedVersionTrioAsync(string orgId, string id, string version)
    {
        await SeedProxyFileAsync(orgId, id, version, $"{id}.{version}.nupkg", sizeBytes: 4096);
        await SeedProxyFileAsync(orgId, id, version, $"{id}.nuspec", sizeBytes: 512);
        await SeedProxyFileAsync(orgId, id, version, $"{id}.{version}.nupkg.sha512", sizeBytes: 88);
    }

    // ── Registration index ──────────────────────────────────────────────────────

    [Fact]
    public async Task RegistrationIndex_ProxiedVersionWithSidecarFiles_ListedExactlyOnce()
    {
        string id = $"gpdedupreg{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string uploadedVersion = "1.0.0";
        string proxyVersion = "2.0.0";

        // Mixed batch: an uploaded version alongside a proxy version that casts three rows.
        await _factory.PushNuGetPackage(id, uploadedVersion);
        string defaultOrgId = await GetDefaultOrgIdAsync();

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            await SeedProxiedVersionTrioAsync(defaultOrgId, id, proxyVersion);

            _factory.Services.GetRequiredService<RenderedResponseCache<NuGetRegistrationKey>>()
                .Evict(new NuGetRegistrationKey(defaultOrgId, id, false));

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/nuget/registration/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string json = await resp.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(json);
            var leaves = doc.RootElement.GetProperty("items")[0].GetProperty("items").EnumerateArray();
            var versionCounts = leaves
                .Select(leaf => leaf.GetProperty("catalogEntry").GetProperty("version").GetString())
                .GroupBy(v => v, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key!, g => g.Count());

            // Mixed partial-failure: the uploaded version is present exactly once, and the
            // proxied version — despite casting three cache_artifact rows — is also listed
            // exactly once, never three times.
            Assert.True(versionCounts.TryGetValue(uploadedVersion, out int uploadedCount));
            Assert.Equal(1, uploadedCount);
            Assert.True(versionCounts.TryGetValue(proxyVersion, out int proxyCount),
                $"Proxy version {proxyVersion} missing from registration index entirely.");
            Assert.Equal(1, proxyCount);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── Search ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Search_ProxiedVersionWithSidecarFiles_ListedExactlyOnce()
    {
        string id = $"gpdedupsrch{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string uploadedVersion = "1.0.0";
        string proxyVersion = "2.0.0";

        await _factory.PushNuGetPackage(id, uploadedVersion);
        string defaultOrgId = await GetDefaultOrgIdAsync();
        await SeedProxiedVersionTrioAsync(defaultOrgId, id, proxyVersion);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/query?q={id}&take=10");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string json = await resp.Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("data").EnumerateArray()
            .Single(e => string.Equals(e.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));
        var versionCounts = entry.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetProperty("version").GetString())
            .GroupBy(v => v, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key!, g => g.Count());

        // Mixed partial-failure: both versions present, neither duplicated.
        Assert.True(versionCounts.TryGetValue(uploadedVersion, out int uploadedCount));
        Assert.Equal(1, uploadedCount);
        Assert.True(versionCounts.TryGetValue(proxyVersion, out int proxyCount),
            $"Proxy version {proxyVersion} missing from search results entirely.");
        Assert.Equal(1, proxyCount);
    }

    // ── Management package page ─────────────────────────────────────────────────

    [Fact]
    public async Task ManagementPackagePage_ProxiedVersionWithSidecarFiles_ListedOnceAndPrefersNupkgRow()
    {
        string id = $"gpdedupmgmt{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string uploadedVersion = "1.0.0";
        string proxyVersion = "2.0.0";

        await _factory.PushNuGetPackage(id, uploadedVersion);
        string defaultOrgId = await GetDefaultOrgIdAsync();
        await SeedProxiedVersionTrioAsync(defaultOrgId, id, proxyVersion);

        string jwt = await _factory.CreateAdminJwt();
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await admin.GetAsync($"/api/v1/packages/nuget/{id}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var versions = doc.RootElement.GetProperty("versions").EnumerateArray().ToList();

        var versionCounts = versions
            .Select(v => v.GetProperty("version").GetString())
            .GroupBy(v => v, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key!, g => g.Count());

        // Mixed partial-failure: uploaded version present once, proxy version present once
        // (not three times for its three cache_artifact rows).
        Assert.True(versionCounts.TryGetValue(uploadedVersion, out int uploadedCount));
        Assert.Equal(1, uploadedCount);
        Assert.True(versionCounts.TryGetValue(proxyVersion, out int proxyCount),
            $"Proxy version {proxyVersion} missing from the management package page entirely.");
        Assert.Equal(1, proxyCount);

        // The surviving row is the .nupkg row, not an arbitrary sidecar: its size (4096) is
        // the seeded .nupkg size, never the .nuspec (512) or .sha512 (88) sidecar sizes.
        var proxyEntry = versions.Single(v =>
            string.Equals(v.GetProperty("version").GetString(), proxyVersion, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(4096, proxyEntry.GetProperty("sizeBytes").GetInt64());
        Assert.Equal($"{id}.{proxyVersion}.nupkg", proxyEntry.GetProperty("filename").GetString());
    }
}
