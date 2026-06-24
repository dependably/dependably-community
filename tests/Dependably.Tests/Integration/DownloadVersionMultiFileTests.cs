using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// A proxy-cached version can map to several files under one coordinate — Maven ships a .jar and
/// a .pom (plus sidecars) per coordinate, PyPI a wheel and an sdist per release — each its own
/// <c>cache_artifact</c> row sharing the version. The management download endpoint takes an
/// optional <c>?file=</c> query so the UI's per-file download in a multi-file version's expanded
/// panel can retrieve a specific artifact; omitting it preserves the single-file default (first
/// cached file for the version).
///
/// These tests seed two distinct-content global-plane files for one version and assert:
/// <c>?file=</c> selects the matching bytes; a non-matching <c>?file=</c> is 404; and the
/// unqualified request still serves one of the files (back-compat).
/// </summary>
[Trait("Category", "Integration")]
public sealed class DownloadVersionMultiFileTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public DownloadVersionMultiFileTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<string> GetDefaultOrgIdAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    // Seeds one global-plane file (cache_artifact + tenant_artifact_access + blob) for the version.
    // Distinct bytes per file give distinct content hashes / blobs, so a download can be attributed
    // to exactly one file rather than passing vacuously.
    private async Task SeedFileAsync(
        string orgId, string ecosystem, string name, string version, string filename, byte[] bytes)
    {
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);

        await _factory.BlobStore.PutAsync(
            BlobKeys.StoreKey(blobKey), new MemoryStream(bytes), CancellationToken.None);

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        await recorder.RecordAccessAsync(new CacheAccess(
            orgId, ecosystem, name, version, filename,
            Sha256: sha256, SizeBytes: bytes.Length,
            BlobKey: $"{blobKey}/{filename}",
            UpstreamUrl: $"https://upstream.example/{filename}"));

        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgId, ecosystem, name, name, isProxy: true, CancellationToken.None);
    }

    [Fact]
    public async Task DownloadVersion_FileParam_SelectsMatchingProxyArtifact()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"gp-multi-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        const string version = "1.2.3";
        string wheel = $"{name}-{version}-py3-none-any.whl";
        string sdist = $"{name}-{version}.tar.gz";
        byte[] wheelBytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        byte[] sdistBytes = [0xAA, 0xBB, 0xCC];

        await SeedFileAsync(orgId, "pypi", name, version, wheel, wheelBytes);
        await SeedFileAsync(orgId, "pypi", name, version, sdist, sdistBytes);

        var client = await AdminClient();
        string baseUrl = $"/api/v1/packages/pypi/{name}/{version}/download";

        // ?file= selects the named artifact's exact bytes.
        var wheelResp = await client.GetAsync($"{baseUrl}?file={Uri.EscapeDataString(wheel)}");
        Assert.Equal(HttpStatusCode.OK, wheelResp.StatusCode);
        Assert.Equal(wheelBytes, await wheelResp.Content.ReadAsByteArrayAsync());
        Assert.Equal(wheel, wheelResp.Content.Headers.ContentDisposition?.FileName?.Trim('"'));

        var sdistResp = await client.GetAsync($"{baseUrl}?file={Uri.EscapeDataString(sdist)}");
        Assert.Equal(HttpStatusCode.OK, sdistResp.StatusCode);
        Assert.Equal(sdistBytes, await sdistResp.Content.ReadAsByteArrayAsync());
        Assert.Equal(sdist, sdistResp.Content.Headers.ContentDisposition?.FileName?.Trim('"'));
    }

    [Fact]
    public async Task DownloadVersion_NoFileParam_StillServesOneFile()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"gp-multi-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        const string version = "2.0.0";
        string wheel = $"{name}-{version}-py3-none-any.whl";
        string sdist = $"{name}-{version}.tar.gz";
        byte[] wheelBytes = [0x10, 0x20, 0x30];
        byte[] sdistBytes = [0x40, 0x50, 0x60, 0x70];

        await SeedFileAsync(orgId, "pypi", name, version, wheel, wheelBytes);
        await SeedFileAsync(orgId, "pypi", name, version, sdist, sdistBytes);

        var client = await AdminClient();
        var resp = await client.GetAsync($"/api/v1/packages/pypi/{name}/{version}/download");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        byte[] served = await resp.Content.ReadAsByteArrayAsync();
        Assert.True(served.SequenceEqual(wheelBytes) || served.SequenceEqual(sdistBytes),
            "Unqualified download must serve one of the version's cached files.");
    }

    [Fact]
    public async Task DownloadVersion_UnknownFileParam_Returns404()
    {
        string orgId = await GetDefaultOrgIdAsync();
        string name = $"gp-multi-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        const string version = "3.1.4";
        string wheel = $"{name}-{version}-py3-none-any.whl";
        await SeedFileAsync(orgId, "pypi", name, version, wheel, [0x01, 0x02]);

        var client = await AdminClient();
        var resp = await client.GetAsync(
            $"/api/v1/packages/pypi/{name}/{version}/download?file=nonexistent-{version}.whl");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
