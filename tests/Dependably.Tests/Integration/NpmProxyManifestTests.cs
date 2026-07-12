using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for proxy-cached npm versions carrying no stored install manifest:
/// <c>cache_artifact.manifest_json</c> must be populated at npm proxy first-fetch (parsed from
/// the tarball's package.json, same extraction as hosted publish), projected through
/// <see cref="Infrastructure.CacheArtifactIndexFacts.ToPackageVersionSynthetic"/>, and rendered
/// by the fallback/local packument build path — not just the hosted-publish path already
/// covered by <see cref="NpmPackumentManifestTests"/>.
///
/// Fail-before/pass-after: before this column existed, every proxy-cached version rendered the
/// minimal legacy shape (name/version/dist only) whenever the packument fell back to
/// locally-derived metadata, breaking dependency resolution for any client that installed from
/// the fallback document.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmProxyManifestTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private static Dictionary<string, object> CliManifestFields() => new()
    {
        ["bin"] = "./bin/cli.js",
        ["dependencies"] = new Dictionary<string, string> { ["yaml"] = "^2.0.0" },
        ["engines"] = new Dictionary<string, string> { ["node"] = ">=18" },
    };

    private async Task<string?> QueryManifestJsonAsync(string name, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT manifest_json FROM cache_artifact
            WHERE ecosystem = 'npm' AND name = @name AND version = @version
            ORDER BY first_cached_at DESC LIMIT 1
            """,
            new { name, version });
    }

    private void StubTarball(string name, string file, byte[] bytes)
        => _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

    // ── first-fetch capture ──────────────────────────────────────────────────────

    [Fact]
    public async Task ProxyFirstFetch_PersistsManifestJsonOnCacheArtifact()
    {
        string name = $"proxymfst{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string version = "1.0.0";
        string file = $"{name}-{version}.tgz";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version, "MIT", CliManifestFields());
        StubTarball(name, file, bytes);
        // No packument-metadata mapping: TryFetchNpmFirstFetchMetadataAsync fails soft
        // (WireMock 404s unmatched paths) and the manifest capture — sourced purely from the
        // tarball's package.json — proceeds independently of that call's outcome.

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? stored = await QueryManifestJsonAsync(name, version);
        Assert.NotNull(stored);
        using var doc = JsonDocument.Parse(stored!);
        Assert.Equal("./bin/cli.js", doc.RootElement.GetProperty("bin").GetProperty(name).GetString());
        Assert.Equal("^2.0.0", doc.RootElement.GetProperty("dependencies").GetProperty("yaml").GetString());
        Assert.Equal(">=18", doc.RootElement.GetProperty("engines").GetProperty("node").GetString());
    }

    // ── fallback packument (the issue's regression) ──────────────────────────────

    [Fact]
    public async Task FallbackPackument_UpstreamUnreachable_RendersManifestAndTimeMap()
    {
        string name = $"proxyfb{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string version = "2.0.0";
        string file = $"{name}-{version}.tgz";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version, "MIT", CliManifestFields());
        StubTarball(name, file, bytes);
        // Deliberately no packument-metadata mapping for GET /{name} — every call to it (both
        // the first-fetch metadata probe and the later packument GET) 404s, forcing the
        // fallback/locally-derived render path this issue is about.

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var tarballResp = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, tarballResp.StatusCode);

        var packumentResp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, packumentResp.StatusCode);

        using var doc = JsonDocument.Parse(await packumentResp.Content.ReadAsStringAsync());
        var ver = doc.RootElement.GetProperty("versions").GetProperty(version);

        // The regression: the fallback packument must carry install-relevant metadata, not
        // just {name, version, dist}.
        Assert.Equal("./bin/cli.js", ver.GetProperty("bin").GetProperty(name).GetString());
        Assert.Equal("^2.0.0", ver.GetProperty("dependencies").GetProperty("yaml").GetString());
        Assert.Equal(">=18", ver.GetProperty("engines").GetProperty("node").GetString());

        // pnpm warns on an absent "time" map — the fallback/local build now emits one from the
        // stored publish timestamp (here, first_cached_at, since upstream never supplied one).
        Assert.True(doc.RootElement.TryGetProperty("time", out var timeObj),
            "fallback packument must carry a time map");
        Assert.True(timeObj.TryGetProperty(version, out _));
    }

    // ── lazy backfill ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task LazyBackfill_PreMigrationRowWithNullManifest_PopulatesOnNextFetch()
    {
        string name = $"proxybf{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string version = "1.0.0";
        string file = $"{name}-{version}.tgz";
        var (bytes, sha256Hex, _) = NpmFixtures.BuildTarball(name, version, "MIT", CliManifestFields());
        StubTarball(name, file, bytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // First fetch populates manifest_json normally.
        var first = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.NotNull(await QueryManifestJsonAsync(name, version));

        // Simulate a pre-migration row: null out manifest_json (mirrors
        // NpmPackumentManifestTests.LegacyRow_...), then evict the blob so the next request is a
        // genuine cache MISS that re-fetches from upstream and re-records facts against the SAME
        // cache_artifact row (INSERT ... ON CONFLICT DO NOTHING resolves to the existing id).
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE cache_artifact SET manifest_json = NULL WHERE ecosystem = 'npm' AND name = @name AND version = @version",
                new { name, version });
        }
        Assert.Null(await QueryManifestJsonAsync(name, version));

        var blobs = _factory.Services.GetRequiredService<IBlobStore>();
        await blobs.DeleteAsync(BlobKeys.Proxy(sha256Hex));

        // Second request: cache row survives, blob is gone → falls through to a genuine
        // upstream re-fetch, which backfills manifest_json via the COALESCE keep-existing update.
        var second = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        string? backfilled = await QueryManifestJsonAsync(name, version);
        Assert.NotNull(backfilled);
        using var doc = JsonDocument.Parse(backfilled!);
        Assert.Equal("^2.0.0", doc.RootElement.GetProperty("dependencies").GetProperty("yaml").GetString());
    }

    // ── mixed partial-failure: one version manifest-populated, one not ───────────

    [Fact]
    public async Task MixedVersions_OneWithManifestOneWithout_RendersEachShapeIndependently()
    {
        string name = $"proxymix{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        const string versionWithManifest = "1.0.0";
        const string versionWithoutManifest = "2.0.0";
        string fileWith = $"{name}-{versionWithManifest}.tgz";
        string fileWithout = $"{name}-{versionWithoutManifest}.tgz";

        var (withBytes, _, _) = NpmFixtures.BuildTarball(name, versionWithManifest, "MIT", CliManifestFields());
        // No extra manifest fields: BuildJson finds nothing install-relevant → manifest_json stays NULL.
        var (withoutBytes, _, _) = NpmFixtures.BuildTarball(name, versionWithoutManifest);
        StubTarball(name, fileWith, withBytes);
        StubTarball(name, fileWithout, withoutBytes);
        // No packument-metadata mapping — both tarball fetches capture only what the tarball
        // itself carries, and GET /{name} later 404s into the fallback/local build path.

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync($"/npm/tarballs/{name}/{fileWith}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync($"/npm/tarballs/{name}/{fileWithout}")).StatusCode);

        Assert.NotNull(await QueryManifestJsonAsync(name, versionWithManifest));
        Assert.Null(await QueryManifestJsonAsync(name, versionWithoutManifest));

        var packumentResp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, packumentResp.StatusCode);
        using var doc = JsonDocument.Parse(await packumentResp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions");

        // The version with a stored manifest renders the full install-relevant shape.
        var withVer = versions.GetProperty(versionWithManifest);
        Assert.Equal("^2.0.0", withVer.GetProperty("dependencies").GetProperty("yaml").GetString());

        // The version without a stored manifest renders the minimal legacy shape — no
        // dependencies/bin/engines keys at all, but still a valid, servable entry.
        var withoutVer = versions.GetProperty(versionWithoutManifest);
        Assert.False(withoutVer.TryGetProperty("dependencies", out _));
        Assert.False(withoutVer.TryGetProperty("bin", out _));
        Assert.False(withoutVer.TryGetProperty("engines", out _));
        Assert.Equal(name, withoutVer.GetProperty("name").GetString());
        Assert.Equal(versionWithoutManifest, withoutVer.GetProperty("version").GetString());
    }

    // ── non-npm ecosystems unaffected ─────────────────────────────────────────────

    [Fact]
    public async Task NuGet_ProxyFirstFetch_ManifestJsonStaysNull_NoError()
    {
        string id = $"NuGetMfst{Guid.NewGuid():N}"[..18];
        string version = "1.0.0";
        string lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        string filename = $"{lowerId}.{version}.nupkg";

        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("""{ "published": "2023-01-01T00:00:00Z", "listed": true }"""));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? manifestJson = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT manifest_json FROM cache_artifact
            WHERE ecosystem = 'nuget' AND name = @name AND version = @version
            ORDER BY first_cached_at DESC LIMIT 1
            """,
            new { name = lowerId, version });
        Assert.Null(manifestJson);
    }
}
