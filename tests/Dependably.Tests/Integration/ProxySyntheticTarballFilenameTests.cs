using System.Net;
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
/// Regression tests for the proxy synthetic-version tarball filename bug: after the
/// global-plane dedup, proxy artifacts stored in <c>cache_artifact</c> with a
/// content-addressed blob key (<c>BlobKeys.Proxy(sha256)</c>) must advertise a
/// servable <c>{name}-{version}.tgz</c> download URL in the npm packument and a
/// correct <c>{name}-{version}.whl</c> href in the PyPI simple index — not the raw
/// SHA-256 hash that was the last path segment of the blob key.
///
/// Root cause: <c>ToPackageVersionSynthetic</c> omitted the <c>Filename</c> field, so
/// the packument and simple-index renderers fell back to
/// <c>v.BlobKey.Split('/').Last()</c> which for proxy versions yields the SHA-256
/// string. The npm tarball handler then fails to parse a version from the advertised
/// filename and returns 404.
///
/// Mixed partial-failure scenario (per house rule): two versions are seeded in the
/// global plane for the same package. Both must advertise correct, resolvable filenames.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxySyntheticTarballFilenameTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ProxySyntheticTarballFilenameTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ────────────────────────────────────────────────────────────────

    private async Task<string> GetDefaultOrgIdAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    /// <summary>
    /// Seeds a global-plane entry (cache_artifact + tenant_artifact_access + packages row)
    /// for the given coordinate, simulating exactly what the proxy first-fetch path writes.
    /// The blob key is content-addressed (<c>BlobKeys.Proxy(sha256)</c>) — the last segment
    /// is the SHA-256, not the filename. This is the shape that triggered the bug.
    /// Returns the SHA-256 so tests can verify the old code would have used it as the filename.
    /// </summary>
    private async Task<string> SeedProxyCacheEntryAsync(
        string orgId, string ecosystem, string name, string version, string filename)
    {
        byte[] fakeBytes = RandomNumberGenerator.GetBytes(16);
        string sha256 = Convert.ToHexString(SHA256.HashData(fakeBytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);

        await _factory.BlobStore.PutAsync(
            BlobKeys.StoreKey(blobKey), new MemoryStream(fakeBytes), CancellationToken.None);

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        await recorder.RecordAccessAsync(new CacheAccess(
            orgId, ecosystem, name, version, filename,
            Sha256: sha256, SizeBytes: fakeBytes.Length,
            BlobKey: blobKey,
            UpstreamUrl: $"https://upstream.example/{filename}"));

        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgId, ecosystem, name, name, isProxy: true, CancellationToken.None);

        return sha256;
    }

    // ── npm: packument dist.tarball must end in {name}-{version}.tgz ─────────

    /// <summary>
    /// A proxy npm version surfaced through the local packument path (upstream passthrough
    /// disabled) must advertise a <c>dist.tarball</c> URL whose filename segment is
    /// <c>{name}-{version}.tgz</c>, not the content-addressed SHA-256 hash.
    ///
    /// Mixed partial-failure: two versions (1.0.0 and 2.0.0) are seeded for the same
    /// package. Both must expose correct filenames. The test also confirms the SHA-256
    /// string itself does not start with <c>{name}-</c>, meaning that on the old code the
    /// tarball handler's <c>ExtractVersionFromTarballFilename</c> would have returned null
    /// and the download path would have 404'd.
    ///
    /// Old code (before fix): <c>v.BlobKey.Split('/').Last()</c> returned the SHA-256,
    /// so <c>dist.tarball</c> ended in a 64-hex string — the download path returned 404.
    /// New code: <c>v.Filename</c> is populated by <c>ToPackageVersionSynthetic</c> and
    /// used preferentially, so <c>dist.tarball</c> ends in <c>{name}-{version}.tgz</c>.
    /// </summary>
    [Fact]
    public async Task Npm_Packument_ProxyVersion_DistTarball_EndsWithNameVersionTgz()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        string name = $"syntar-npm-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string v1 = "1.0.0";
        string v2 = "2.0.0";
        string file1 = $"{name}-{v1}.tgz";
        string file2 = $"{name}-{v2}.tgz";

        // Disable proxy passthrough so the packument renderer uses the local-only
        // BuildNpmMetadata path (the path that carries the Filename-vs-blob-key bug).
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            string sha256v1 = await SeedProxyCacheEntryAsync(defaultOrgId, "npm", name, v1, file1);
            string sha256v2 = await SeedProxyCacheEntryAsync(defaultOrgId, "npm", name, v2, file2);

            _factory.Services.GetRequiredService<RenderedResponseCache<NpmPackumentKey>>()
                .Evict(new NpmPackumentKey(defaultOrgId, name));

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync($"/npm/{name}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var versions = doc.RootElement.GetProperty("versions");

            // Mixed partial-failure: both versions must be present and each must have a
            // correct, servable dist.tarball — not a SHA-256 hash path segment.
            foreach (var (ver, expectedFilename, sha256) in new[]
            {
                (v1, file1, sha256v1),
                (v2, file2, sha256v2),
            })
            {
                Assert.True(versions.TryGetProperty(ver, out var verObj),
                    $"Version {ver} must appear in packument after global-plane seeding.");

                string? tarball = verObj.GetProperty("dist").GetProperty("tarball").GetString();
                Assert.NotNull(tarball);

                string advertisedFilename = tarball!.Split('/').Last();

                // The advertised filename must be the real artifact filename, not the SHA-256.
                Assert.Equal(expectedFilename, advertisedFilename);

                // Confirm the advertised filename is one the download path can resolve:
                // ExtractVersionFromTarballFilename(shortName, file) returns a non-null result
                // when the file matches {shortName}-{version}.tgz.
                string baseName = advertisedFilename.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase)
                    ? advertisedFilename[..^4]
                    : advertisedFilename;
                bool parseable = baseName.Length > name.Length + 1
                    && baseName.StartsWith(name + "-", StringComparison.Ordinal);
                Assert.True(parseable,
                    $"dist.tarball filename '{advertisedFilename}' must be parseable as {{name}}-{{version}}.tgz.");

                // Confirm the SHA-256 blob-key suffix would NOT be parseable (64 lowercase hex
                // chars never start with "{name}-"), proving the fix is what produces the correct URL.
                Assert.False(sha256.StartsWith(name + "-", StringComparison.Ordinal),
                    "The SHA-256 blob-key suffix must not start with '{name}-' — if it did, " +
                    "the old code would accidentally produce the correct URL and this regression test would be vacuous.");
            }
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── PyPI: simple index href must use the real filename ────────────────────

    /// <summary>
    /// A proxy PyPI version surfaced through the local simple index (upstream passthrough
    /// disabled) must advertise an anchor href that uses the real artifact filename
    /// (e.g. <c>mypackage-1.0.0-py3-none-any.whl</c>), not the SHA-256 blob-key suffix.
    ///
    /// Old code: <c>v.BlobKey.Split('/').Last()</c> returned the SHA-256 — the advertised
    /// href pointed at a non-existent download path. New code: <c>v.Filename</c> is set by
    /// <c>ToPackageVersionSynthetic</c> and used preferentially.
    ///
    /// Mixed partial-failure: two versions of the same package are seeded. Both must expose
    /// their correct wheel filename in the simple index — not the SHA-256 hash.
    /// </summary>
    [Fact]
    public async Task PyPi_SimpleIndex_ProxyVersion_HrefEndsWithRealFilename()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        string name = $"syntar-pypi-{Guid.NewGuid():N}"[..19].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string v1 = "1.0.0";
        string v2 = "2.0.0";
        string file1 = $"{underscored}-{v1}-py3-none-any.whl";
        string file2 = $"{underscored}-{v2}-py3-none-any.whl";

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            string sha256v1 = await SeedProxyCacheEntryAsync(defaultOrgId, "pypi", name, v1, file1);
            string sha256v2 = await SeedProxyCacheEntryAsync(defaultOrgId, "pypi", name, v2, file2);

            _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>()
                .Evict(new PyPiSimpleIndexKey(defaultOrgId, name));

            string token = await _factory.CreateToken("pull");
            using var clientBasic = _factory.CreateClientWithBasic(token);

            var resp = await clientBasic.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string html = await resp.Content.ReadAsStringAsync();

            // Mixed partial-failure: both filenames must appear in the simple index HTML as
            // anchor text and as part of the href. The SHA-256 must not appear as anchor text.
            foreach (var (filename, sha256) in new[] { (file1, sha256v1), (file2, sha256v2) })
            {
                Assert.True(html.Contains($">{filename}<", StringComparison.Ordinal),
                    $"Simple index must contain anchor text '{filename}'.");
                Assert.True(html.Contains($"/packages/{filename}", StringComparison.Ordinal),
                    $"Simple index href must point at '{filename}', not at the SHA-256 blob-key suffix.");

                // The SHA-256 must not appear as anchor text (that is what the old code produced).
                Assert.False(html.Contains($">{sha256}<", StringComparison.Ordinal),
                    $"Simple index must not contain the SHA-256 '{sha256}' as anchor text.");
            }
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── unit: ToPackageVersionSynthetic carries Filename through ──────────────

    /// <summary>
    /// <c>CacheArtifactIndexFacts.ToPackageVersionSynthetic</c> must propagate the
    /// <c>Filename</c> field to the resulting <c>PackageVersion</c>. This is a pure
    /// unit assertion on the projection: no DB, no HTTP.
    ///
    /// Old code: <c>Filename</c> was not set in the initializer, so the projected
    /// <c>PackageVersion.Filename</c> was always null — renderers fell back to the
    /// SHA-256 blob-key suffix.
    /// New code: <c>Filename = Filename</c> copies the field through.
    /// </summary>
    [Fact]
    public void ToPackageVersionSynthetic_PropagatesFilename()
    {
        const string sha256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        var facts = new CacheArtifactIndexFacts
        {
            Id = "ca-001",
            Version = "3.0.0",
            Filename = "some-package-3.0.0.tgz",
            BlobKey = BlobKeys.Proxy(sha256),
            ContentHash = sha256,
            CreatedAt = TestTime.KnownNow,
        };

        var pv = facts.ToPackageVersionSynthetic(new Dictionary<string, VulnGateSignals>());

        // Filename must be carried through — not null.
        Assert.Equal("some-package-3.0.0.tgz", pv.Filename);

        // Confirm the blob-key suffix IS the SHA-256 (documents what old code returned).
        string blobKeySuffix = pv.BlobKey.Split('/').Last();
        Assert.Equal(sha256, blobKeySuffix);

        // Confirm the blob-key suffix differs from Filename — proving why Filename is needed.
        Assert.NotEqual(pv.Filename, blobKeySuffix);
    }

    // ── management UI direct download: Content-Disposition filename ────────────

    /// <summary>
    /// The management UI direct-download endpoint
    /// (GET /api/v1/packages/{eco}/{name}/{version}/download) serves proxy artifacts from the
    /// global plane (no package_versions row). The downloaded file must be labelled with the
    /// real artifact filename via Content-Disposition, not the content-addressed blob-key suffix
    /// (the SHA-256). The bytes were always correct — only the suggested filename was wrong.
    ///
    /// Old code: <c>facts.BlobKey.Split('/').Last()</c> returned the SHA-256.
    /// New code: <c>facts.Filename</c> is used preferentially.
    /// </summary>
    [Fact]
    public async Task DownloadVersion_GlobalPlaneProxyVersion_ContentDispositionUsesRealFilename()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        string name = $"syntar-dl-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "2.0.0";
        string filename = $"{name}-{version}.tgz";

        string sha256 = await SeedProxyCacheEntryAsync(defaultOrgId, "npm", name, version, filename);

        string jwt = await _factory.CreateAdminJwt();
        using var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        var resp = await adminClient.GetAsync($"/api/v1/packages/npm/{name}/{version}/download");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? dispositionName = (resp.Content.Headers.ContentDisposition?.FileNameStar
            ?? resp.Content.Headers.ContentDisposition?.FileName)?.Trim('"');

        // The suggested filename must be the real artifact filename, not the SHA-256.
        Assert.Equal(filename, dispositionName);
        Assert.NotEqual(sha256, dispositionName);
    }
}
