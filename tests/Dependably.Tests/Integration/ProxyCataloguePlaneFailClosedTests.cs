using System.Net;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// The fail-closed cache-plane contract for the ecosystems whose proxy blobs are addressed by
/// their package coordinate rather than by content hash: Go, Cargo, and apk.
///
/// A proxied artefact's <c>cache_artifact</c> row is what the registry scans, gates, and reclaims
/// against. When the plane cannot take that row the fetch is refused (503) rather than served
/// ungated — the same contract npm/PyPI/NuGet/Maven enforce through
/// <see cref="Dependably.Protocol.ProxyCatalogueUnavailableException"/>.
///
/// Those four ecosystems key their proxy blobs by SHA-256 and find them through a row-driven
/// lookup, so "no row" already means "cache miss" and a retry re-enters the fetch path. Go, Cargo,
/// and apk probe the blob store by an org-scoped coordinate key instead, and all three cache-hit
/// gates allow a hit they hold no row for — so a staged-but-unrecorded blob would answer every
/// later request with nothing to gate against. These tests pin both halves: the refusal, and the
/// fact that the refusal is not undone by the next request.
///
/// RPM is deliberately absent: its serve path is row-driven (a null row is a cache MISS that
/// re-fetches and re-records), so it has no permanent bypass, and its proxy blobs are
/// content-addressed and shared across tenants, which makes blob-discard actively wrong there.
///
/// The outage is simulated with a trigger that aborts <c>cache_artifact</c> inserts. That models
/// the real failure precisely: reads and existing rows keep working (so a recorded artefact still
/// serves), only the admission of a new artefact fails. Each test owns its factory so the trigger
/// cannot bleed into the shared fixture.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxyCataloguePlaneFailClosedTests
{
    // ── Go ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A .zip first fetch whose cache-plane row cannot be written is answered 503 and serves no
    /// bytes. The staged blob is dropped with the refusal: leaving it behind would let the next
    /// request serve the module from cache with no row to gate against.
    /// </summary>
    [Fact]
    public async Task GoZip_FirstFetch_CachePlaneUnavailable_Refuses503AndLeavesNothingServable()
    {
        const string module = "example.com/failclosed-zip";
        const string version = "v1.0.0";

        await using var factory = new DependablyFactory();
        byte[] zipBytes = BuildGoZip(module, version);
        StubGoZip(factory, module, version, zipBytes);

        await BreakCachePlaneAsync(factory);

        using var client = factory.CreateClientWithBearer(await factory.CreateToken("pull"));
        var resp = await client.GetAsync($"/go/{module}/@v/{version}.zip");

        // 503, not 404: the module exists upstream — we could not admit it.
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.NotEqual(zipBytes, await resp.Content.ReadAsByteArrayAsync());

        string orgId = await DefaultOrgIdAsync(factory);
        Assert.False(await factory.BlobStore.ExistsAsync(
            Dependably.Storage.BlobKeys.Go(orgId, module, version, "zip")));
        Assert.Equal(0, await CacheArtifactCountAsync(factory, "golang", module, version));
    }

    /// <summary>
    /// The refusal survives the retry. A second request during the same outage is refused again
    /// rather than served from the blob staged by the first — the bypass this closes is a
    /// permanent one, not a deferred one. Once the plane recovers the module serves normally and
    /// lands its row; <c>X-Cache: MISS</c> proves the recovered serve re-fetched rather than
    /// serving a leftover blob.
    /// </summary>
    [Fact]
    public async Task GoZip_AfterCachePlaneRecovers_ReFetchesAndRecords()
    {
        const string module = "example.com/failclosed-zip-recovery";
        const string version = "v1.4.0";

        await using var factory = new DependablyFactory();
        byte[] zipBytes = BuildGoZip(module, version);
        StubGoZip(factory, module, version, zipBytes);

        using var client = factory.CreateClientWithBearer(await factory.CreateToken("pull"));

        await BreakCachePlaneAsync(factory);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await client.GetAsync($"/go/{module}/@v/{version}.zip")).StatusCode);

        // The retry, still during the outage, must not serve what the first fetch staged.
        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await client.GetAsync($"/go/{module}/@v/{version}.zip")).StatusCode);

        await RestoreCachePlaneAsync(factory);

        var recovered = await client.GetAsync($"/go/{module}/@v/{version}.zip");
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        Assert.Equal(zipBytes, await recovered.Content.ReadAsByteArrayAsync());
        Assert.Equal("MISS", recovered.Headers.GetValues("X-Cache").First());
        Assert.Equal(1, await CacheArtifactCountAsync(factory, "golang", module, version));
    }

    /// <summary>
    /// Mixed outcomes inside one outage: the .zip carries the module's code and its cache-plane
    /// row, so it is refused; the .info / .mod sidecars are never recorded on the plane and carry
    /// no block state, so they keep serving. The contract refuses what it cannot gate, not the
    /// whole surface.
    /// </summary>
    [Fact]
    public async Task GoOutage_MixedSidecarAndZip_RefusesOnlyTheGatedZip()
    {
        const string module = "example.com/failclosed-mixed";
        const string version = "v2.0.0";
        const string modContent = "module example.com/failclosed-mixed\n\ngo 1.21\n";
        const string infoJson = "{\"Version\":\"v2.0.0\",\"Time\":\"2024-01-15T10:00:00Z\"}";

        await using var factory = new DependablyFactory();
        StubGoZip(factory, module, version, BuildGoZip(module, version));
        StubGoText(factory, $"/{module}/@v/{version}.mod", "text/plain; charset=utf-8", modContent);
        StubGoText(factory, $"/{module}/@v/{version}.info", "application/json", infoJson);

        await BreakCachePlaneAsync(factory);

        using var client = factory.CreateClientWithBearer(await factory.CreateToken("pull"));

        var modResp = await client.GetAsync($"/go/{module}/@v/{version}.mod");
        Assert.Equal(HttpStatusCode.OK, modResp.StatusCode);
        Assert.Equal(modContent, await modResp.Content.ReadAsStringAsync());

        var infoResp = await client.GetAsync($"/go/{module}/@v/{version}.info");
        Assert.Equal(HttpStatusCode.OK, infoResp.StatusCode);

        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await client.GetAsync($"/go/{module}/@v/{version}.zip")).StatusCode);
    }

    // ── Cargo ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// A crate first fetch whose cache-plane row cannot be written is answered 503 and serves no
    /// bytes, and the staged blob is dropped with the refusal.
    /// </summary>
    [Fact]
    public async Task Crate_FirstFetch_CachePlaneUnavailable_Refuses503AndLeavesNothingServable()
    {
        string name = UniqueCrateName("fcclosed");
        const string version = "1.0.0";
        byte[] crateBytes = "fail-closed-crate-bytes"u8.ToArray();

        await using var factory = new DependablyFactory();
        StubCrateDownload(factory, name, version, crateBytes);
        await SeedCargoUpstreamAsync(factory);
        await SetAnonymousPullAsync(factory, true);

        await BreakCachePlaneAsync(factory);

        using var client = factory.CreateClient();
        var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.NotEqual(crateBytes, await resp.Content.ReadAsByteArrayAsync());

        string orgId = await DefaultOrgIdAsync(factory);
        Assert.False(await factory.BlobStore.ExistsAsync(
            Dependably.Storage.BlobKeys.Cargo(orgId, name, version)));
        Assert.Equal(0, await CacheArtifactCountAsync(factory, "cargo", name, version));
    }

    /// <summary>
    /// The Cargo cache-hit gate allows a hit it holds no <c>cache_artifact</c> row for, so a
    /// staged-but-unrecorded crate left in the blob store would be served ungated by the very next
    /// request — turning the 503 into a one-request speed bump. The retry must be refused too, and
    /// the crate must serve normally once the plane recovers.
    /// </summary>
    [Fact]
    public async Task Crate_RetryDuringOutage_StillRefused_ThenServesOnceCachePlaneRecovers()
    {
        string name = UniqueCrateName("fcretry");
        const string version = "2.1.0";
        byte[] crateBytes = "retry-during-outage-bytes"u8.ToArray();

        await using var factory = new DependablyFactory();
        StubCrateDownload(factory, name, version, crateBytes);
        await SeedCargoUpstreamAsync(factory);
        await SetAnonymousPullAsync(factory, true);

        using var client = factory.CreateClient();

        await BreakCachePlaneAsync(factory);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download")).StatusCode);

        // The hit-path gate would allow this one if the first fetch had left its blob behind.
        var retry = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, retry.StatusCode);
        Assert.NotEqual(crateBytes, await retry.Content.ReadAsByteArrayAsync());

        await RestoreCachePlaneAsync(factory);

        var recovered = await client.GetAsync($"/cargo/api/v1/crates/{name}/{version}/download");
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        Assert.Equal(crateBytes, await recovered.Content.ReadAsByteArrayAsync());
        Assert.Equal(1, await CacheArtifactCountAsync(factory, "cargo", name, version));
    }

    /// <summary>
    /// Mixed outcomes inside one outage: a crate already on the cache plane keeps serving (its row
    /// exists, so the serve path can still gate it — only the access tick is lost), while a crate
    /// being fetched for the first time is refused. The contract refuses admission, not traffic.
    /// </summary>
    [Fact]
    public async Task CargoOutage_MixedRecordedAndFirstFetch_RefusesOnlyTheUnrecordedCrate()
    {
        string recorded = UniqueCrateName("fcwarm");
        string firstFetch = UniqueCrateName("fccold");
        const string version = "1.0.0";
        byte[] recordedBytes = "already-catalogued-bytes"u8.ToArray();
        byte[] firstFetchBytes = "never-catalogued-bytes"u8.ToArray();

        await using var factory = new DependablyFactory();
        StubCrateDownload(factory, recorded, version, recordedBytes);
        StubCrateDownload(factory, firstFetch, version, firstFetchBytes);
        await SeedCargoUpstreamAsync(factory);
        await SetAnonymousPullAsync(factory, true);

        using var client = factory.CreateClient();

        // Admit the first crate while the plane is healthy.
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync($"/cargo/api/v1/crates/{recorded}/{version}/download")).StatusCode);
        Assert.Equal(1, await CacheArtifactCountAsync(factory, "cargo", recorded, version));

        await BreakCachePlaneAsync(factory);

        var warm = await client.GetAsync($"/cargo/api/v1/crates/{recorded}/{version}/download");
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        Assert.Equal(recordedBytes, await warm.Content.ReadAsByteArrayAsync());

        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await client.GetAsync($"/cargo/api/v1/crates/{firstFetch}/{version}/download")).StatusCode);
        Assert.Equal(0, await CacheArtifactCountAsync(factory, "cargo", firstFetch, version));
    }

    // ── apk ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// An .apk first fetch whose cache-plane row cannot be written is answered 503 and serves no
    /// bytes. The staged blob is dropped with the refusal: apk blob keys are org-scoped and the
    /// hit path probes the blob store, so leaving it behind would let every later request serve
    /// the package from cache with no row to gate against.
    /// </summary>
    [Fact]
    public async Task Apk_FirstFetch_CachePlaneUnavailable_Refuses503AndLeavesNothingServable()
    {
        const string release = "v3.90";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "failclosed-1.0.0-r0.apk";
        byte[] apkBytes = "failclosed-apk-bytes"u8.ToArray();

        await using var factory = new DependablyFactory();
        StubApk(factory, release, repo, arch, file, apkBytes);

        await BreakCachePlaneAsync(factory);

        using var client = factory.CreateClientWithBearer(await factory.CreateToken("pull"));
        var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

        // 503, not 404: the package exists upstream — we could not admit it.
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.NotEqual(apkBytes, await resp.Content.ReadAsByteArrayAsync());

        string orgId = await DefaultOrgIdAsync(factory);
        Assert.False(await factory.BlobStore.ExistsAsync(
            Dependably.Storage.BlobKeys.Apk(orgId, release, repo, arch, file)));
        Assert.Equal(0, await CacheArtifactCountAsync(factory, "apk", "failclosed", "1.0.0-r0"));
    }

    /// <summary>
    /// The pin for the hit-gate hole. A second request during the same outage is refused again
    /// rather than served from the blob the first fetch staged — the bypass this closes is
    /// permanent, because nothing would ever re-record that blob. Once the plane recovers the
    /// package serves normally and lands its row; <c>X-Cache: MISS</c> proves the recovered serve
    /// re-fetched rather than finding a leftover blob.
    /// </summary>
    [Fact]
    public async Task Apk_RetryDuringOutage_StillRefused_ThenReFetchesOnceCachePlaneRecovers()
    {
        const string release = "v3.91";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "fcretry-2.1.0-r3.apk";
        byte[] apkBytes = "apk-retry-during-outage"u8.ToArray();

        await using var factory = new DependablyFactory();
        StubApk(factory, release, repo, arch, file, apkBytes);

        using var client = factory.CreateClientWithBearer(await factory.CreateToken("pull"));

        await BreakCachePlaneAsync(factory);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}")).StatusCode);

        // The hit path probes the blob store and its gate allows a hit with no row, so this is the
        // request the discarded blob protects.
        var retry = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, retry.StatusCode);
        Assert.NotEqual(apkBytes, await retry.Content.ReadAsByteArrayAsync());

        await RestoreCachePlaneAsync(factory);

        var recovered = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        Assert.Equal(apkBytes, await recovered.Content.ReadAsByteArrayAsync());
        Assert.Equal("MISS", recovered.Headers.GetValues("X-Cache").First());
        Assert.Equal(1, await CacheArtifactCountAsync(factory, "apk", "fcretry", "2.1.0-r3"));
    }

    /// <summary>
    /// Mixed outcomes inside one outage: a package already on the cache plane keeps serving (its
    /// row exists, so the serve path can still gate it — only the access tick is lost), while a
    /// package being fetched for the first time is refused. The contract refuses admission, not
    /// traffic.
    /// </summary>
    [Fact]
    public async Task ApkOutage_MixedRecordedAndFirstFetch_RefusesOnlyTheUnrecordedPackage()
    {
        const string release = "v3.92";
        const string repo = "main";
        const string arch = "x86_64";
        const string recorded = "fcwarm-1.0.0-r0.apk";
        const string firstFetch = "fccold-1.0.0-r0.apk";
        byte[] recordedBytes = "already-catalogued-apk"u8.ToArray();
        byte[] firstFetchBytes = "never-catalogued-apk"u8.ToArray();

        await using var factory = new DependablyFactory();
        StubApk(factory, release, repo, arch, recorded, recordedBytes);
        StubApk(factory, release, repo, arch, firstFetch, firstFetchBytes);

        using var client = factory.CreateClientWithBearer(await factory.CreateToken("pull"));

        // Admit the first package while the plane is healthy.
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync($"/apk/{release}/{repo}/{arch}/{recorded}")).StatusCode);
        Assert.Equal(1, await CacheArtifactCountAsync(factory, "apk", "fcwarm", "1.0.0-r0"));

        await BreakCachePlaneAsync(factory);

        var warm = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{recorded}");
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        Assert.Equal(recordedBytes, await warm.Content.ReadAsByteArrayAsync());

        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await client.GetAsync($"/apk/{release}/{repo}/{arch}/{firstFetch}")).StatusCode);
        Assert.Equal(0, await CacheArtifactCountAsync(factory, "apk", "fccold", "1.0.0-r0"));
    }

    /// <summary>
    /// A filename that does not parse as {pkgname}-{pkgver}-r{pkgrel} has no coordinate to record
    /// or gate on — the controller's documented "never fail on an unparsable filename" contract
    /// skips both. It must therefore keep serving through an outage: refusing it would trade a
    /// bypass that does not exist for an availability loss that does.
    /// </summary>
    [Fact]
    public async Task Apk_UnparsableFilename_KeepsServingDuringOutage()
    {
        const string release = "v3.93";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "no-release-suffix.apk";
        byte[] apkBytes = "unparsable-apk-bytes"u8.ToArray();

        await using var factory = new DependablyFactory();
        StubApk(factory, release, repo, arch, file, apkBytes);

        await BreakCachePlaneAsync(factory);

        using var client = factory.CreateClientWithBearer(await factory.CreateToken("pull"));
        var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(apkBytes, await resp.Content.ReadAsByteArrayAsync());
    }

    // ── Cache-plane outage ────────────────────────────────────────────────────

    // Aborts every cache_artifact INSERT, leaving reads and existing rows intact — the shape of a
    // metadata-store blip that stops a new artefact being admitted. CacheAccessRecorder swallows
    // the abort on both of its attempts and returns null, which is the condition under test.
    private const string OutageTrigger = "cache_plane_outage";

    private static async Task BreakCachePlaneAsync(DependablyFactory factory)
    {
        await using var conn = await OpenAsync(factory);
        await conn.ExecuteAsync(
            $"""
            CREATE TRIGGER {OutageTrigger} BEFORE INSERT ON cache_artifact
            BEGIN SELECT RAISE(ABORT, 'cache plane unavailable'); END
            """);
    }

    private static async Task RestoreCachePlaneAsync(DependablyFactory factory)
    {
        await using var conn = await OpenAsync(factory);
        await conn.ExecuteAsync($"DROP TRIGGER IF EXISTS {OutageTrigger}");
    }

    // ── Fixtures and probes ───────────────────────────────────────────────────

    private static Task<System.Data.Common.DbConnection> OpenAsync(DependablyFactory factory)
    {
        factory.CreateClient().Dispose();
        return factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
    }

    private static async Task<string> DefaultOrgIdAsync(DependablyFactory factory)
    {
        await using var conn = await OpenAsync(factory);
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private static async Task<long> CacheArtifactCountAsync(
        DependablyFactory factory, string ecosystem, string name, string version)
    {
        await using var conn = await OpenAsync(factory);
        return await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = @ecosystem AND name = @name AND version = @version
            """,
            new { ecosystem, name, version });
    }

    private static string UniqueCrateName(string prefix) =>
        $"{prefix}{Guid.NewGuid():N}"[..15].ToLowerInvariant();

    private static void StubGoZip(DependablyFactory factory, string module, string version, byte[] zipBytes) =>
        factory.MockUpstream
            .Given(Request.Create().WithPath($"/{module}/@v/{version}.zip").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/zip")
                .WithBody(zipBytes));

    private static void StubApk(
        DependablyFactory factory, string release, string repo, string arch, string file, byte[] bytes) =>
        factory.MockUpstream
            .Given(Request.Create().WithPath($"/{release}/{repo}/{arch}/{file}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(bytes));

    private static void StubGoText(DependablyFactory factory, string path, string contentType, string body) =>
        factory.MockUpstream
            .Given(Request.Create().WithPath(path).UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", contentType)
                .WithBody(body));

    // BuildCrateDownloadUrl appends /api/v1/crates/{name}/{version}/download for a
    // non-crates.io upstream base. No index stub is registered, so no cksum is advertised and the
    // download proceeds unverified — the same shape as a registry that omits cksum.
    private static void StubCrateDownload(DependablyFactory factory, string name, string version, byte[] bytes) =>
        factory.MockUpstream
            .Given(Request.Create().WithPath($"/api/v1/crates/{name}/{version}/download").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(bytes));

    // Makes WireMock the org's SOLE cargo upstream. First boot seeds the real index.crates.io
    // (there is no Cargo:Upstream test setting the way there is for Go), and leaving it in front
    // of the mock makes these tests depend on egress: unreachable, its fetch exhausts retries and
    // the request 503s from UpstreamFetchFailedException — the same status this suite asserts, for
    // an unrelated reason. Dropping it keeps the assertions about the cache plane.
    private static async Task SeedCargoUpstreamAsync(DependablyFactory factory)
    {
        string orgId = await DefaultOrgIdAsync(factory);
        await using var conn = await OpenAsync(factory);
        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'cargo'",
            new { orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @orgId, 'cargo', @url, 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, url = factory.MockUpstream.Urls[0] });
    }

    private static async Task SetAnonymousPullAsync(DependablyFactory factory, bool enabled)
    {
        string orgId = await DefaultOrgIdAsync(factory);
        await using var conn = await OpenAsync(factory);
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    // A real Go module zip using the GOPROXY entry-naming convention ({module}@{version}/…) that
    // LicenseExtractor.FromGoModuleZip parses, so the recovered fetch exercises the same
    // licence-extraction pass a production first fetch would.
    private static byte[] BuildGoZip(string module, string version)
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(
            ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry($"{module}@{version}/go.mod");
            using var s = entry.Open();
            using var w = new StreamWriter(s, new UTF8Encoding(false));
            w.Write($"module {module}\n\ngo 1.21\n");
        }
        return ms.ToArray();
    }
}
