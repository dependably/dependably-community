using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// The Cargo sparse index and Go's <c>@v/list</c> enforced the block gate on download and not at
/// all on their index, so each advertised versions its own artifact route refuses. Both resolvers
/// treat a refused download as a hard failure once they have committed to a version, so an index
/// entry the client cannot fetch is a broken build rather than a resolution it routes around.
///
/// Manual block is the arm under test throughout. That is deliberate: it needs no publish
/// timestamp, and neither ecosystem records one — both write <c>publishedAt: null</c> at proxy
/// first fetch — so the release-age arm is inert here and an arm that actually has facts is the
/// only honest way to prove the filter runs.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CargoGoIndexParityTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public CargoGoIndexParityTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Cargo sparse index ────────────────────────────────────────────────────

    /// <summary>
    /// A blocked crate version leaves the sparse index, and the surviving version stays — the
    /// mixed case, so a filter that emptied the index would not pass.
    /// </summary>
    [Fact]
    public async Task CargoIndex_BlockedVersion_IsAbsent_AndTheOtherVersionRemains()
    {
        string name = $"cgate{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        await PublishCrateAsync(name, "1.0.0");
        await PublishCrateAsync(name, "2.0.0");

        string index = $"/cargo/{Dependably.Api.CargoController.IndexPath(name)}";
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string before = await (await client.GetAsync(index)).Content.ReadAsStringAsync();
        Assert.Contains("\"1.0.0\"", before, StringComparison.Ordinal);
        Assert.Contains("\"2.0.0\"", before, StringComparison.Ordinal);

        await BlockUploadedVersionAsync("cargo", name, "1.0.0");

        var resp = await client.GetAsync(index);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string after = await resp.Content.ReadAsStringAsync();

        Assert.DoesNotContain("\"1.0.0\"", after, StringComparison.Ordinal);
        Assert.Contains("\"2.0.0\"", after, StringComparison.Ordinal);
    }

    /// <summary>
    /// The parity half: the version the index stopped advertising is the one the download refuses.
    /// Without this the index filter could be hiding the wrong thing and still look correct.
    /// </summary>
    [Fact]
    public async Task CargoIndex_BlockedVersion_IsTheSameVersionTheDownloadRefuses()
    {
        string name = $"cpar{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        await PublishCrateAsync(name, "1.0.0");
        await BlockUploadedVersionAsync("cargo", name, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string body = await (await client.GetAsync(
            $"/cargo/{Dependably.Api.CargoController.IndexPath(name)}")).Content.ReadAsStringAsync();
        Assert.DoesNotContain("\"1.0.0\"", body, StringComparison.Ordinal);

        var download = await client.GetAsync($"/cargo/api/v1/crates/{name}/1.0.0/download");
        Assert.Equal(HttpStatusCode.Forbidden, download.StatusCode);
    }

    // ── Go @v/list ────────────────────────────────────────────────────────────

    /// <summary>
    /// A blocked module version leaves <c>@v/list</c>, and the surviving version stays.
    /// </summary>
    [Fact]
    public async Task GoVersionList_BlockedVersion_IsAbsent_AndTheOtherVersionRemains()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await SeedGoVersionAsync(module, "v1.0.0", ageRank: 0);
        await SeedGoVersionAsync(module, "v1.1.0", ageRank: 1);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string before = await (await client.GetAsync($"/go/{module}/@v/list")).Content.ReadAsStringAsync();
        Assert.Contains("v1.0.0", before, StringComparison.Ordinal);
        Assert.Contains("v1.1.0", before, StringComparison.Ordinal);

        await BlockUploadedVersionAsync("golang", module, "v1.0.0");

        var resp = await client.GetAsync($"/go/{module}/@v/list");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string[] lines = (await resp.Content.ReadAsStringAsync())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        Assert.DoesNotContain("v1.0.0", lines);
        Assert.Contains("v1.1.0", lines);
    }

    /// <summary>
    /// The control: with nothing blocked, both versions are listed. Without it, a filter that
    /// dropped everything would satisfy the test above.
    /// </summary>
    [Fact]
    public async Task GoVersionList_WithNothingBlocked_ListsEveryVersion()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await SeedGoVersionAsync(module, "v1.0.0", ageRank: 0);
        await SeedGoVersionAsync(module, "v1.1.0", ageRank: 1);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string[] lines = (await (await client.GetAsync($"/go/{module}/@v/list")).Content.ReadAsStringAsync())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        Assert.Contains("v1.0.0", lines);
        Assert.Contains("v1.1.0", lines);
    }


    /// <summary>
    /// The parity assertion for Go, and the one that exposed a hole the index filter alone would
    /// have hidden: the download gate read only the global cache plane, so a block on a
    /// <c>package_versions</c> row — the plane the management API writes to whenever a PV row
    /// exists — was accepted, displayed as applied, and never enforced. Filtering the index
    /// against that same block without fixing the download would have produced the opposite
    /// asymmetry: a version hidden from `go list` that `go get` still served 200.
    ///
    /// So this asserts both halves against one seeded row: absent from the list, refused by the
    /// download.
    /// </summary>
    [Fact]
    public async Task GoVersionList_BlockedVersion_IsTheSameVersionTheZipDownloadRefuses()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await SeedGoVersionAsync(module, "v1.0.0", ageRank: 0);
        await SeedGoVersionAsync(module, "v1.1.0", ageRank: 1);
        await BlockUploadedVersionAsync("golang", module, "v1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string[] lines = (await (await client.GetAsync($"/go/{module}/@v/list")).Content.ReadAsStringAsync())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.DoesNotContain("v1.0.0", lines);

        Assert.Equal(
            HttpStatusCode.Forbidden,
            (await client.GetAsync($"/go/{module}/@v/v1.0.0.zip")).StatusCode);
    }

    /// <summary>
    /// The other half of parity, and the one that catches over-filtering: a version the index
    /// still advertises must actually download. A filter that hid too much would pass every
    /// "blocked version is absent" assertion while breaking every build.
    /// </summary>
    [Fact]
    public async Task GoVersionList_SurvivingVersion_IsStillDownloadable()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await SeedGoVersionAsync(module, "v1.0.0", ageRank: 0);
        await SeedGoVersionAsync(module, "v1.1.0", ageRank: 1);
        await BlockUploadedVersionAsync("golang", module, "v1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string[] lines = (await (await client.GetAsync($"/go/{module}/@v/list")).Content.ReadAsStringAsync())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Contains("v1.1.0", lines);

        Assert.NotEqual(
            HttpStatusCode.Forbidden,
            (await client.GetAsync($"/go/{module}/@v/v1.1.0.zip")).StatusCode);
    }

    /// <summary>
    /// <c>go get</c> with no version pin resolves through <c>@latest</c>, not <c>@v/list</c>, so
    /// filtering only the list leaves the unpinned path handing clients a version they commit to
    /// and then cannot fetch. The answer falls back to the newest version that is servable rather
    /// than to nothing: an older usable version is something a resolver can act on.
    /// </summary>
    [Fact]
    public async Task GoLatest_WhenTheNewestVersionIsBlocked_FallsBackToTheNewestServableOne()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await SeedGoVersionAsync(module, "v1.0.0", ageRank: 0);
        await SeedGoVersionAsync(module, "v1.1.0", ageRank: 1);
        await BlockUploadedVersionAsync("golang", module, "v1.1.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/{module}/@latest");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();

        Assert.Contains("v1.0.0", body, StringComparison.Ordinal);
        Assert.DoesNotContain("v1.1.0", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control: with nothing blocked, <c>@latest</c> still names the newest version. Without
    /// it, an implementation that always returned the second-newest would pass the test above.
    /// </summary>
    [Fact]
    public async Task GoLatest_WithNothingBlocked_NamesTheNewestVersion()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await SeedGoVersionAsync(module, "v1.0.0", ageRank: 0);
        await SeedGoVersionAsync(module, "v1.1.0", ageRank: 1);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string body = await (await client.GetAsync($"/go/{module}/@latest")).Content.ReadAsStringAsync();
        Assert.Contains("v1.1.0", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every cached version withheld is a 404, not a fall-through to upstream. Proxying onward
    /// would re-propose the very version this org just refused, and answering 200 with a blocked
    /// version would be the original bug.
    /// </summary>
    [Fact]
    public async Task GoLatest_WhenEveryCachedVersionIsBlocked_Is404()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await SeedGoVersionAsync(module, "v1.0.0");
        await BlockUploadedVersionAsync("golang", module, "v1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/go/{module}/@latest")).StatusCode);
    }

    /// <summary>
    /// <c>cargo search</c> reports <c>max_version</c> as the version to install, so it must not
    /// name one the download refuses — the same failure as the sparse index, on the surface a
    /// user reaches first.
    /// </summary>
    [Fact]
    public async Task CargoSearch_MaxVersion_SkipsABlockedVersion()
    {
        string name = $"csrch{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        await PublishCrateAsync(name, "1.0.0");
        await PublishCrateAsync(name, "2.0.0");
        await BlockUploadedVersionAsync("cargo", name, "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string body = await (await client.GetAsync(
            $"/cargo/api/v1/crates?q={name}")).Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(body);
        var crate = doc.RootElement.GetProperty("crates").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);
        Assert.Equal("1.0.0", crate.GetProperty("max_version").GetString());
    }

    // ── Cross-tenant isolation of the block state the index reads ─────────────

    /// <summary>
    /// The index filter reads <c>manual_block_state</c> from <c>tenant_artifact_access</c>, not
    /// from the global <c>cache_artifact</c> row two tenants share. That distinction is the whole
    /// isolation property: get it wrong and one tenant blocking a version disappears it from every
    /// other tenant's index, or — worse in the other direction — one tenant's block is the only
    /// thing standing between another tenant and an artifact it should still be served.
    ///
    /// Asserted against the repository rather than over HTTP because the property is about which
    /// column the row comes from, and a single-tenant HTTP harness cannot express two tenants
    /// holding the same coordinate.
    /// </summary>
    [Fact]
    public async Task BlockState_IsPerTenant_NotSharedThroughTheGlobalCacheRow()
    {
        string orgA = await DefaultOrgIdAsync();
        string orgB = await CreateOrgAsync();
        string name = $"xt{Guid.NewGuid():N}"[..10].ToLowerInvariant();

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        var cacheArtifacts = new CacheArtifactRepository(store);
        var recorder = new CacheAccessRecorder(
            cacheArtifacts, new TenantArtifactAccessRepository(store),
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);

        // Both tenants reach the same coordinate, so they share one global cache_artifact row.
        foreach (string org in new[] { orgA, orgB })
        {
            await recorder.RecordAccessAsync(
                new CacheAccess(org, "cargo", name, "1.0.0", "1.0.0.crate",
                    new string('a', 64), 3, $"proxy/{new string('a', 64)}", UpstreamUrl: null,
                    Origin: CacheAccessOrigin.FirstFetch), default);
        }

        await using (var conn = await store.OpenAsync())
        {
            long distinctArtifacts = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'cargo' AND name = @name",
                new { name });
            // If this were two rows the test would prove nothing about sharing.
            Assert.Equal(1, distinctArtifacts);

            int rows = await conn.ExecuteAsync(
                """
                UPDATE tenant_artifact_access SET manual_block_state = 'blocked'
                WHERE org_id = @orgA AND cache_artifact_id IN (
                    SELECT id FROM cache_artifact WHERE ecosystem = 'cargo' AND name = @name)
                """,
                new { orgA, name });
            Assert.Equal(1, rows);
        }

        var settings = new OrgSettings { AnonymousPull = true };
        var now = DateTimeOffset.UnixEpoch;

        var factsA = await cacheArtifacts.ListServeFactsForNameAsync(orgA, "cargo", name, default);
        var factsB = await cacheArtifacts.ListServeFactsForNameAsync(orgB, "cargo", name, default);

        Assert.True(BlockGateService.IsHardBlockedByCacheEntry(
            Assert.Single(factsA), settings, signals: null, now));
        Assert.False(BlockGateService.IsHardBlockedByCacheEntry(
            Assert.Single(factsB), settings, signals: null, now));
    }

    private async Task<string> CreateOrgAsync()
    {
        string orgId = Guid.NewGuid().ToString();
        string slug = $"org{Guid.NewGuid():N}"[..12].ToLowerInvariant();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@orgId, @slug)", new { orgId, slug });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });
        return orgId;
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task PublishCrateAsync(string name, string version)
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        byte[] crate = System.Text.Encoding.UTF8.GetBytes($"crate-bytes-{name}-{version}");
        string metadata =
            $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"features":{},"description":"parity fixture"}""";

        byte[] metaBytes = System.Text.Encoding.UTF8.GetBytes(metadata);
        var frame = new List<byte>();
        frame.AddRange(BitConverter.GetBytes((uint)metaBytes.Length));
        frame.AddRange(metaBytes);
        frame.AddRange(BitConverter.GetBytes((uint)crate.Length));
        frame.AddRange(crate);

        var content = new ByteArrayContent([.. frame]);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        var resp = await client.PutAsync("/cargo/api/v1/crates/new", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    /// <summary>
    /// Writes a Go module version as a <c>package_versions</c> row with <c>origin='proxy'</c> —
    /// the pre-P3b plane shape, which both the serve path and the version-list query still handle
    /// explicitly. Go has no hosted publish route, so a fixture cannot go through a push path, and
    /// driving a real proxy first fetch would exercise the fetch rather than the index.
    ///
    /// The plane matters: this is the row the management API writes manual_block_state onto
    /// whenever a PV row exists, and it is the plane the download gate used to ignore.
    /// </summary>
    private async Task SeedGoVersionAsync(string module, string version, int ageRank = 0)
    {
        string orgId = await DefaultOrgIdAsync();

        // Stage the actual .zip, so a download reaches the block gate instead of short-circuiting
        // on a cache miss. Without this the parity assertions would read 404 and prove nothing
        // about the gate.
        string blobKey = BlobKeys.Go(orgId, module, version, "zip");
        await _factory.BlobStore.PutAsync(blobKey, new MemoryStream([1, 2, 3]), default);
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string packageId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM packages WHERE org_id = @orgId AND ecosystem = 'golang' AND purl_name = @module",
            new { orgId, module }) ?? Guid.NewGuid().ToString();

        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, created_at)
            VALUES (@packageId, @orgId, 'golang', @module, @module, @now)
            ON CONFLICT (id) DO NOTHING
            """,
            new { packageId, orgId, module, now = DateTimeOffset.UnixEpoch.ToUtcIso() });

        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, origin, created_at)
            VALUES (@id, @packageId, @version, @purl, @blobKey, 10, @sha, 'proxy', @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString(),
                packageId,
                version,
                purl = $"pkg:golang/{module}@{version}",
                blobKey,
                sha = new string('a', 64),
                now = DateTimeOffset.UnixEpoch.AddDays(ageRank).ToUtcIso(),
            });
    }

    private async Task BlockUploadedVersionAsync(string ecosystem, string purlName, string version)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        int rows = await conn.ExecuteAsync(
            """
            UPDATE package_versions SET manual_block_state = 'blocked'
            WHERE version = @version
              AND package_id IN (
                  SELECT id FROM packages
                  WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName)
            """,
            new { orgId, ecosystem, purlName, version });

        // A silent no-op here would make every assertion below pass against an unblocked version,
        // which is the shape of a test that proves nothing.
        Assert.Equal(1, rows);
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }
}
