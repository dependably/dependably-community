using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression tests for P3b increment 3: proxy-first-fetched versions that live only in the
/// global plane (cache_artifact + tenant_artifact_access, no package_versions row) must appear
/// in the management GetPackage detail, npm dist-tags GET, NuGet search, PyPI JSON API, and
/// Cargo search surfaces.
///
/// Each test: seeds a global-plane-only proxy version, then asserts it appears in the named
/// surface. The "before seeding" assertion confirms the version is absent — establishing that
/// the test would have caught the regression on the old code. Per-tenant isolation is verified
/// where applicable via the mixed partial-failure pattern.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxyVersionReadSurfacesTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ProxyVersionReadSurfacesTests(DependablyFactory factory) => _factory = factory;

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

    // Seeds a global-plane proxy entry (cache_artifact + tenant_artifact_access) without
    // creating a package_versions row, matching the real proxy first-fetch write path.
    private async Task<string> SeedGlobalPlaneEntryAsync(
        string orgId, string ecosystem, string name, string version, string filename)
    {
        byte[] fakeBytes = [0x42, 0x43, 0x44, 0x45];
        string sha256 = Convert.ToHexString(SHA256.HashData(fakeBytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);

        await _factory.BlobStore.PutAsync(
            BlobKeys.StoreKey(blobKey), new MemoryStream(fakeBytes), CancellationToken.None);

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        string? caId = await recorder.RecordAccessAsync(new CacheAccess(
            orgId, ecosystem, name, version, filename,
            Sha256: sha256, SizeBytes: fakeBytes.Length,
            BlobKey: $"{blobKey}/{filename}",
            UpstreamUrl: $"https://upstream.example/{filename}"));

        // Real proxy first-fetch also creates the per-tenant packages row.
        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgId, ecosystem, name, name, isProxy: true, CancellationToken.None);

        return caId ?? throw new InvalidOperationException("CacheAccessRecorder did not return an id.");
    }

    // ── Surface 1: management GetPackage detail ────────────────────────────────

    /// <summary>
    /// A proxy-first-fetched version that exists only in the global plane must appear in the
    /// management GetPackage detail response (GET /api/v1/packages/{eco}/{name}) with the
    /// correct per-tenant download_count from tenant_artifact_access.
    ///
    /// Regression: GetPackage called GetVersionsAsync which read only package_versions; a
    /// global-plane-only version was invisible to the management UI.
    ///
    /// Mixed partial-failure: an uploaded version and a proxy version coexist on the same
    /// package name; both must appear in the versions array; the proxy version carries the
    /// download count from tenant_artifact_access, not package_versions.
    /// </summary>
    [Fact]
    public async Task GetPackage_GlobalPlaneProxyVersion_AppearsWithDownloadCount()
    {
        string name = $"gp-mgmt-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string uploadedVersion = "1.0.0";
        string proxyVersion = "2.0.0";
        string filename = $"{name}-{proxyVersion}.tgz";

        // Push an uploaded version so the package row exists.
        await _factory.PushNpmPackage(name, uploadedVersion);

        string defaultOrgId = await GetDefaultOrgIdAsync();

        // Before seeding: management API shows only the uploaded version.
        string jwt = await _factory.CreateAdminJwt();
        using var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        var beforeResp = await adminClient.GetAsync($"/api/v1/packages/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);
        string beforeJson = await beforeResp.Content.ReadAsStringAsync();
        using var beforeDoc = JsonDocument.Parse(beforeJson);
        var beforeVersions = beforeDoc.RootElement.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetProperty("version").GetString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains(uploadedVersion, beforeVersions);
        Assert.DoesNotContain(proxyVersion, beforeVersions);

        // Seed a global-plane entry for the proxy version (no package_versions row).
        string caId = await SeedGlobalPlaneEntryAsync(defaultOrgId, "npm", name, proxyVersion, filename);

        // Simulate a download (increments tenant_artifact_access.download_count).
        var tenantAccess = _factory.Services.GetRequiredService<TenantArtifactAccessRepository>();
        var timeProvider = _factory.Services.GetRequiredService<TimeProvider>();
        await tenantAccess.UpsertStateAsync(defaultOrgId, caId, timeProvider.GetUtcNow());

        // After seeding: both versions appear; proxy version carries download_count = 1.
        var afterResp = await adminClient.GetAsync($"/api/v1/packages/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
        string afterJson = await afterResp.Content.ReadAsStringAsync();
        using var afterDoc = JsonDocument.Parse(afterJson);
        var afterVersionsArr = afterDoc.RootElement.GetProperty("versions").EnumerateArray().ToList();
        var versionStrings = afterVersionsArr
            .Select(v => v.GetProperty("version").GetString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Mixed partial-failure: uploaded version present AND proxy version present.
        Assert.Contains(uploadedVersion, versionStrings);
        Assert.Contains(proxyVersion, versionStrings);

        // Per-tenant download_count: the proxy version's download_count reflects
        // tenant_artifact_access.download_count (incremented to 1 above via UpsertStateAsync,
        // which adds to the existing row; the initial RecordAccessAsync sets access_count=1
        // but download_count starts at 0 there — UpsertStateAsync seeds it to 1).
        var proxyEntry = afterVersionsArr.First(v =>
            string.Equals(v.GetProperty("version").GetString(), proxyVersion, StringComparison.OrdinalIgnoreCase));
        long downloadCount = proxyEntry.GetProperty("downloadCount").GetInt64();
        Assert.True(downloadCount >= 1,
            $"Proxy version download_count should be >= 1 (got {downloadCount}).");

        // Size comes from cache_artifact.size_bytes for global-plane proxy versions (there is no
        // package_versions row to read it from). The seeded artifact is 4 bytes; a 0 here means
        // the serve-fact projection dropped size_bytes and the UI renders a bogus "0 B".
        Assert.Equal(4, proxyEntry.GetProperty("sizeBytes").GetInt64());

        // Uploaded version's download_count comes from package_versions (should still be 0).
        var uploadedEntry = afterVersionsArr.First(v =>
            string.Equals(v.GetProperty("version").GetString(), uploadedVersion, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, uploadedEntry.GetProperty("downloadCount").GetInt64());
    }

    // ── Surface 2: npm dist-tags latest ───────────────────────────────────────

    /// <summary>
    /// When the newest version of an npm package is a global-plane proxy entry (no
    /// package_versions row), the dist-tags GET endpoint must return it as 'latest'.
    ///
    /// Regression: GetDistTagsImplAsync fell back to GetVersionsAsync (package_versions only)
    /// when no persisted tags exist; a global-plane-only newer version was missed, so 'latest'
    /// pointed at an older uploaded version.
    ///
    /// Mixed partial-failure: an uploaded 1.0.0 and a proxy 3.0.0 coexist; 'latest' should
    /// resolve to 3.0.0 (the newer one from the global plane). Before seeding 3.0.0 it
    /// resolves to 1.0.0 via the lazy-latest computation. After seeding it resolves to 3.0.0.
    /// </summary>
    [Fact]
    public async Task NpmDistTags_GlobalPlaneProxyVersion_AppearsAsLatestWhenNewest()
    {
        string name = $"gp-dist-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string uploadedVersion = "1.0.0";
        string newerProxyVersion = "3.0.0";
        string filename = $"{name}-{newerProxyVersion}.tgz";

        // Push an older uploaded version so a packages row exists.
        await _factory.PushNpmPackage(name, uploadedVersion);

        string defaultOrgId = await GetDefaultOrgIdAsync();
        var pkgRepo = _factory.Services.GetRequiredService<PackageRepository>();
        var distTagRepo = _factory.Services.GetRequiredService<NpmDistTagRepository>();

        // npm publish sets an explicit 'latest' tag; remove it so the lazy-latest
        // computation runs in GetDistTagsImplAsync (tags.Count == 0 path).
        var pkg = await pkgRepo.GetByPurlNameAsync(defaultOrgId, "npm", name, CancellationToken.None);
        Assert.NotNull(pkg);
        await distTagRepo.DeleteTagAsync(defaultOrgId, pkg.Id, "latest", CancellationToken.None);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Before seeding: lazy-latest computes latest from uploaded versions only.
        var beforeResp = await client.GetAsync($"/npm/-/package/{name}/dist-tags");
        Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);
        string beforeJson = await beforeResp.Content.ReadAsStringAsync();
        using var beforeDoc = JsonDocument.Parse(beforeJson);
        string? latestBefore = beforeDoc.RootElement.TryGetProperty("latest", out var bv)
            ? bv.GetString() : null;
        Assert.Equal(uploadedVersion, latestBefore);

        // Seed a global-plane proxy entry for the newer version (seeded after push
        // so first_cached_at > uploaded version's created_at).
        await SeedGlobalPlaneEntryAsync(defaultOrgId, "npm", name, newerProxyVersion, filename);

        // After seeding: lazy-latest across combined versions must resolve to the proxy version.
        var afterResp = await client.GetAsync($"/npm/-/package/{name}/dist-tags");
        Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
        string afterJson = await afterResp.Content.ReadAsStringAsync();
        using var afterDoc = JsonDocument.Parse(afterJson);
        string? latestAfter = afterDoc.RootElement.TryGetProperty("latest", out var av)
            ? av.GetString() : null;
        Assert.Equal(newerProxyVersion, latestAfter);
    }

    // ── Surface 3: NuGet search ────────────────────────────────────────────────

    /// <summary>
    /// A NuGet package that has only a global-plane proxy version (no package_versions row)
    /// must appear in NuGet search results with the correct latest version string.
    ///
    /// Regression: NuGetSearchHandler.SearchAsync called GetVersionsAsync per package,
    /// which read only package_versions; a proxy-only package had no versions and was
    /// silently excluded from results.
    ///
    /// Mixed partial-failure: a package with both an uploaded version and a global-plane proxy
    /// version must show the newer proxy version as the 'version' field in search results.
    /// </summary>
    [Fact]
    public async Task NuGetSearch_GlobalPlaneProxyVersion_AppearsInSearchResults()
    {
        // Disable proxy passthrough so the search uses only local-plane data.
        string defaultOrgId = await GetDefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            string id = $"gpsearch{Guid.NewGuid():N}"[..14].ToLowerInvariant();
            string uploadedVersion = "1.0.0";
            string proxyVersion = "5.0.0";
            string proxyFilename = $"{id}.{proxyVersion}.nupkg";

            // Push an uploaded version.
            await _factory.PushNuGetPackage(id, uploadedVersion);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Before seeding the proxy version: search shows uploaded version as latest.
            var beforeResp = await client.GetAsync($"/nuget/query?q={id}&take=10");
            Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);
            string beforeJson = await beforeResp.Content.ReadAsStringAsync();
            using var beforeDoc = JsonDocument.Parse(beforeJson);
            var beforeResults = beforeDoc.RootElement.GetProperty("data").EnumerateArray().ToList();
            var beforePackage = beforeResults.FirstOrDefault(r =>
                string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));
            Assert.True(beforePackage.ValueKind != JsonValueKind.Undefined,
                "Package should appear in search after push.");
            Assert.Equal(uploadedVersion, beforePackage.GetProperty("version").GetString());

            // Seed a global-plane proxy entry for a newer version.
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "nuget", id, proxyVersion, proxyFilename);

            // Evict registration cache so the renderer picks up the new version.
            _factory.Services.GetRequiredService<RenderedResponseCache<NuGetRegistrationKey>>()
                .Evict(new NuGetRegistrationKey(defaultOrgId, id, false));

            // After seeding: search shows the newer proxy version as 'version'.
            var afterResp = await client.GetAsync($"/nuget/query?q={id}&take=10");
            Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
            string afterJson = await afterResp.Content.ReadAsStringAsync();
            using var afterDoc = JsonDocument.Parse(afterJson);
            var afterResults = afterDoc.RootElement.GetProperty("data").EnumerateArray().ToList();
            var afterPackage = afterResults.FirstOrDefault(r =>
                string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));
            Assert.True(afterPackage.ValueKind != JsonValueKind.Undefined,
                "Package should still appear in search after seeding proxy version.");

            // Mixed partial-failure: both versions are present in the versions array.
            var allVersions = afterPackage.GetProperty("versions").EnumerateArray()
                .Select(v => v.GetProperty("version").GetString())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.Contains(uploadedVersion, allVersions);
            Assert.Contains(proxyVersion, allVersions);

            // The 'version' field reflects the latest (most recently created) version.
            // The proxy version was seeded after the uploaded one, so it should be latest.
            Assert.Equal(proxyVersion, afterPackage.GetProperty("version").GetString());
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── Surface 4: PyPI JSON API ───────────────────────────────────────────────

    /// <summary>
    /// A PyPI package that has only a global-plane proxy version (no package_versions row)
    /// must appear in the PyPI JSON API response (GET /pypi/{package}/json) in the
    /// 'releases' map.
    ///
    /// Regression: PyPiJsonApiHandler checked only origin='uploaded' versions; a global-plane
    /// proxy version was treated as "no local versions" and the handler fell through to the
    /// upstream proxy path (or NotFound when passthrough is disabled).
    ///
    /// Mixed partial-failure: an uploaded 1.0.0 and a proxy 4.0.0 coexist; both must appear
    /// in the releases map. Before seeding 4.0.0 only 1.0.0 is present; after seeding both
    /// appear.
    /// </summary>
    [Fact]
    public async Task PyPiJsonApi_GlobalPlaneProxyVersion_AppearsInReleasesMap()
    {
        // Disable proxy passthrough so the handler takes the local-only code path.
        string defaultOrgId = await GetDefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            string name = $"gp-json-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            string uploadedVersion = "1.0.0";
            string proxyVersion = "4.0.0";
            string underscored = name.Replace('-', '_');
            string proxyFilename = $"{underscored}-{proxyVersion}-py3-none-any.whl";

            // Push an uploaded version so the packages row exists.
            await _factory.PushPyPiPackage(name, uploadedVersion);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Before seeding: JSON API shows only the uploaded version.
            var beforeResp = await client.GetAsync($"/pypi/{name}/json");
            Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);
            string beforeJson = await beforeResp.Content.ReadAsStringAsync();
            using var beforeDoc = JsonDocument.Parse(beforeJson);
            var beforeReleases = beforeDoc.RootElement.GetProperty("releases").EnumerateObject()
                .Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.Contains(uploadedVersion, beforeReleases);
            Assert.DoesNotContain(proxyVersion, beforeReleases);

            // Seed a global-plane proxy entry.
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "pypi", name, proxyVersion, proxyFilename);

            // After seeding: both versions appear in releases.
            var afterResp = await client.GetAsync($"/pypi/{name}/json");
            Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
            string afterJson = await afterResp.Content.ReadAsStringAsync();
            using var afterDoc = JsonDocument.Parse(afterJson);
            var afterReleases = afterDoc.RootElement.GetProperty("releases").EnumerateObject()
                .Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Mixed partial-failure: uploaded + proxy version both present.
            Assert.Contains(uploadedVersion, afterReleases);
            Assert.Contains(proxyVersion, afterReleases);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── Surface 5: Cargo search max_version ───────────────────────────────────

    /// <summary>
    /// The Cargo search endpoint (GET /cargo/api/v1/crates) must surface the correct
    /// max_version for a crate that has a global-plane proxy version newer than any
    /// uploaded version.
    ///
    /// Regression: ResolveMaxVersionAsync called GetVersionsAsync (package_versions only);
    /// a global-plane-only newer version was not considered, so max_version pointed at the
    /// older uploaded version.
    ///
    /// Mixed partial-failure: an uploaded 0.1.0 and a proxy 9.0.0 coexist; max_version
    /// before seeding is 0.1.0 (uploaded); after seeding 9.0.0 it should be 9.0.0.
    /// </summary>
    [Fact]
    public async Task CargoSearch_GlobalPlaneProxyVersion_ReflectedInMaxVersion()
    {
        // Disable proxy passthrough so the search uses only local-plane data.
        string defaultOrgId = await GetDefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            string name = $"gp-cargo-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            string uploadedVersion = "0.1.0";
            string newerProxyVersion = "9.0.0";
            string proxyFilename = $"{name}-{newerProxyVersion}.crate";

            // Publish an uploaded Cargo crate so the package row exists.
            string token = await _factory.CreateToken("push");
            using var pushClient = _factory.CreateClientWithBearer(token);
            byte[] crateBytes = [0x50, 0x4B, 0x03, 0x04];
            string metaJson = $"{{\"name\":\"{name}\",\"vers\":\"{uploadedVersion}\",\"deps\":[],\"features\":{{}},\"description\":\"test\"}}";
            byte[] metaEncoded = System.Text.Encoding.UTF8.GetBytes(metaJson);
            byte[] frame = new byte[4 + metaEncoded.Length + 4 + crateBytes.Length];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)metaEncoded.Length);
            metaEncoded.CopyTo(frame, 4);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
                frame.AsSpan(4 + metaEncoded.Length), (uint)crateBytes.Length);
            crateBytes.CopyTo(frame, 4 + metaEncoded.Length + 4);
            var pushContent = new ByteArrayContent(frame);
            pushContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            var pushResp = await pushClient.PutAsync("/cargo/api/v1/crates/new", pushContent);
            Assert.Equal(HttpStatusCode.OK, pushResp.StatusCode);

            string pullToken = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(pullToken);

            // Before seeding: search shows uploaded version as max_version.
            var beforeResp = await client.GetAsync($"/cargo/api/v1/crates?q={name}&per_page=5");
            Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);
            string beforeJson = await beforeResp.Content.ReadAsStringAsync();
            using var beforeDoc = JsonDocument.Parse(beforeJson);
            var beforeCrates = beforeDoc.RootElement.GetProperty("crates").EnumerateArray().ToList();
            var beforeCrate = beforeCrates.FirstOrDefault(c =>
                string.Equals(c.GetProperty("name").GetString(), name, StringComparison.OrdinalIgnoreCase));
            Assert.True(beforeCrate.ValueKind != JsonValueKind.Undefined,
                "Crate should appear in search after publish.");
            Assert.Equal(uploadedVersion, beforeCrate.GetProperty("max_version").GetString());

            // Seed a global-plane proxy entry for the newer version.
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "cargo", name, newerProxyVersion, proxyFilename);

            // After seeding: max_version should be the newer proxy version.
            var afterResp = await client.GetAsync($"/cargo/api/v1/crates?q={name}&per_page=5");
            Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
            string afterJson = await afterResp.Content.ReadAsStringAsync();
            using var afterDoc = JsonDocument.Parse(afterJson);
            var afterCrates = afterDoc.RootElement.GetProperty("crates").EnumerateArray().ToList();
            var afterCrate = afterCrates.FirstOrDefault(c =>
                string.Equals(c.GetProperty("name").GetString(), name, StringComparison.OrdinalIgnoreCase));
            Assert.True(afterCrate.ValueKind != JsonValueKind.Undefined,
                "Crate should still appear in search after seeding proxy version.");

            // Mixed partial-failure: max_version now reflects the newer global-plane proxy version.
            Assert.Equal(newerProxyVersion, afterCrate.GetProperty("max_version").GetString());
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── Surface 6: per-tenant isolation (GetPackage) ───────────────────────────

    /// <summary>
    /// GetPackage must not leak global-plane proxy versions from one tenant into another
    /// tenant's version list. Only versions accessible to the requesting tenant
    /// (via tenant_artifact_access) should appear.
    ///
    /// Mixed partial-failure: tenant A's proxy version appears for A, is absent for B;
    /// after B records access it appears for B too.
    /// </summary>
    [Fact]
    public async Task GetPackage_GlobalPlaneIsolation_VersionAbsentForOtherTenant()
    {
        string name = $"gp-isol-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string proxyVersion = "7.0.0";
        string filename = $"{name}-{proxyVersion}.tgz";

        string defaultOrgId = await GetDefaultOrgIdAsync();

        // Create tenant B.
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var orgB = await orgRepo.CreateOrgAsync($"gpiso-{Guid.NewGuid():N}"[..20]);

        // Ensure tenant B has org_settings.
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@orgId) ON CONFLICT DO NOTHING",
            new { orgId = orgB.Id });

        // Seed proxy entry only for tenant A.
        await SeedGlobalPlaneEntryAsync(defaultOrgId, "npm", name, proxyVersion, filename);

        // Tenant A: GetPackage shows the proxy version.
        string jwtA = await _factory.CreateAdminJwt();
        using var clientA = _factory.CreateClient();
        clientA.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtA);
        var respA = await clientA.GetAsync($"/api/v1/packages/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, respA.StatusCode);
        string jsonA = await respA.Content.ReadAsStringAsync();
        using var docA = JsonDocument.Parse(jsonA);
        var versionsA = docA.RootElement.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetProperty("version").GetString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains(proxyVersion, versionsA);

        // Tenant B: the cache_artifact row exists globally, but B has no
        // tenant_artifact_access row — so B's GetPackage should not show it.
        long bAccessCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'npm' AND ca.name = @name
            """,
            new { orgId = orgB.Id, name });
        Assert.Equal(0, bAccessCount);

        // Tenant B has no packages row for this name in their org → GetPackage returns 404.
        // (The per-tenant packages row is only created for the org that made the first fetch.)
        var cacheRepo = _factory.Services.GetRequiredService<CacheArtifactRepository>();
        var forB = await cacheRepo.ListServeFactsForNameAsync(orgB.Id, "npm", name);
        Assert.Empty(forB);
    }

    // ── Surface 7: GetPackage version status reflects proxy advisories ──────────

    /// <summary>
    /// A global-plane proxy version with a linked advisory must report a vulnerable serving
    /// status — not "clean"/No advisories. The synthetic PackageVersion built from
    /// CacheArtifactIndexFacts must carry HasAdvisory so ComputeVersionStatus does not fall
    /// through to "clean".
    ///
    /// Regression: ToPackageVersionSynthetic never set HasAdvisory, so a proxy version carrying
    /// CRITICAL advisories rendered Status = "clean" (No advisories) while the vuln list below
    /// it showed the advisories.
    /// </summary>
    [Fact]
    public async Task GetPackage_GlobalPlaneProxyVersionWithAdvisory_StatusIsVulnerableNotClean()
    {
        string name = $"gp-adv-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string proxyVersion = "1.2.12";
        string filename = $"{name}-{proxyVersion}.jar";

        string defaultOrgId = await GetDefaultOrgIdAsync();

        // Seed a global-plane proxy version (no package_versions row).
        string caId = await SeedGlobalPlaneEntryAsync(defaultOrgId, "maven", name, proxyVersion, filename);

        // Link a scored advisory (9.8, below the default 10.0 tolerance → vulnerable, not blocked)
        // and stamp vuln_checked_at so the status gate doesn't short-circuit to "unscanned".
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            db, $"GHSA-{Guid.NewGuid():N}"[..14], ecosystem: "maven", packageName: name,
            severity: "CRITICAL", cvssScore: 9.8);
        await VulnerabilitySeeder.LinkToCacheArtifactAsync(db, caId, vulnId);
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE cache_artifact SET vuln_checked_at = '2026-06-20T00:00:00Z' WHERE id = @caId",
                new { caId });
        }

        string jwt = await _factory.CreateAdminJwt();
        using var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        var resp = await adminClient.GetAsync($"/api/v1/packages/maven/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("versions").EnumerateArray()
            .First(v => string.Equals(v.GetProperty("version").GetString(), proxyVersion, StringComparison.OrdinalIgnoreCase));

        Assert.Equal("vulnerable", entry.GetProperty("status").GetString());
    }

    // ── Surface 8: GetPackage projects upstream integrity for proxy versions ────

    /// <summary>
    /// A global-plane proxy version must surface its upstream-declared integrity digest
    /// (cache_artifact.upstream_integrity_value / _algorithm) in the GetPackage detail, so the
    /// detail panel's SRI integrity row renders for non-npm proxy artifacts too.
    ///
    /// Regression: ToPackageVersionSynthetic never projected the integrity columns, so the
    /// integrity row was absent for every proxy version (npm fell back to the sha1 shasum;
    /// pypi/maven/nuget showed nothing).
    /// </summary>
    [Fact]
    public async Task GetPackage_GlobalPlaneProxyVersion_ProjectsUpstreamIntegrity()
    {
        string name = $"gp-intg-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string proxyVersion = "2.5.0";
        string filename = $"{name}-{proxyVersion}-py3-none-any.whl";

        string defaultOrgId = await GetDefaultOrgIdAsync();
        string caId = await SeedGlobalPlaneEntryAsync(defaultOrgId, "pypi", name, proxyVersion, filename);

        const string integrityValue = "sha256-3q2+7w==";
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                UPDATE cache_artifact
                SET upstream_integrity_value = @integrityValue, upstream_integrity_algorithm = 'sha256'
                WHERE id = @caId
                """,
                new { integrityValue, caId });
        }

        string jwt = await _factory.CreateAdminJwt();
        using var adminClient = _factory.CreateClient();
        adminClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        var resp = await adminClient.GetAsync($"/api/v1/packages/pypi/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("versions").EnumerateArray()
            .First(v => string.Equals(v.GetProperty("version").GetString(), proxyVersion, StringComparison.OrdinalIgnoreCase));

        Assert.Equal(integrityValue, entry.GetProperty("upstreamIntegrityValue").GetString());
        Assert.Equal("sha256", entry.GetProperty("upstreamIntegrityAlgorithm").GetString());
    }
}

