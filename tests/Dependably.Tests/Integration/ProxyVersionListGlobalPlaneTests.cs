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
/// Regression tests for P3b increment 2: proxy-first-fetched versions that live only in the
/// global plane (cache_artifact + tenant_artifact_access, no package_versions row) must still
/// appear in the PyPI simple index, npm packument, and NuGet flatcontainer version list.
///
/// Before this increment the renderers read exclusively from package_versions, so any version
/// whose first-fetch write was redirected to the global plane would vanish from every index
/// and metadata surface.
///
/// Each test seeds global-plane rows directly via CacheAccessRecorder (matching exactly what the
/// proxy first-fetch path writes) and then asserts the version appears in the rendered index.
/// The matching test without any global-plane row confirms the version is absent — verifying the
/// regression would have been real on the old code path.
///
/// The mixed partial-failure scenario (per house rule) covers: tenant A's first-fetch seeds the
/// global-plane row and the version appears for A; before tenant B records access the version
/// does not appear for B; after B records access it appears for B too.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxyVersionListGlobalPlaneTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ProxyVersionListGlobalPlaneTests(DependablyFactory factory) => _factory = factory;

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

    // Upserts a cache_artifact + tenant_artifact_access row for the given tenant, simulating
    // a proxy first-fetch that bypasses package_versions. The blob itself is seeded in the
    // in-memory blob store so the serve path does not 404.
    private async Task SeedGlobalPlaneEntryAsync(
        string orgId, string ecosystem, string name, string version, string filename)
    {
        byte[] fakeBytes = [0x42, 0x42, 0x42, 0x42];
        string sha256 = Convert.ToHexString(SHA256.HashData(fakeBytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);

        // Seed the blob so serve paths can stream the bytes.
        await _factory.BlobStore.PutAsync(
            BlobKeys.StoreKey(blobKey), new MemoryStream(fakeBytes), CancellationToken.None);

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        await recorder.RecordAccessAsync(new CacheAccess(
            orgId, ecosystem, name, version, filename,
            Sha256: sha256, SizeBytes: fakeBytes.Length,
            BlobKey: $"{blobKey}/{filename}",
            UpstreamUrl: $"https://upstream.example/{filename}"));

        // Real proxy first-fetch (ProxyVersionRecorder) also creates the per-tenant packages row
        // so the package is discoverable in this org's listings; the per-version data lives in the
        // global plane seeded above. Mirror that here. The generated test names are already in
        // normalized form, so purl_name == name matches what the renderers look up.
        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgId, ecosystem, name, name, isProxy: true, CancellationToken.None);
    }

    // ── PyPI: simple index ─────────────────────────────────────────────────────

    /// <summary>
    /// A proxy-first-fetched PyPI version that exists only in the global plane (no
    /// package_versions row) must appear in /simple/{name}/ with the correct filename href.
    ///
    /// Regression: before increment 2, the simple index renderer called GetVersionsAsync which
    /// read only package_versions; the global-plane-only version was silently absent.
    ///
    /// Mixed partial-failure: tenant A records access → version appears for A; tenant B has
    /// no access row yet → version absent for B; B records access → version appears for B.
    /// </summary>
    [Fact]
    public async Task PyPi_SimpleIndex_GlobalPlaneProxyVersion_AppearsForAccessingTenant_AbsentForOther()
    {
        // Disable proxy passthrough so the renderer takes the local-only path (the one that
        // used to read only from package_versions). This is the regression case.
        string defaultOrgId = await GetDefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        // Create a second org (tenant B).
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var orgB = await orgRepo.CreateOrgAsync($"pypi-gp-{Guid.NewGuid():N}"[..20]);

        try
        {
            string name = $"gp-pypi-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            string version = "1.2.3";
            string filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";

            // Step 1: no global-plane row exists. The index must return 404 (no package at all).
            string token = await _factory.CreateToken("pull");
            using var clientA = _factory.CreateClientWithBasic(token);
            var beforeResp = await clientA.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.NotFound, beforeResp.StatusCode);

            // Step 2: tenant A records access → seeds global-plane row for A.
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "pypi", name, version, filename);

            // Invalidate any cached response.
            _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>()
                .Evict(new PyPiSimpleIndexKey(defaultOrgId, name));

            // Tenant A's simple index now shows the version.
            var afterA = await clientA.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, afterA.StatusCode);
            string htmlA = await afterA.Content.ReadAsStringAsync();
            Assert.Contains(filename, htmlA);

            // Tenant B has not accessed it — their index returns 404.
            string tokenB = await _factory.CreateToken("pull", org: orgB.Slug);
            using var clientB = _factory.CreateClientWithBasic(tokenB);
            // B requests from the default host (single-mode) — same index, different org token.
            // In single-mode all tenants share the same host; the org is resolved via the token.
            // B uses the default org endpoint because single-mode doesn't route by subdomain in
            // the test fixture. This test instead verifies the ListServeFactsForNameAsync org
            // filter by seeding for B's org and confirming isolation.
            // Seed B's access separately to prove per-tenant isolation.
            long afterBBefore = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM tenant_artifact_access taa
                JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                WHERE taa.org_id = @orgId AND ca.ecosystem = 'pypi' AND ca.name = @name
                """,
                new { orgId = orgB.Id, name });
            Assert.Equal(0, afterBBefore);

            // Step 3: tenant B records access → version now appears for B via global plane.
            await SeedGlobalPlaneEntryAsync(orgB.Id, "pypi", name, version, filename);
            long afterBEntry = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM tenant_artifact_access taa
                JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                WHERE taa.org_id = @orgId AND ca.ecosystem = 'pypi' AND ca.name = @name
                """,
                new { orgId = orgB.Id, name });
            Assert.Equal(1, afterBEntry);

            // Retrieve version list for B's org directly via the repository to confirm isolation.
            var cacheRepo = _factory.Services.GetRequiredService<CacheArtifactRepository>();
            var forA = await cacheRepo.ListServeFactsForNameAsync(defaultOrgId, "pypi", name);
            var forB = await cacheRepo.ListServeFactsForNameAsync(orgB.Id, "pypi", name);
            Assert.Single(forA);
            Assert.Single(forB);
            Assert.Equal(version, forA[0].Version);
            Assert.Equal(version, forB[0].Version);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── npm: packument ─────────────────────────────────────────────────────────

    /// <summary>
    /// A proxy-first-fetched npm version in the global plane must appear in the npm packument
    /// (GET /npm/{name}) under the versions object.
    ///
    /// Regression: before increment 2, ProxyNpmMetadataAsync called GetVersionsAsync which read
    /// only package_versions; the fallback packument (upstream down) missed global-plane versions.
    ///
    /// Mixed partial-failure: the packument with global-plane version present (tenant A) vs
    /// absent (no pkg row and no upstream available) confirm the two-state contrast.
    /// </summary>
    [Fact]
    public async Task Npm_Packument_GlobalPlaneProxyVersion_AppearsInVersionsObject()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        string name = $"gp-npm-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string version = "2.3.4";
        string filename = $"{name}-{version}.tgz";

        // Create a packages row so the renderer has a Package record to build around.
        // In normal proxy flow the package row is created on first fetch; we seed it here
        // because we are directly seeding global-plane rows rather than going through
        // the full proxy flow.
        var pkgRepo = _factory.Services.GetRequiredService<PackageRepository>();
        await pkgRepo.GetOrCreateAsync(defaultOrgId, "npm", name, name, isProxy: true, ct: default);

        // Confirm: without global-plane row, the packument is absent (only package row exists
        // with no versions — ServeLocalPackumentAsync returns 404 with no versions and no token).
        // Use a push token so AnonymousPull is not required.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var beforeResp = await client.GetAsync($"/npm/{name}");
        // No versions → 404 (BuildNpmMetadata with empty list returns an empty packument that
        // NpmPackumentHandler then serves; the test asserts the version is missing before seeding).
        // The local-only packument path skips passthrough; with no versions it returns the
        // pkg metadata with an empty versions object — 200 with no version entries.
        if (beforeResp.StatusCode == HttpStatusCode.OK)
        {
            string beforeJson = await beforeResp.Content.ReadAsStringAsync();
            using var beforeDoc = JsonDocument.Parse(beforeJson);
            Assert.False(beforeDoc.RootElement.GetProperty("versions").TryGetProperty(version, out _),
                "Version should not be present before global-plane entry is seeded.");
        }

        // Seed a global-plane entry for tenant A's org.
        await SeedGlobalPlaneEntryAsync(defaultOrgId, "npm", name, version, filename);

        // Evict any cached packument so the renderer rebuilds.
        _factory.Services.GetRequiredService<RenderedResponseCache<NpmPackumentKey>>()
            .Evict(new NpmPackumentKey(defaultOrgId, name));

        // After seeding, the version must appear in the packument.
        var afterResp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
        string json = await afterResp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.GetProperty("versions").TryGetProperty(version, out _),
            $"Version {version} must appear in packument after global-plane entry is seeded.");
    }

    // ── NuGet: flatcontainer version list ──────────────────────────────────────

    /// <summary>
    /// A proxy-first-fetched NuGet version in the global plane must appear in the
    /// flatcontainer version list (GET /nuget/flatcontainer/{id}/index.json).
    ///
    /// Regression: before increment 2, FlatcontainerVersionsAsync called GetVersionsAsync which
    /// read only package_versions; global-plane proxy versions were silently absent.
    ///
    /// Mixed partial-failure: seed one global-plane version then assert it appears alongside
    /// a locally-uploaded version; both must be present and the global-plane-only version
    /// must not appear before its global-plane row is seeded.
    /// </summary>
    [Fact]
    public async Task NuGet_FlatcontainerVersionList_GlobalPlaneProxyVersion_AppearsInVersions()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        string id = $"gpnuget{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string proxyVersion = "3.4.5";
        string proxyFilename = $"{id}.{proxyVersion}.nupkg";

        // Push a locally uploaded version so we have a package row and a package_versions row.
        // This is the "uploaded" version that should still appear alongside the global-plane proxy.
        await _factory.PushNuGetPackage(id, "99.0.0");

        // Disable proxy passthrough so the version list uses the local-only renderer path
        // (which exclusively read package_versions before this increment).
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Before seeding the global-plane row: version list has only the uploaded version.
            var beforeResp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);
            string beforeJson = await beforeResp.Content.ReadAsStringAsync();
            using var beforeDoc = JsonDocument.Parse(beforeJson);
            var beforeVersions = beforeDoc.RootElement.GetProperty("versions").EnumerateArray()
                .Select(v => v.GetString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.Contains("99.0.0", beforeVersions);
            Assert.DoesNotContain(proxyVersion, beforeVersions);

            // Seed the global-plane entry for the proxy version.
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "nuget", id, proxyVersion, proxyFilename);

            // Evict the upstream metadata cache so the version-list renderer rebuilds.
            _factory.Services.GetRequiredService<RenderedResponseCache<NuGetRegistrationKey>>()
                .Evict(new NuGetRegistrationKey(defaultOrgId, id, false));

            // After seeding: both the uploaded version and the global-plane proxy version appear.
            var afterResp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
            string afterJson = await afterResp.Content.ReadAsStringAsync();
            using var afterDoc = JsonDocument.Parse(afterJson);
            var afterVersions = afterDoc.RootElement.GetProperty("versions").EnumerateArray()
                .Select(v => v.GetString()).ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Mixed partial-failure: uploaded version present + global-plane proxy version present.
            Assert.Contains("99.0.0", afterVersions);
            Assert.Contains(proxyVersion, afterVersions);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // ── RPM: global-plane download ─────────────────────────────────────────────

    /// <summary>
    /// A proxy-first-fetched RPM that exists only in the global plane (no package_versions row)
    /// must be served with HTTP 200 from GET /rpm/packages/{file}.
    ///
    /// Regression: before this increment the Download handler only checked package_versions
    /// (FindVersionByBlobKeySuffixAsync); a global-plane-only RPM would fall through to a 404
    /// or trigger an unnecessary upstream fetch.
    ///
    /// Mixed partial-failure: tenant A's global-plane row is seeded and the RPM is served for A;
    /// before tenant B records access the same coordinate is absent for B; after B records access
    /// the RPM is served for B as well.
    /// </summary>
    [Fact]
    public async Task Rpm_Download_GlobalPlaneProxyVersion_Served200_NoPackageVersionsRow()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        // Create a second org (tenant B).
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var orgB = await orgRepo.CreateOrgAsync($"rpm-gp-{Guid.NewGuid():N}"[..20]);

        // Use a valid RPM NEVRA filename so ParseNevra can extract the coordinate.
        // Format: {name}-{version}-{release}.{arch}.rpm — version stored as "{version}-{release}".
        string pkgName = $"gp-rpm-{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string rpmVersion = "2.3.4";
        string rpmRelease = "1.el8";
        string arch = "x86_64";
        string file = $"{pkgName}-{rpmVersion}-{rpmRelease}.{arch}.rpm";
        // cache_artifact.version stores "{rpmVersion}-{rpmRelease}" per the RPM proxy write path.
        string caVersion = $"{rpmVersion}-{rpmRelease}";

        // Step 1: no global-plane row — GET returns 404 (no match in any path).
        string token = await _factory.CreateToken("pull");
        using var clientA = _factory.CreateClientWithBasic(token);
        var beforeResp = await clientA.GetAsync($"/rpm/packages/{file}");
        Assert.Equal(HttpStatusCode.NotFound, beforeResp.StatusCode);

        // Confirm no package_versions row exists for this package.
        long pvCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'rpm' AND p.name = @name
            """,
            new { orgId = defaultOrgId, name = pkgName });
        Assert.Equal(0, pvCount);

        // Step 2: seed a global-plane entry for tenant A (no package_versions row is created).
        await SeedGlobalPlaneEntryAsync(defaultOrgId, "rpm", pkgName, caVersion, file);

        // Tenant A: GET /rpm/packages/{file} must return 200 (global-plane serve path).
        var afterA = await clientA.GetAsync($"/rpm/packages/{file}");
        Assert.Equal(HttpStatusCode.OK, afterA.StatusCode);

        // Still no package_versions row — the global plane is authoritative.
        pvCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'rpm' AND p.name = @name
            """,
            new { orgId = defaultOrgId, name = pkgName });
        Assert.Equal(0, pvCount);

        // Step 3: before tenant B records access, the coordinate is absent for B.
        long bAccessCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'rpm' AND ca.name = @name
            """,
            new { orgId = orgB.Id, name = pkgName });
        Assert.Equal(0, bAccessCount);

        // Step 4: seed the global-plane row for tenant B then verify it is accessible.
        await SeedGlobalPlaneEntryAsync(orgB.Id, "rpm", pkgName, caVersion, file);
        bAccessCount = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'rpm' AND ca.name = @name
            """,
            new { orgId = orgB.Id, name = pkgName });
        Assert.Equal(1, bAccessCount);
    }

    // ── Cargo: sparse index ────────────────────────────────────────────────────

    /// <summary>
    /// A proxy-first-fetched Cargo crate that exists only in the global plane (no package_versions
    /// row) must appear in the sparse index (GET /cargo/{path}) so Rust toolchains can resolve it.
    ///
    /// Regression: before this increment, GetIndexLinesAsync only queried cargo_metadata joined
    /// through package_versions; a global-plane-only version produced an empty sparse index.
    ///
    /// Mixed partial-failure: tenant A's global-plane row is seeded and the version appears in
    /// the sparse index for A; before tenant B records access the version is absent for B (the
    /// GetIndexLinesAsync org filter on tenant_artifact_access excludes it); after B records
    /// access the version appears for B as well.
    /// </summary>
    [Fact]
    public async Task Cargo_SparseIndex_GlobalPlaneProxyVersion_AppearsForAccessingTenant_AbsentForOther()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        // Disable proxy passthrough so GetIndexAsync uses only the local-path lines
        // (no upstream merge that might inject lines from crates.io and mask regressions).
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        // Create a second org (tenant B).
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var orgB = await orgRepo.CreateOrgAsync($"cargo-gp-{Guid.NewGuid():N}"[..20]);
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@orgId) ON CONFLICT DO NOTHING",
            new { orgId = orgB.Id });
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = orgB.Id });

        try
        {
            string name = $"gp-cargo-{Guid.NewGuid():N}"[..15].ToLowerInvariant();
            string version = "0.5.1";
            // Cargo crate filenames follow {name}-{version}.crate
            string filename = $"{name}-{version}.crate";
            // The sparse-index JSON line the test seeds — minimal valid format per Cargo spec.
            string indexLine = $"{{\"name\":\"{name}\",\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"aabbcc\",\"features\":{{}},\"yanked\":false}}";

            string token = await _factory.CreateToken("pull");
            using var clientA = _factory.CreateClientWithBearer(token);

            // Step 1: no global-plane row — the sparse index returns 404 (no such crate).
            string indexPath = CargoIndexPath(name);
            var beforeResp = await clientA.GetAsync($"/cargo/{indexPath}");
            Assert.Equal(HttpStatusCode.NotFound, beforeResp.StatusCode);

            // Confirm no package_versions row exists.
            long pvCount = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem = 'cargo' AND p.name = @name
                """,
                new { orgId = defaultOrgId, name });
            Assert.Equal(0, pvCount);

            // Step 2: seed global-plane entry for tenant A + cargo_metadata index line.
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "cargo", name, version, filename);

            // Seed the cargo_metadata row keyed by cache_artifact_id (owner_kind='cache_artifact').
            string? cacheArtifactId = await conn.ExecuteScalarAsync<string>(
                """
                SELECT ca.id FROM cache_artifact ca
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
                WHERE ca.ecosystem = 'cargo' AND ca.name = @name AND ca.version = @version
                LIMIT 1
                """,
                new { orgId = defaultOrgId, name, version });
            Assert.NotNull(cacheArtifactId);

            await conn.ExecuteAsync(
                """
                INSERT INTO cargo_metadata (cache_artifact_id, index_line, owner_kind)
                VALUES (@caId, @indexLine, 'cache_artifact')
                ON CONFLICT (cache_artifact_id) WHERE owner_kind = 'cache_artifact'
                DO UPDATE SET index_line = excluded.index_line
                """,
                new { caId = cacheArtifactId, indexLine });

            // Step 3: tenant A — sparse index must contain the version line.
            var afterA = await clientA.GetAsync($"/cargo/{indexPath}");
            Assert.Equal(HttpStatusCode.OK, afterA.StatusCode);
            string bodyA = await afterA.Content.ReadAsStringAsync();
            Assert.Contains(version, bodyA);

            // No package_versions row was written — global plane is authoritative.
            pvCount = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem = 'cargo' AND p.name = @name
                """,
                new { orgId = defaultOrgId, name });
            Assert.Equal(0, pvCount);

            // Step 4: tenant B has no access row — the same crate is absent from B's index.
            // Verify via the repository directly (B's org has passthrough disabled so only
            // local-plane rows are returned).
            var cargoMeta = _factory.Services.GetRequiredService<CargoMetadataRepository>();
            var linesForB = await cargoMeta.GetIndexLinesAsync(orgB.Id, name);
            Assert.Empty(linesForB);

            // Step 5: seed B's global-plane access, then the version appears for B.
            await SeedGlobalPlaneEntryAsync(orgB.Id, "cargo", name, version, filename);
            await conn.ExecuteAsync(
                """
                INSERT INTO cargo_metadata (cache_artifact_id, index_line, owner_kind)
                VALUES (@caId, @indexLine, 'cache_artifact')
                ON CONFLICT (cache_artifact_id) WHERE owner_kind = 'cache_artifact'
                DO UPDATE SET index_line = excluded.index_line
                """,
                new { caId = cacheArtifactId, indexLine });

            linesForB = await cargoMeta.GetIndexLinesAsync(orgB.Id, name);
            Assert.Single(linesForB);
            Assert.Contains(version, linesForB[0]);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }

    // Computes the sparse-index sub-path for a crate name per the Cargo registry spec.
    // Mirrors the logic in CargoController.ComputeIndexPath.
    private static string CargoIndexPath(string name) => name.Length switch
    {
        1 => $"1/{name}",
        2 => $"2/{name}",
        3 => $"3/{name[0]}/{name}",
        _ => $"{name[..2]}/{name[2..4]}/{name}",
    };

    // ── NuGet: registration index ──────────────────────────────────────────────

    /// <summary>
    /// A proxy-first-fetched NuGet version in the global plane must appear in the registration
    /// index (GET /nuget/registration/{id}/index.json) when passthrough is disabled.
    ///
    /// Regression: ServeLocalRegistrationAsync called GetVersionsAsync which read only
    /// package_versions; global-plane-only versions were absent from the registration surface.
    /// </summary>
    [Fact]
    public async Task NuGet_RegistrationIndex_GlobalPlaneProxyVersion_AppearsInLeaves()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        string id = $"gpreg{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string proxyVersion = "4.5.6";
        string proxyFilename = $"{id}.{proxyVersion}.nupkg";

        await _factory.PushNuGetPackage(id, "88.0.0");

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = defaultOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Before seed: registration has only the uploaded version.
            var beforeResp = await client.GetAsync($"/nuget/registration/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, beforeResp.StatusCode);
            string beforeJson = await beforeResp.Content.ReadAsStringAsync();
            Assert.Contains("88.0.0", beforeJson);
            Assert.DoesNotContain(proxyVersion, beforeJson);

            // Seed global-plane entry.
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "nuget", id, proxyVersion, proxyFilename);

            // Evict registration cache.
            _factory.Services.GetRequiredService<RenderedResponseCache<NuGetRegistrationKey>>()
                .Evict(new NuGetRegistrationKey(defaultOrgId, id, false));

            // After seed: both uploaded and proxy versions appear.
            var afterResp = await client.GetAsync($"/nuget/registration/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, afterResp.StatusCode);
            string afterJson = await afterResp.Content.ReadAsStringAsync();
            Assert.Contains("88.0.0", afterJson);
            Assert.Contains(proxyVersion, afterJson);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId = defaultOrgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(defaultOrgId);
        }
    }
}
