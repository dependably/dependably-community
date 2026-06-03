using System.Net;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the deprecation refresh background service: repository query, npm packument parsing,
/// PyPI yanked detection, unchanged-status stamping, unsupported-ecosystem skipping, and the
/// air-gap early-exit. Tests use an in-memory SQLite store and a fake HTTP handler that returns
/// controlled packument/project-JSON responses.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── npm tests ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task NpmPackage_VersionBecomesDeprecated_UpdatesBothColumns()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "left-pad", version: "1.0.0", origin: "proxy", deprecated: null);

        var packument = NpmPackument("left-pad", new Dictionary<string, string?>
        {
            ["1.0.0"] = "use pad-left instead"
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionId });
        Assert.Equal("use pad-left instead", dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task NpmPackage_DeprecationCleared_UpdatesBothColumns()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "old-pkg", version: "2.0.0", origin: "proxy",
            deprecated: "was deprecated");

        var packument = NpmPackument("old-pkg", new Dictionary<string, string?>
        {
            ["2.0.0"] = null // no longer deprecated
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionId });
        Assert.Null(dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task NpmPackage_UnchangedDeprecation_OnlyStampsCheckedAt()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "stable-pkg", version: "3.0.0", origin: "proxy",
            deprecated: "still deprecated");

        var packument = NpmPackument("stable-pkg", new Dictionary<string, string?>
        {
            ["3.0.0"] = "still deprecated"
        });
        var service = BuildService(packument);

        // Record the deprecated value before the pass
        await using var connBefore = await _db.OpenAsync();
        var depBefore = await connBefore.QuerySingleAsync<string?>(
            "SELECT deprecated FROM package_versions WHERE id = @id", new { id = versionId });

        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionId });
        Assert.Equal(depBefore, dep); // unchanged
        Assert.NotNull(checkedAt);    // stamped
    }

    [Fact]
    public async Task NpmPackage_UploadedVersion_NotUpdated()
    {
        // origin='uploaded' versions are not proxy-cached; they should be skipped.
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "my-pkg", version: "1.0.0", origin: "uploaded", deprecated: null);

        var packument = NpmPackument("my-pkg", new Dictionary<string, string?>
        {
            ["1.0.0"] = "deprecated"
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM package_versions WHERE id = @id", new { id = versionId });
        // uploaded version is skipped entirely — no deprecation_checked_at stamp
        Assert.Null(checkedAt);
    }

    // ── PyPI tests ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPiPackage_VersionYanked_SetsDeprecatedField()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "evil-lib", version: "0.1.0", origin: "proxy", deprecated: null);

        var pypiJson = PyPiJson("evil-lib", new Dictionary<string, (bool Yanked, string? Reason)>
        {
            ["0.1.0"] = (true, "security vulnerability")
        });
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionId });
        Assert.Equal("security vulnerability", dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task PyPiPackage_VersionYankedNoReason_UsesDefaultMessage()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "bad-lib", version: "1.0.0", origin: "proxy", deprecated: null);

        var pypiJson = PyPiJson("bad-lib", new Dictionary<string, (bool Yanked, string? Reason)>
        {
            ["1.0.0"] = (true, null)
        });
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var dep = await conn.QuerySingleAsync<string?>(
            "SELECT deprecated FROM package_versions WHERE id = @id", new { id = versionId });
        Assert.Equal("yanked", dep);
    }

    [Fact]
    public async Task PyPiPackage_NotYanked_LeavesDeprecatedNull()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "good-lib", version: "2.0.0", origin: "proxy", deprecated: null);

        var pypiJson = PyPiJson("good-lib", new Dictionary<string, (bool Yanked, string? Reason)>
        {
            ["2.0.0"] = (false, null)
        });
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionId });
        Assert.Null(dep);
        Assert.NotNull(checkedAt);
    }

    // ── Unsupported ecosystem tests ────────────────────────────────────────────

    [Theory]
    [InlineData("nuget")]
    [InlineData("maven")]
    [InlineData("rpm")]
    [InlineData("oci")]
    public async Task UnsupportedEcosystem_VersionNotChecked(string ecosystem)
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: ecosystem, name: "some-pkg", version: "1.0.0", origin: "proxy", deprecated: null);

        var service = BuildService(responseBody: ""); // handler should never be called
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM package_versions WHERE id = @id", new { id = versionId });
        Assert.Null(checkedAt);
    }

    // ── Air-gap test ───────────────────────────────────────────────────────────

    [Fact]
    public async Task AirGapMode_PassSkipped_NoRowsUpdated()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "pkg", version: "1.0.0", origin: "proxy", deprecated: null);

        var service = BuildService("{}", airGapped: true);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM package_versions WHERE id = @id", new { id = versionId });
        Assert.Null(checkedAt);
    }

    /// <summary>
    /// Mixed per-tenant air-gap: tenant A is air-gapped (org_settings.air_gapped=1), tenant B is
    /// not. Both hold the same proxy npm package the upstream packument marks deprecated. Only
    /// tenant B's version is refreshed; tenant A's is left untouched (excluded by the
    /// per-tenant join in ListPackagesNeedingDeprecationRefreshAsync). The instance air-gap is
    /// off here, so this proves the per-tenant gate works independently of the instance posture.
    /// </summary>
    [Fact]
    public async Task PerTenantAirGap_OnlyNonAirGappedTenantRefreshed()
    {
        // Distinct names (PURL is globally unique) but the same upstream body — the npm parser
        // keys deprecation by version string, so version 1.0.0 is marked deprecated for both.
        var (orgA, _, versionA, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "airgap-pkg-a", version: "1.0.0", origin: "proxy", deprecated: null);
        var (_, _, versionB, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "airgap-pkg-b", version: "1.0.0", origin: "proxy", deprecated: null);
        await SetAirGappedAsync(orgA, true);

        var packument = NpmPackument("airgap-pkg", new Dictionary<string, string?>
        {
            ["1.0.0"] = "use something else"
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (depA, checkedA) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionA });
        var (depB, checkedB) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionB });

        // Air-gapped tenant A: untouched.
        Assert.Null(depA);
        Assert.Null(checkedA);
        // Connected tenant B: refreshed.
        Assert.Equal("use something else", depB);
        Assert.NotNull(checkedB);
    }

    // ── Repository method tests ────────────────────────────────────────────────

    [Fact]
    public async Task ListPackagesNeedingDeprecationRefresh_NullDeprecationCheckedAt_Returned()
    {
        await SeedVersionAsync(ecosystem: "npm", name: "stale-pkg", version: "1.0.0",
            origin: "proxy", deprecated: null, deprecationCheckedAt: null);

        var repo = new PackageRepository(_db);
        var results = await repo.ListPackagesNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10);

        Assert.Single(results, r => r.PurlName == "stale-pkg");
    }

    [Fact]
    public async Task ListPackagesNeedingDeprecationRefresh_FreshRow_NotReturned()
    {
        var freshAt = DateTimeOffset.UtcNow.AddMinutes(-30).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await SeedVersionAsync(ecosystem: "npm", name: "fresh-pkg", version: "1.0.0",
            origin: "proxy", deprecated: null, deprecationCheckedAt: freshAt);

        var repo = new PackageRepository(_db);
        var results = await repo.ListPackagesNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10);

        Assert.DoesNotContain(results, r => r.PurlName == "fresh-pkg");
    }

    [Fact]
    public async Task ListPackagesNeedingDeprecationRefresh_StaleRow_Returned()
    {
        var staleAt = DateTimeOffset.UtcNow.AddHours(-48).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await SeedVersionAsync(ecosystem: "npm", name: "stale-pkg2", version: "1.0.0",
            origin: "proxy", deprecated: null, deprecationCheckedAt: staleAt);

        var repo = new PackageRepository(_db);
        var results = await repo.ListPackagesNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10);

        Assert.Single(results, r => r.PurlName == "stale-pkg2");
    }

    [Fact]
    public async Task ListPackagesNeedingDeprecationRefresh_UploadedOrigin_NotReturned()
    {
        await SeedVersionAsync(ecosystem: "npm", name: "uploaded-pkg", version: "1.0.0",
            origin: "uploaded", deprecated: null, deprecationCheckedAt: null);

        var repo = new PackageRepository(_db);
        var results = await repo.ListPackagesNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10);

        Assert.DoesNotContain(results, r => r.PurlName == "uploaded-pkg");
    }

    [Fact]
    public async Task UpdateDeprecationCheckedAtAsync_StampsTimestamp()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "x", version: "1.0.0", origin: "proxy", deprecated: null);

        var repo = new PackageRepository(_db);
        await repo.UpdateDeprecationCheckedAtAsync(versionId);

        await using var conn = await _db.OpenAsync();
        var checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM package_versions WHERE id = @id", new { id = versionId });
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task UpdateDeprecatedAndCheckedAsync_SetsBothColumns()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "y", version: "1.0.0", origin: "proxy", deprecated: null);

        var repo = new PackageRepository(_db);
        await repo.UpdateDeprecatedAndCheckedAsync(versionId, "some reason");

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionId });
        Assert.Equal("some reason", dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task UpdateDeprecatedAndCheckedAsync_ClearsDeprecation()
    {
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "z", version: "1.0.0", origin: "proxy", deprecated: "old reason");

        var repo = new PackageRepository(_db);
        await repo.UpdateDeprecatedAndCheckedAsync(versionId, null);

        await using var conn = await _db.OpenAsync();
        var dep = await conn.QuerySingleAsync<string?>(
            "SELECT deprecated FROM package_versions WHERE id = @id", new { id = versionId });
        Assert.Null(dep);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private DeprecationRefreshService BuildService(
        string responseBody,
        bool airGapped = false)
    {
        var handler = new FixedResponseHandler(responseBody);
        var factory = new SingleHandlerFactory(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        var audit = new AuditRepository(_db);
        var validator = new AllowAllValidator();
        var stagingDir = Path.Combine(Path.GetTempPath(), $"dep-refresh-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = stagingDir,
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = "100",
                ["Npm:Upstream"] = "http://npm.test",
                ["PyPI:Upstream"] = "http://pypi.test",
            })
            .Build();
        var airGap = new StubAirGap(airGapped);
        var upstream = new UpstreamClient(
            factory, tiered, new AuditRepository(_db), validator, airGap, config,
            NullLogger<UpstreamClient>.Instance);
        var packages = new PackageRepository(_db);
        return new DeprecationRefreshService(
            packages, audit, upstream, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance);
    }

    private async Task<(string OrgId, string PackageId, string VersionId, string Purl)> SeedVersionAsync(
        string ecosystem,
        string name,
        string version,
        string origin,
        string? deprecated,
        string? deprecationCheckedAt = null)
    {
        await using var conn = await _db.OpenAsync();
        var orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = $"org-{orgId[..6]}" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        var packageId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @orgId, @eco, @name, @name, 1)",
            new { id = packageId, orgId, eco = ecosystem, name });

        var versionId = Guid.NewGuid().ToString("N");
        var purl = $"pkg:{ecosystem}/{name}@{version}";
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, deprecated, deprecation_checked_at)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @origin, @deprecated, @deprecationCheckedAt)
            """,
            new { id = versionId, pkgId = packageId, version, purl, blobKey = $"blobs/{versionId}", origin, deprecated, deprecationCheckedAt });
        return (orgId, packageId, versionId, purl);
    }

    private async Task SetAirGappedAsync(string orgId, bool airGapped)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET air_gapped = @flag WHERE org_id = @orgId",
            new { orgId, flag = airGapped ? 1 : 0 });
    }

    // Builds an npm packument JSON with controlled deprecated values per version.
    private static string NpmPackument(string name, Dictionary<string, string?> deprecatedByVersion)
    {
        var versions = new Dictionary<string, object>();
        foreach (var (ver, dep) in deprecatedByVersion)
        {
            if (dep is not null)
                versions[ver] = new { deprecated = dep, name, version = ver };
            else
                versions[ver] = new { name, version = ver };
        }
        return JsonSerializer.Serialize(new { name, versions });
    }

    // Builds a PyPI project JSON with controlled yanked state per release.
    private static string PyPiJson(string name, Dictionary<string, (bool Yanked, string? Reason)> releases)
    {
        var releaseMap = new Dictionary<string, object[]>();
        foreach (var (ver, (yanked, reason)) in releases)
        {
            releaseMap[ver] = new object[]
            {
                new
                {
                    filename = $"{name}-{ver}.tar.gz",
                    yanked,
                    yanked_reason = reason
                }
            };
        }
        return JsonSerializer.Serialize(new { info = new { name }, releases = releaseMap });
    }

    private sealed class FixedResponseHandler : HttpMessageHandler
    {
        private readonly string _body;
        public FixedResponseHandler(string body) => _body = body;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler h) => _client = new HttpClient(h);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public StubAirGap(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }
}
