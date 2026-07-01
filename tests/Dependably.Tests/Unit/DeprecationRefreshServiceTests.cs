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
using Microsoft.Extensions.Time.Testing;

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
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

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
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "left-pad", version: "1.0.0", origin: "proxy", deprecated: null);

        string packument = NpmPackument("left-pad", new Dictionary<string, string?>
        {
            ["1.0.0"] = "use pad-left instead"
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = caId });
        Assert.Equal("use pad-left instead", dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task NpmPackage_DeprecationCleared_UpdatesBothColumns()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "old-pkg", version: "2.0.0", origin: "proxy",
            deprecated: "was deprecated");

        string packument = NpmPackument("old-pkg", new Dictionary<string, string?>
        {
            ["2.0.0"] = null // no longer deprecated
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = caId });
        Assert.Null(dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task NpmPackage_UnchangedDeprecation_OnlyStampsCheckedAt()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "stable-pkg", version: "3.0.0", origin: "proxy",
            deprecated: "still deprecated");

        string packument = NpmPackument("stable-pkg", new Dictionary<string, string?>
        {
            ["3.0.0"] = "still deprecated"
        });
        var service = BuildService(packument);

        // Record the deprecated value before the pass
        await using var connBefore = await _db.OpenAsync();
        string? depBefore = await connBefore.QuerySingleAsync<string?>(
            "SELECT deprecated FROM cache_artifact WHERE id = @id", new { id = caId });

        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = caId });
        Assert.Equal(depBefore, dep); // unchanged
        Assert.NotNull(checkedAt);    // stamped
    }

    [Fact]
    public async Task NpmPackage_UploadedVersion_NotUpdated()
    {
        // origin='uploaded' versions are not in cache_artifact; the service only enumerates
        // cache_artifact groups, so uploaded versions are skipped entirely.
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "my-pkg", version: "1.0.0", origin: "uploaded", deprecated: null);

        string packument = NpmPackument("my-pkg", new Dictionary<string, string?>
        {
            ["1.0.0"] = "deprecated"
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM package_versions WHERE id = @id", new { id = versionId });
        // uploaded version stays untouched in package_versions
        Assert.Null(checkedAt);
    }

    [Fact]
    public async Task NpmPackage_RefreshPass_RecordsUpstreamLatestVersion()
    {
        // The service looks up the packages row (if any) to record upstream's declared latest
        // version; SeedVersionAsync always creates a packages row for the org.
        var (_, packageId, _, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "left-pad", version: "1.0.0", origin: "proxy", deprecated: null);

        string packument = NpmPackument("left-pad",
            new Dictionary<string, string?> { ["1.0.0"] = null }, latest: "2.5.0");
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? latest = await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId });
        Assert.Equal("2.5.0", latest);
    }

    [Fact]
    public async Task NuGetPackage_RefreshPass_RecordsUpstreamLatestStableVersion()
    {
        // NuGet has no per-version deprecation signal, but the refresh pass still resolves the
        // upstream latest STABLE version (the 2.1.0-rc prerelease must be ignored).
        var (orgId, packageId, _, _) = await SeedVersionAsync(
            ecosystem: "nuget", name: "newtonsoft.json", version: "1.0.0", origin: "proxy", deprecated: null);
        await SeedUpstreamRegistryAsync(orgId, "nuget", "http://nuget.test/v3");

        var service = BuildService("""{"versions":["1.0.0","2.0.0","2.1.0-rc.1"]}""");
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? latest = await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId });
        Assert.Equal("2.0.0", latest);
    }

    [Fact]
    public async Task MavenPackage_RefreshPass_RecordsUpstreamReleaseVersion()
    {
        var (orgId, packageId, _, _) = await SeedVersionAsync(
            ecosystem: "maven", name: "org.example:widget", version: "1.0.0", origin: "proxy", deprecated: null);
        await SeedUpstreamRegistryAsync(orgId, "maven", "http://maven.test");

        var service = BuildService(
            "<metadata><versioning><latest>2.1.0-SNAPSHOT</latest><release>2.0.0</release></versioning></metadata>");
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? latest = await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId });
        Assert.Equal("2.0.0", latest);
    }

    // ── PyPI tests ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPiPackage_VersionYanked_SetsDeprecatedField()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "evil-lib", version: "0.1.0", origin: "proxy", deprecated: null);

        string pypiJson = PyPiJson("evil-lib", new Dictionary<string, (bool Yanked, string? Reason)>
        {
            ["0.1.0"] = (true, "security vulnerability")
        });
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = caId });
        Assert.Equal("security vulnerability", dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task PyPiPackage_VersionYankedNoReason_UsesDefaultMessage()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "bad-lib", version: "1.0.0", origin: "proxy", deprecated: null);

        string pypiJson = PyPiJson("bad-lib", new Dictionary<string, (bool Yanked, string? Reason)>
        {
            ["1.0.0"] = (true, null)
        });
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? dep = await conn.QuerySingleAsync<string?>(
            "SELECT deprecated FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Equal("yanked", dep);
    }

    [Fact]
    public async Task PyPiPackage_NotYanked_LeavesDeprecatedNull()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "good-lib", version: "2.0.0", origin: "proxy", deprecated: null);

        string pypiJson = PyPiJson("good-lib", new Dictionary<string, (bool Yanked, string? Reason)>
        {
            ["2.0.0"] = (false, null)
        });
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = caId });
        Assert.Null(dep);
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task PyPiPackage_RefreshPass_RecordsUpstreamLatestVersion()
    {
        var (_, packageId, _, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "good-lib", version: "1.0.0", origin: "proxy", deprecated: null);

        string pypiJson = PyPiJson("good-lib",
            new Dictionary<string, (bool Yanked, string? Reason)> { ["1.0.0"] = (false, null) },
            latest: "3.1.4");
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? latest = await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId });
        Assert.Equal("3.1.4", latest);
    }

    // ── Revocation (upstream-removal) tests ─────────────────────────────────────

    [Fact]
    public async Task NpmPackage_VersionRemovedUpstream_SetsRevokedAtAndLogsActivity()
    {
        var (orgId, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "gone-pkg", version: "1.0.0", origin: "proxy", deprecated: null);

        // Upstream still publishes the package, but no longer lists 1.0.0 (only 2.0.0).
        string packument = NpmPackument("gone-pkg", new Dictionary<string, string?> { ["2.0.0"] = null });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? revokedAt = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), revokedAt);

        var (eventCount, purl) = await conn.QuerySingleAsync<(int, string?)>(
            "SELECT COUNT(*), MAX(purl) FROM activity WHERE event_type = 'version_revoked' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(1, eventCount);
        Assert.Equal("pkg:npm/gone-pkg@1.0.0", purl);
    }

    [Fact]
    public async Task NpmPackage_VersionPresentUpstream_LeavesRevokedNull()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "live-pkg", version: "1.0.0", origin: "proxy", deprecated: null);

        string packument = NpmPackument("live-pkg", new Dictionary<string, string?> { ["1.0.0"] = null });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? revokedAt = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Null(revokedAt);
    }

    [Fact]
    public async Task NpmPackage_EmptyUpstreamSet_DoesNotRevoke()
    {
        // An empty upstream version set models a 404 / transient outage / whole-package removal.
        // The false-positive guard must NOT revoke any locally-cached version in that case.
        var (orgId, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "flaky-pkg", version: "1.0.0", origin: "proxy", deprecated: null);

        string packument = NpmPackument("flaky-pkg", new Dictionary<string, string?>());
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? revokedAt = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Null(revokedAt);
        int eventCount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'version_revoked' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(0, eventCount);
    }

    [Fact]
    public async Task NpmPackage_RevokedVersionReappears_ClearsRevokedAt()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "back-pkg", version: "1.0.0", origin: "proxy", deprecated: null);
        await SetRevokedAtAsync(caId, "2020-01-01T00:00:00Z");

        string packument = NpmPackument("back-pkg", new Dictionary<string, string?> { ["1.0.0"] = null });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? revokedAt = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Null(revokedAt);
    }

    [Fact]
    public async Task NpmPackage_AlreadyRevoked_DoesNotReLogActivity()
    {
        // A version that is already marked revoked and is still absent upstream must not emit a
        // second version_revoked event — the activity row records first-observation only.
        var (orgId, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "stale-gone", version: "1.0.0", origin: "proxy", deprecated: null);
        await SetRevokedAtAsync(caId, "2020-01-01T00:00:00Z");

        string packument = NpmPackument("stale-gone", new Dictionary<string, string?> { ["2.0.0"] = null });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        int eventCount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'version_revoked' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(0, eventCount);
    }

    [Fact]
    public async Task NpmPackage_MixedPass_RevokesOnlyAbsentVersions()
    {
        // One refresh group, two cached versions: 1.0.0 is gone upstream, 2.0.0 still listed.
        var (orgId, _, caV1, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "multi-pkg", version: "1.0.0", origin: "proxy", deprecated: null);
        string caV2 = await SeedCacheVersionAsync(orgId, "npm", "multi-pkg", "2.0.0");

        string packument = NpmPackument("multi-pkg", new Dictionary<string, string?> { ["2.0.0"] = null });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? revokedV1 = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caV1 });
        string? revokedV2 = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caV2 });
        Assert.NotNull(revokedV1);
        Assert.Null(revokedV2);

        int eventCount = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'version_revoked' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(1, eventCount);
    }

    [Fact]
    public async Task PyPiPackage_VersionRemovedUpstream_SetsRevokedAt()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "pypi", name: "removed-lib", version: "0.1.0", origin: "proxy", deprecated: null);

        // Upstream lists 0.2.0 only — 0.1.0 has been deleted.
        string pypiJson = PyPiJson("removed-lib",
            new Dictionary<string, (bool Yanked, string? Reason)> { ["0.2.0"] = (false, null) });
        var service = BuildService(pypiJson);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? revokedAt = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), revokedAt);
    }

    [Fact]
    public async Task NuGetPackage_VersionAbsentUpstream_NotRevoked()
    {
        // NuGet/Maven resolve only a latest-scalar (empty per-version Deprecated set), so revocation
        // detection is out of scope and must never fire for them.
        var (orgId, _, caId, _) = await SeedVersionAsync(
            ecosystem: "nuget", name: "newtonsoft.json", version: "1.0.0", origin: "proxy", deprecated: null);
        await SeedUpstreamRegistryAsync(orgId, "nuget", "http://nuget.test/v3");

        var service = BuildService("""{"versions":["2.0.0","3.0.0"]}""");
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? revokedAt = await conn.QuerySingleAsync<string?>(
            "SELECT revoked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Null(revokedAt);
    }

    // ── Unsupported ecosystem tests ────────────────────────────────────────────

    [Theory]
    [InlineData("rpm")]
    [InlineData("oci")]
    [InlineData("cargo")]
    [InlineData("go")]
    public async Task UnsupportedEcosystem_VersionNotChecked(string ecosystem)
    {
        // The refresh query filters to npm/pypi/nuget/maven, so other ecosystems are excluded from
        // enumeration; their cache_artifact rows remain unstamped.
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: ecosystem, name: "some-pkg", version: "1.0.0", origin: "proxy", deprecated: null);

        var service = BuildService(responseBody: ""); // handler should never be called
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Null(checkedAt);
    }

    // ── Air-gap test ───────────────────────────────────────────────────────────

    [Fact]
    public async Task AirGapMode_PassSkipped_NoRowsUpdated()
    {
        var (_, _, caId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "pkg", version: "1.0.0", origin: "proxy", deprecated: null);

        var service = BuildService("{}", airGapped: true);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Null(checkedAt);
    }

    /// <summary>
    /// Mixed per-tenant air-gap: tenant A is air-gapped (org_settings.air_gapped=1), tenant B is
    /// not. Both hold the same proxy npm package the upstream packument marks deprecated. Only
    /// tenant B's cache_artifact row is refreshed; tenant A's is left untouched (excluded by
    /// the per-tenant join in ListGroupsNeedingDeprecationRefreshAsync). The instance air-gap is
    /// off here, so this proves the per-tenant gate works independently of the instance posture.
    /// </summary>
    [Fact]
    public async Task PerTenantAirGap_OnlyNonAirGappedTenantRefreshed()
    {
        // Distinct names (PURL is globally unique) but the same upstream body — the npm parser
        // keys deprecation by version string, so version 1.0.0 is marked deprecated for both.
        // The per-tenant air-gap filter in ListGroupsNeedingDeprecationRefreshAsync excludes
        // tenant A's group, so only tenant B's cache_artifact row is refreshed.
        var (orgA, _, caIdA, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "airgap-pkg-a", version: "1.0.0", origin: "proxy", deprecated: null);
        var (_, _, caIdB, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "airgap-pkg-b", version: "1.0.0", origin: "proxy", deprecated: null);
        await SetAirGappedAsync(orgA, true);

        string packument = NpmPackument("airgap-pkg", new Dictionary<string, string?>
        {
            ["1.0.0"] = "use something else"
        });
        var service = BuildService(packument);
        await service.RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (depA, checkedA) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = caIdA });
        var (depB, checkedB) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = caIdB });

        // Air-gapped tenant A: untouched.
        Assert.Null(depA);
        Assert.Null(checkedA);
        // Connected tenant B: refreshed.
        Assert.Equal("use something else", depB);
        Assert.NotNull(checkedB);
    }

    // ── Repository method tests ────────────────────────────────────────────────

    [Fact]
    public async Task ListGroupsNeedingDeprecationRefresh_NullDeprecationCheckedAt_Returned()
    {
        var (orgId, _, _, _) = await SeedVersionAsync(ecosystem: "npm", name: "stale-pkg",
            version: "1.0.0", origin: "proxy", deprecated: null, deprecationCheckedAt: null);

        var repo = new CacheArtifactRepository(_db);
        var results = await repo.ListGroupsNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10, _clock);

        Assert.Contains(results, r => r.Name == "stale-pkg" && r.OrgId == orgId);
    }

    [Fact]
    public async Task ListGroupsNeedingDeprecationRefresh_FreshRow_NotReturned()
    {
        string freshAt = _clock.GetUtcNow().AddMinutes(-30).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var (orgId, _, _, _) = await SeedVersionAsync(ecosystem: "npm", name: "fresh-pkg",
            version: "1.0.0", origin: "proxy", deprecated: null, deprecationCheckedAt: freshAt);

        var repo = new CacheArtifactRepository(_db);
        var results = await repo.ListGroupsNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10, _clock);

        Assert.DoesNotContain(results, r => r.Name == "fresh-pkg" && r.OrgId == orgId);
    }

    [Fact]
    public async Task ListGroupsNeedingDeprecationRefresh_StaleRow_Returned()
    {
        // 48 hours old, well outside the 24-hour window
        string staleAt = _clock.GetUtcNow().AddHours(-48).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var (orgId, _, _, _) = await SeedVersionAsync(ecosystem: "npm", name: "stale-pkg2",
            version: "1.0.0", origin: "proxy", deprecated: null, deprecationCheckedAt: staleAt);

        var repo = new CacheArtifactRepository(_db);
        var results = await repo.ListGroupsNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10, _clock);

        Assert.Contains(results, r => r.Name == "stale-pkg2" && r.OrgId == orgId);
    }

    [Fact]
    public async Task ListGroupsNeedingDeprecationRefresh_UploadedOrigin_NotReturned()
    {
        // Uploaded versions have no cache_artifact rows; the query enumerates cache_artifact only.
        var (orgId, _, _, _) = await SeedVersionAsync(ecosystem: "npm", name: "uploaded-pkg",
            version: "1.0.0", origin: "uploaded", deprecated: null, deprecationCheckedAt: null);

        var repo = new CacheArtifactRepository(_db);
        var results = await repo.ListGroupsNeedingDeprecationRefreshAsync(ageHours: 24, limit: 10, _clock);

        Assert.DoesNotContain(results, r => r.Name == "uploaded-pkg" && r.OrgId == orgId);
    }

    [Fact]
    public async Task UpdateDeprecationCheckedAtAsync_StampsTimestamp()
    {
        // This PackageRepository method writes to package_versions; seed an uploaded version
        // so RowId is the package_versions PK.
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "x", version: "1.0.0", origin: "uploaded", deprecated: null);

        var repo = new PackageRepository(_db, time: _clock);
        await repo.UpdateDeprecationCheckedAtAsync(versionId);

        await using var conn = await _db.OpenAsync();
        string? checkedAt = await conn.QuerySingleAsync<string?>(
            "SELECT deprecation_checked_at FROM package_versions WHERE id = @id", new { id = versionId });
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), checkedAt);
    }

    [Fact]
    public async Task UpdateDeprecatedAndCheckedAsync_SetsBothColumns()
    {
        // This PackageRepository method writes to package_versions; seed an uploaded version
        // so RowId is the package_versions PK.
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "y", version: "1.0.0", origin: "uploaded", deprecated: null);

        var repo = new PackageRepository(_db, time: _clock);
        await repo.UpdateDeprecatedAndCheckedAsync(versionId, "some reason");

        await using var conn = await _db.OpenAsync();
        var (dep, checkedAt) = await conn.QuerySingleAsync<(string?, string?)>(
            "SELECT deprecated, deprecation_checked_at FROM package_versions WHERE id = @id",
            new { id = versionId });
        Assert.Equal("some reason", dep);
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), checkedAt);
    }

    [Fact]
    public async Task UpdateDeprecatedAndCheckedAsync_ClearsDeprecation()
    {
        // This PackageRepository method writes to package_versions; seed an uploaded version
        // so RowId is the package_versions PK.
        var (_, _, versionId, _) = await SeedVersionAsync(
            ecosystem: "npm", name: "z", version: "1.0.0", origin: "uploaded", deprecated: "old reason");

        var repo = new PackageRepository(_db, time: _clock);
        await repo.UpdateDeprecatedAndCheckedAsync(versionId, null);

        await using var conn = await _db.OpenAsync();
        string? dep = await conn.QuerySingleAsync<string?>(
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
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dep-refresh-test-{Guid.NewGuid():N}");
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
            factory, tiered, new AuditRepository(_db), validator, airGap,
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        var packages = new PackageRepository(_db, time: _clock);
        var cacheArtifacts = new CacheArtifactRepository(_db);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured()));
        var latestResolver = new UpstreamLatestVersionResolver(upstream, registries, config);
        return new DeprecationRefreshService(
            packages, cacheArtifacts, audit, upstream, latestResolver, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance,
            _clock);
    }

    /// <summary>
    /// Seeds a package version. For proxy origin, also seeds a <c>cache_artifact</c> row plus a
    /// <c>tenant_artifact_access</c> row (the global-plane records the service now reads).
    /// Returns: (orgId, packageId, cacheArtifactId-or-versionId-for-uploaded, purl).
    /// </summary>
    private async Task<(string OrgId, string PackageId, string RowId, string Purl)> SeedVersionAsync(
        string ecosystem,
        string name,
        string version,
        string origin,
        string? deprecated,
        string? deprecationCheckedAt = null)
    {
        await using var conn = await _db.OpenAsync();
        string orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = $"org-{orgId[..6]}" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        string packageId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @orgId, @eco, @name, @name, 1)",
            new { id = packageId, orgId, eco = ecosystem, name });

        string versionId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, deprecated, deprecation_checked_at)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @origin, @deprecated, @deprecationCheckedAt)
            """,
            new { id = versionId, pkgId = packageId, version, purl, blobKey = $"blobs/{versionId}", origin, deprecated, deprecationCheckedAt });

        if (origin == "proxy")
        {
            // Seed the global-plane row. The deprecation refresh service reads from cache_artifact
            // via tenant_artifact_access; without this row the service cannot find the package.
            string caId = Guid.NewGuid().ToString("N");
            string blobKey = $"proxy/{caId}/{name}-{version}.tgz";
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, purl,
                     deprecated, deprecation_checked_at)
                VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h', @purl,
                        @deprecated, @deprecationCheckedAt)
                """,
                new { id = caId, ecosystem, name, version, filename = $"{name}-{version}.tgz", blobKey, purl, deprecated, deprecationCheckedAt });

            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId, caId });

            return (orgId, packageId, caId, purl);
        }

        return (orgId, packageId, versionId, purl);
    }

    /// <summary>
    /// Seeds an additional <c>cache_artifact</c> + <c>tenant_artifact_access</c> row for an
    /// existing (org, ecosystem, name) so a single refresh group spans multiple versions.
    /// Returns the new cache_artifact id.
    /// </summary>
    private async Task<string> SeedCacheVersionAsync(
        string orgId, string ecosystem, string name, string version,
        string? deprecated = null, string? revokedAt = null)
    {
        await using var conn = await _db.OpenAsync();
        string caId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:{ecosystem}/{name}@{version}";
        string blobKey = $"proxy/{caId}/{name}-{version}.tgz";
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, purl,
                 deprecated, revoked_at)
            VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h', @purl,
                    @deprecated, @revokedAt)
            """,
            new { id = caId, ecosystem, name, version, filename = $"{name}-{version}.tgz", blobKey, purl, deprecated, revokedAt });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        return caId;
    }

    private async Task SetRevokedAtAsync(string caId, string revokedAt)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET revoked_at = @revokedAt WHERE id = @id",
            new { id = caId, revokedAt });
    }

    private async Task SeedUpstreamRegistryAsync(string orgId, string ecosystem, string url)
    {
        var repo = new UpstreamRegistryRepository(_db, _clock, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured());
        await repo.AddAsync(orgId, new NewUpstreamRegistry(ecosystem, url));
    }

    private async Task SetAirGappedAsync(string orgId, bool airGapped)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET air_gapped = @flag WHERE org_id = @orgId",
            new { orgId, flag = airGapped ? 1 : 0 });
    }

    // Builds an npm packument JSON with controlled deprecated values per version and an optional
    // dist-tags.latest claim.
    private static string NpmPackument(string name, Dictionary<string, string?> deprecatedByVersion, string? latest = null)
    {
        var versions = new Dictionary<string, object>();
        foreach (var (ver, dep) in deprecatedByVersion)
        {
            if (dep is not null)
            {
                versions[ver] = new { deprecated = dep, name, version = ver };
            }
            else
            {
                versions[ver] = new { name, version = ver };
            }
        }
        var root = new Dictionary<string, object?> { ["name"] = name, ["versions"] = versions };
        if (latest is not null)
        {
            root["dist-tags"] = new Dictionary<string, object?> { ["latest"] = latest };
        }

        return JsonSerializer.Serialize(root);
    }

    // Builds a PyPI project JSON with controlled yanked state per release and an optional
    // info.version (PyPI's latest release) claim.
    private static string PyPiJson(string name, Dictionary<string, (bool Yanked, string? Reason)> releases, string? latest = null)
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
        var info = new Dictionary<string, object?> { ["name"] = name };
        if (latest is not null)
        {
            info["version"] = latest;
        }

        return JsonSerializer.Serialize(new { info, releases = releaseMap });
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
