using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The one-shot rescan flags stored npm tarballs whose top-level manifest is ambiguous or
/// unscannable, in both the proxy cache plane and the uploaded plane, leaves clean and missing
/// blobs alone, and never repeats once the marker is written.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmManifestRescanTests : IAsyncLifetime
{
    private const string Clean = """{"name":"p","version":"1.0.0","license":"MIT"}""";
    private const string Evil = """{"name":"p","version":"1.0.0","scripts":{"postinstall":"x"}}""";
    private const string Stamp = "2026-01-01T00:00:00Z";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly InMemoryBlobStore _blobs = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private NpmManifestRescan Build(IBlobStore? store = null, ILogger<NpmManifestRescan>? logger = null) =>
        new(_db, new TieredBlobStorage(store ?? _blobs, store ?? _blobs), _clock, logger ?? NullLogger<NpmManifestRescan>.Instance);

    private async Task SeedLicenceAsync(string ownerColumn, string ownerKind, string id, string spdx, string source = "upstream")
    {
        await using var conn = await _db.OpenAsync();
        // rawsql: ownerColumn is a compile-time constant column name chosen by the test.
        await conn.ExecuteAsync(
            $"INSERT INTO package_version_licenses (id, {ownerColumn}, owner_kind, license_spdx, source) VALUES (@lid, @id, @ownerKind, @spdx, @source)",
            new { lid = Guid.NewGuid().ToString("N"), id, ownerKind, spdx, source });
    }

    private async Task<List<string>> LicencesAsync(string ownerColumn, string id)
    {
        await using var conn = await _db.OpenAsync();
        // rawsql: ownerColumn is a compile-time constant column name chosen by the test.
        return (await conn.QueryAsync<string>(
            $"SELECT license_spdx FROM package_version_licenses WHERE {ownerColumn} = @id ORDER BY license_spdx", new { id })).ToList();
    }

    private async Task<string> SeedCacheAsync(string name, string key, byte[]? bytes)
    {
        if (bytes is not null)
        {
            await _blobs.PutAsync(key, new MemoryStream(bytes));
        }

        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, license_checked_at)
            VALUES (@id, 'npm', @name, '1.0.0', @name || '-1.0.0.tgz', @key, 'h', @stamp)
            """, new { id, name, key, stamp = Stamp });
        return id;
    }

    private async Task<string> SeedUploadedAsync(string orgId, string name, string key, byte[] bytes)
    {
        await _blobs.PutAsync(key, new MemoryStream(bytes));
        string pkg = await PackageSeeder.InsertAsync(_db, orgId, "npm", name);
        return await PackageSeeder.InsertVersionAsync(_db, pkg, "1.0.0", $"pkg:npm/{name}@1.0.0", blobKey: key);
    }

    private async Task<(int Script, string? Kind, string? Checked)> CacheRowAsync(string id)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(int, string?, string?)>(
            "SELECT has_install_script, install_script_kind, license_checked_at FROM cache_artifact WHERE id = @id", new { id });
    }

    private async Task<(int Script, string? Kind)> VersionRowAsync(string id)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(int, string?)>(
            "SELECT has_install_script, install_script_kind FROM package_versions WHERE id = @id", new { id });
    }

    [Fact]
    public async Task Rescan_MixedStore_FlagsOnlyAmbiguousAndUnscannable_AndRunsOnce()
    {
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        string orgId = await OrgSeeder.InsertAsync(_db, "acme");

        string cacheAmbiguous = await SeedCacheAsync("amb", "proxy/" + new string('a', 64), ambiguous);
        string cacheClean = await SeedCacheAsync("ok", "proxy/" + new string('b', 64), single);
        string cacheJunk = await SeedCacheAsync("junk", "proxy/" + new string('c', 64), "not a tarball"u8.ToArray());
        string cacheGone = await SeedCacheAsync("gone", "proxy/" + new string('d', 64), null);
        string verAmbiguous = await SeedUploadedAsync(orgId, "uamb", "uamb/1.0.0/uamb-1.0.0.tgz", ambiguous);
        string verClean = await SeedUploadedAsync(orgId, "uok", "uok/1.0.0/uok-1.0.0.tgz", single);

        int flagged = await Build().RunOnceAsync();

        Assert.Equal(3, flagged);
        Assert.Equal((1, NpmManifestRescan.AmbiguousKind, (string?)null), await CacheRowAsync(cacheAmbiguous));
        Assert.Equal((1, NpmManifestRescan.UnscannableKind, (string?)null), await CacheRowAsync(cacheJunk));
        Assert.Equal((0, (string?)null, (string?)Stamp), await CacheRowAsync(cacheClean));
        Assert.Equal((0, (string?)null, (string?)Stamp), await CacheRowAsync(cacheGone));
        Assert.Equal((1, (string?)NpmManifestRescan.AmbiguousKind), await VersionRowAsync(verAmbiguous));
        Assert.Equal((0, (string?)null), await VersionRowAsync(verClean));

        // The marker stops a second run: a row stamped clean again after the pass is not touched.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE cache_artifact SET has_install_script = 0, install_script_kind = NULL WHERE id = @cacheAmbiguous",
                new { cacheAmbiguous });
        }

        Assert.Equal(-1, await Build().RunOnceAsync());
        Assert.Equal(0, (await CacheRowAsync(cacheAmbiguous)).Script);
    }

    [Fact]
    public async Task Rescan_PagesAcrossSmallBatches_FlagsEveryRow()
    {
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        var ids = new List<string>();
        for (int i = 0; i < 7; i++)
        {
            ids.Add(await SeedCacheAsync($"p{i}", "proxy/" + i.ToString("x").PadLeft(64, 'e'), ambiguous));
        }

        Assert.Equal(7, await Build().RunOnceAsync(batchRows: 3));
        foreach (string id in ids)
        {
            Assert.Equal(1, (await CacheRowAsync(id)).Script);
        }
    }

    [Fact]
    public async Task Rescan_DeletesTheFirstManifestsLicenceRows_OfFlaggedArtefactsOnly()
    {
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        string orgId = await OrgSeeder.InsertAsync(_db, "acme");
        string cacheAmbiguous = await SeedCacheAsync("amb", "proxy/" + new string('a', 64), ambiguous);
        string cacheClean = await SeedCacheAsync("ok", "proxy/" + new string('b', 64), single);
        string verAmbiguous = await SeedUploadedAsync(orgId, "uamb", "uamb/1.0.0/uamb-1.0.0.tgz", ambiguous);
        string verClean = await SeedUploadedAsync(orgId, "uok", "uok/1.0.0/uok-1.0.0.tgz", single);
        foreach (string id in new[] { cacheAmbiguous, cacheClean })
        {
            await SeedLicenceAsync("cache_artifact_id", "cache_artifact", id, "MIT");
        }

        foreach (string id in new[] { verAmbiguous, verClean })
        {
            await SeedLicenceAsync("package_version_id", "package_version", id, "MIT");
        }

        await SeedLicenceAsync("package_version_id", "package_version", verAmbiguous, "Apache-2.0", source: "manual");

        await Build().RunOnceAsync();

        Assert.Empty(await LicencesAsync("cache_artifact_id", cacheAmbiguous));
        Assert.Equal(new[] { "MIT" }, await LicencesAsync("cache_artifact_id", cacheClean));
        Assert.Equal(new[] { "Apache-2.0" }, await LicencesAsync("package_version_id", verAmbiguous));
        Assert.Equal(new[] { "MIT" }, await LicencesAsync("package_version_id", verClean));
    }

    [Fact]
    public async Task Rescan_AmbiguousImportedVersion_LosesUploadedLicence_AndBlockModeGateRefusesIt()
    {
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        string orgId = await OrgSeeder.InsertAsync(_db, "acme");
        await LicensePolicySeeder.AddAllowlistEntryAsync(_db, orgId, "MIT");
        string verAmbiguous = await SeedUploadedAsync(orgId, "uamb", "uamb/1.0.0/uamb-1.0.0.tgz", ambiguous);
        string verClean = await SeedUploadedAsync(orgId, "uok", "uok/1.0.0/uok-1.0.0.tgz", single);
        foreach (string id in new[] { verAmbiguous, verClean })
        {
            await SeedLicenceAsync("package_version_id", "package_version", id, "MIT", source: "uploaded");
        }

        Assert.Equal(BlockDecision.Allowed, await BlockGate().EvaluateAsync(GateRequest(orgId, verAmbiguous)));

        await Build().RunOnceAsync();

        Assert.Empty(await LicencesAsync("package_version_id", verAmbiguous));
        Assert.Equal(BlockDecision.Blocked, await BlockGate().EvaluateAsync(GateRequest(orgId, verAmbiguous)));
        Assert.Equal(new[] { "MIT" }, await LicencesAsync("package_version_id", verClean));
        Assert.Equal(BlockDecision.Allowed, await BlockGate().EvaluateAsync(GateRequest(orgId, verClean)));
    }

    private BlockGateService BlockGate() => new(
        new VulnerabilityRepository(_db, _clock),
        new AuditRepository(_db),
        new QuarantineRepository(_db, _clock),
        new AlertService(new AlertRepository(_db, _clock), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance),
        new InstallScriptAllowlistService(_db, new MemoryCache(new MemoryCacheOptions()), _clock),
        new LicenseRepository(_db, _clock, new LicenseNormalizer(_db, NullLogger<LicenseNormalizer>.Instance)),
        new StubPerOrgTrustAnchorStore(),
        NullLogger<BlockGateService>.Instance,
        _clock,
        new OrgRepository(_db),
        NSubstitute.Substitute.For<Dependably.Infrastructure.Webhooks.IPackageEventSink>(),
        new BlockRefusalWebhookThrottle(_clock, TimeSpan.Zero));

    private static BlockGateRequest GateRequest(string orgId, string versionId) => new BlockGateRequest(
        OrgId: orgId,
        Ecosystem: "npm",
        Purl: "pkg:npm/test@1.0.0",
        VersionId: versionId,
        ManualState: null,
        VulnCheckedAt: null,
        AuditActorId: null,
        MaxOsvScoreTolerance: 10.0,
        SourceIp: null) with
    { LicenseEnforcementMode = "block" };

    [Fact]
    public async Task Rescan_MidStreamReadFailure_DoesNotFlag_WithholdsMarker_ThenRecoversOnRetry()
    {
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        string flakyKey = "proxy/" + new string('a', 64);
        string cleanId = await SeedCacheAsync("flaky", flakyKey, single);
        string ambId = await SeedCacheAsync("zamb", "proxy/" + new string('b', 64), ambiguous);
        var store = new MidStreamFaultBlobStore(_blobs);
        store.FailingKeys.Add(flakyKey);

        Assert.Equal(1, await Build(store).RunOnceAsync());

        Assert.Equal((0, (string?)null, (string?)Stamp), await CacheRowAsync(cleanId));
        Assert.Equal(1, (await CacheRowAsync(ambId)).Script);
        Assert.NotNull(await SettingAsync(NpmManifestRescan.FailKeyPrefix + "cache:" + cleanId));
        Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));

        store.FailingKeys.Clear();
        await Build(store).RunOnceAsync();

        Assert.Equal((0, (string?)null, (string?)Stamp), await CacheRowAsync(cleanId));
        Assert.Null(await SettingAsync(NpmManifestRescan.FailKeyPrefix + "cache:" + cleanId));
        Assert.NotNull(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    [Fact]
    public async Task Rescan_PersistentReadFailure_IsFlaggedUnscannableAfterMaxAttempts_AndMarkerIsWritten()
    {
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        string key = "proxy/" + new string('a', 64);
        string id = await SeedCacheAsync("stuck", key, single);
        await SeedCacheAsync("zz-healthy", "proxy/" + new string('b', 64), single);
        var store = new MidStreamFaultBlobStore(_blobs);
        store.FailingKeys.Add(key);

        for (int run = 1; run < NpmManifestRescan.MaxAttempts; run++)
        {
            await Build(store).RunOnceAsync();
            Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));
        }

        await Build(store).RunOnceAsync();

        Assert.NotNull(await SettingAsync(NpmManifestRescan.MarkerKey));
        Assert.Equal((1, (string?)NpmManifestRescan.UnscannableKind, (string?)null), await CacheRowAsync(id));
        Assert.Null(await SettingAsync(NpmManifestRescan.FailKeyPrefix + "cache:" + id));
    }

    [Fact]
    public async Task Rescan_PerTickCap_ResumesFromPersistedCursor_AndMarksOnlyWhenBothPlanesAreDone()
    {
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        string orgId = await OrgSeeder.InsertAsync(_db, "acme");
        var cacheIds = new List<string>();
        for (int i = 0; i < 5; i++)
        {
            cacheIds.Add(await SeedCacheAsync($"p{i}", "proxy/" + i.ToString("x").PadLeft(64, 'e'), ambiguous));
        }

        string ver = await SeedUploadedAsync(orgId, "uamb", "uamb/1.0.0/uamb-1.0.0.tgz", ambiguous);

        Assert.Equal(2, await Build().RunOnceAsync(batchRows: 2, maxBlobs: 2));
        Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));
        Assert.Equal(2, await CountFlaggedCacheAsync());

        Assert.Equal(2, await Build().RunOnceAsync(batchRows: 2, maxBlobs: 2));
        Assert.Equal(4, await CountFlaggedCacheAsync());

        Assert.Equal(2, await Build().RunOnceAsync(batchRows: 2, maxBlobs: 2));
        Assert.Equal(5, await CountFlaggedCacheAsync());
        Assert.Equal(1, (await VersionRowAsync(ver)).Script);
        Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));

        Assert.Equal(0, await Build().RunOnceAsync(batchRows: 2, maxBlobs: 2));
        Assert.NotNull(await SettingAsync(NpmManifestRescan.MarkerKey));
        Assert.Equal(-1, await Build().RunOnceAsync());
    }

    private async Task<string?> SettingAsync(string key)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleOrDefaultAsync<string>("SELECT value FROM instance_settings WHERE key = @key", new { key });
    }

    private async Task<int> CountFlaggedCacheAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM cache_artifact WHERE has_install_script = 1");
    }

    [Fact]
    public async Task Rescan_StoredOversizedPaxArchive_IsFlaggedUnscannable_OnTheFirstTick()
    {
        string id = await SeedCacheAsync("bigpax", "proxy/" + new string('a', 64), NpmFixtures.BuildTarballWithOversizedPaxHeader(Evil));

        Assert.Equal(1, await Build().RunOnceAsync());

        Assert.Equal((1, (string?)NpmManifestRescan.UnscannableKind, (string?)null), await CacheRowAsync(id));
        Assert.NotNull(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    [Fact]
    public async Task Rescan_StoreOutage_CountsNoAttempts_FlagsNothing_AndResumesWhenHealed()
    {
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        var ids = new List<string>();
        for (int i = 0; i < 6; i++)
        {
            ids.Add(await SeedCacheAsync($"p{i}", "proxy/" + i.ToString("x").PadLeft(64, 'e'), i == 5 ? ambiguous : single));
        }

        var store = new MidStreamFaultBlobStore(_blobs) { ThrowOnEveryRead = true };
        for (int tick = 1; tick <= 4; tick++)
        {
            var log = new RecordingLogger<NpmManifestRescan>();
            Assert.Equal(0, await Build(store, log).RunOnceAsync());

            Assert.Single(log.Warnings, w => w.Message.Contains("blob store unavailable"));
            Assert.Equal(0, await CountFlaggedCacheAsync());
            Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));
            Assert.Null(await SettingAsync(NpmManifestRescan.CursorKeyPrefix + "cache"));
            Assert.Empty(await FailKeysAsync());
        }

        store.ThrowOnEveryRead = false;
        Assert.Equal(1, await Build(store).RunOnceAsync());

        Assert.Equal(1, (await CacheRowAsync(ids[5])).Script);
        Assert.Equal(1, await CountFlaggedCacheAsync());
        Assert.NotNull(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    [Fact]
    public async Task Rescan_SingleOutageWithOneRow_DoesNotCountAnAttempt()
    {
        string key = "proxy/" + new string('a', 64);
        await SeedCacheAsync("solo", key, NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean)));
        var store = new MidStreamFaultBlobStore(_blobs) { ThrowOnEveryRead = true };

        await Build(store).RunOnceAsync();

        Assert.Empty(await FailKeysAsync());
        Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    [Fact]
    public async Task Rescan_OneBlobThatAlwaysThrows_AmongHealthyOnes_IsStillFlaggedAfterMaxAttempts()
    {
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        string badKey = "proxy/" + new string('0', 64);
        string badId = await SeedCacheAsync("a-bad", badKey, single);
        string goodId = await SeedCacheAsync("b-good", "proxy/" + new string('1', 64), single);
        var store = new MidStreamFaultBlobStore(_blobs);
        store.ThrowingKeys.Add(badKey);

        for (int tick = 1; tick <= NpmManifestRescan.MaxAttempts; tick++)
        {
            await Build(store).RunOnceAsync();
        }

        Assert.Equal((1, (string?)NpmManifestRescan.UnscannableKind, (string?)null), await CacheRowAsync(badId));
        Assert.Equal((0, (string?)null, (string?)Stamp), await CacheRowAsync(goodId));
        Assert.NotNull(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    [Fact]
    public async Task Rescan_MixedBatchBelowTheOutageThreshold_CountsTheFailures()
    {
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        var store = new MidStreamFaultBlobStore(_blobs);
        var badIds = new List<string>();
        for (int i = 0; i < 3; i++)
        {
            string key = "proxy/" + i.ToString("x").PadLeft(64, 'a');
            badIds.Add(await SeedCacheAsync($"bad{i}", key, single));
            store.ThrowingKeys.Add(key);
        }

        await SeedCacheAsync("good", "proxy/" + new string('f', 64), single);

        await Build(store).RunOnceAsync();

        foreach (string id in badIds)
        {
            Assert.Equal("1", await SettingAsync(NpmManifestRescan.FailKeyPrefix + "cache:" + id));
        }

        Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    private NpmManifestRescan BuildSplit(IBlobStore cache, IBlobStore registry) =>
        new(_db, new TieredBlobStorage(cache, registry), _clock, NullLogger<NpmManifestRescan>.Instance);

    private async Task SetSettingAsync(string key, string value)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES (@key, @value) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            new { key, value });
    }

    [Fact]
    public async Task Rescan_RetryPhase_RegistryTierOutageWhileCacheAnswers_CountsNoAttemptsAgainstUploadedVersions()
    {
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        string orgId = await OrgSeeder.InsertAsync(_db, "acme");
        await SeedCacheAsync("healthy", "proxy/" + new string('a', 64), single);
        string verId = await SeedUploadedAsync(orgId, "uok", "uok/1.0.0/uok-1.0.0.tgz", single);
        await SeedLicenceAsync("package_version_id", "package_version", verId, "MIT");
        await SetSettingAsync(NpmManifestRescan.CursorKeyPrefix + "cache", "\u0001end");
        await SetSettingAsync(NpmManifestRescan.CursorKeyPrefix + "versions", "\u0001end");
        await SetSettingAsync(NpmManifestRescan.FailKeyPrefix + "versions:" + verId, "1");
        var registry = new MidStreamFaultBlobStore(_blobs) { ThrowOnEveryRead = true };

        for (int tick = 1; tick <= NpmManifestRescan.MaxAttempts + 1; tick++)
        {
            await BuildSplit(_blobs, registry).RunOnceAsync();
        }

        Assert.Equal((0, (string?)null), await VersionRowAsync(verId));
        Assert.Equal(["MIT"], await LicencesAsync("package_version_id", verId));
        Assert.Equal("1", await SettingAsync(NpmManifestRescan.FailKeyPrefix + "versions:" + verId));
        Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));

        registry.ThrowOnEveryRead = false;
        await BuildSplit(_blobs, registry).RunOnceAsync();

        Assert.Equal((0, (string?)null), await VersionRowAsync(verId));
        Assert.Null(await SettingAsync(NpmManifestRescan.FailKeyPrefix + "versions:" + verId));
        Assert.NotNull(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    [Fact]
    public async Task Rescan_SmallTrailingVersionsPage_RegistryTierOutageAfterCacheSuccess_CountsNoAttempt()
    {
        byte[] single = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));
        string orgId = await OrgSeeder.InsertAsync(_db, "acme");
        await SeedCacheAsync("healthy", "proxy/" + new string('a', 64), single);
        string verId = await SeedUploadedAsync(orgId, "uok", "uok/1.0.0/uok-1.0.0.tgz", single);
        var registry = new MidStreamFaultBlobStore(_blobs) { ThrowOnEveryRead = true };

        await BuildSplit(_blobs, registry).RunOnceAsync();

        Assert.Empty(await FailKeysAsync());
        Assert.Null(await SettingAsync(NpmManifestRescan.CursorKeyPrefix + "versions"));
        Assert.Equal((0, (string?)null), await VersionRowAsync(verId));
        Assert.Null(await SettingAsync(NpmManifestRescan.MarkerKey));
    }

    private async Task<List<string>> FailKeysAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<string>(
            "SELECT key FROM instance_settings WHERE substr(key, 1, @len) = @prefix",
            new { len = NpmManifestRescan.FailKeyPrefix.Length, prefix = NpmManifestRescan.FailKeyPrefix })).ToList();
    }
}
