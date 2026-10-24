using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// The deprecation refresh selects and refreshes Hex groups like the other supported
/// ecosystems: a stale cached Hex group and a hosted-only Hex package are enumerated, the signed
/// upstream package resource is read with the upstream's configured public key, a retirement is
/// recorded as the version's deprecation, and the upstream latest and versions-behind are written.
/// An upstream answer that cannot be verified records nothing, and a reserved Hex name makes no
/// upstream request.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshHexTests : IAsyncLifetime
{
    private const string UpstreamUrl = "http://upstream.test";
    private static readonly DateTimeOffset Epoch = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly HexRetirementStatus SecurityRetirement = new(HexRetirementReason.Security, "CVE-2026-9");

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly RSA _upstreamKey = RSA.Create(2048);
    private ReservedNamespaceService _reserved = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _reserved = new ReservedNamespaceService(_db, new MemoryCache(new MemoryCacheOptions()), _clock);
    }

    public async Task DisposeAsync()
    {
        _upstreamKey.Dispose();
        await _db.DisposeAsync();
    }

    // ── Selection ───────────────────────────────────────────────────────────────

    public static TheoryData<string> RefreshedEcosystems()
    {
        var data = new TheoryData<string>();
        foreach (string ecosystem in DeprecationRefreshEcosystems.All)
        {
            data.Add(ecosystem);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(RefreshedEcosystems))]
    public async Task EveryRefreshedEcosystem_IsSelectedByBothEnumerations(string ecosystem)
    {
        // Pins the SQL ecosystem lists to DeprecationRefreshEcosystems: adding an ecosystem to
        // the set without adding it to either query fails here.
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedCachedAsync(orgId, ecosystem, "cached-pkg", "1.0.0");
        await SeedHostedOnlyAsync(orgId, ecosystem, "hosted-pkg", "1.0.0");

        var cacheGroups = await new CacheArtifactRepository(_db)
            .ListGroupsNeedingDeprecationRefreshAsync(24, 100, _clock);
        var hostedGroups = await new PackageRepository(_db, time: _clock)
            .ListHostedGroupsNeedingUpstreamRefreshAsync(24, 100, _clock);

        Assert.Contains((ecosystem, "cached-pkg", orgId), cacheGroups);
        Assert.Contains((ecosystem, "hosted-pkg", orgId), hostedGroups);
    }

    [Theory]
    [InlineData("golang")]
    [InlineData("cargo")]
    public async Task UnrefreshedEcosystem_IsSelectedByNeitherEnumeration(string ecosystem)
    {
        Assert.False(DeprecationRefreshEcosystems.Contains(ecosystem));
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        await SeedCachedAsync(orgId, ecosystem, "cached-pkg", "1.0.0");
        await SeedHostedOnlyAsync(orgId, ecosystem, "hosted-pkg", "1.0.0");

        Assert.Empty(await new CacheArtifactRepository(_db).ListGroupsNeedingDeprecationRefreshAsync(24, 100, _clock));
        Assert.Empty(await new PackageRepository(_db, time: _clock).ListHostedGroupsNeedingUpstreamRefreshAsync(24, 100, _clock));
    }

    // ── Refresh pass ────────────────────────────────────────────────────────────

    [Fact]
    public async Task CachedHexGroup_RecordsRetirement_LatestAndVersionsBehind()
    {
        string orgId = await SeedOrgAsync(withKey: true);
        string packageId = await SeedPackageRowAsync(orgId, "jason", upstreamLatestCheckedAt: null);
        string retiredId = await SeedCacheArtifactAsync(orgId, "jason", "1.1.0");
        string currentId = await SeedCacheArtifactAsync(orgId, "jason", "1.0.0");

        var handler = new HexUpstream();
        handler.Serve("jason", _upstreamKey);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal($"{UpstreamUrl}/packages/jason", Assert.Single(handler.Urls));
        await using var conn = await _db.OpenAsync();
        var (latest, latestPublishedAt) = await conn.QuerySingleAsync<(string? Latest, string? PublishedAt)>(
            "SELECT upstream_latest_version, upstream_latest_published_at FROM packages WHERE id = @id",
            new { id = packageId });
        Assert.Equal("1.2.0", latest);
        Assert.Equal("2025-06-05T00:00:00.000000Z", latestPublishedAt);

        var (retiredDeprecated, retiredCheckedAt, retiredBehind) = await ReadCacheRowAsync(conn, retiredId);
        Assert.Equal(HexIndexBuilder.RetirementAsDeprecation(SecurityRetirement), retiredDeprecated);
        Assert.StartsWith("retired:", retiredDeprecated, StringComparison.Ordinal);
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), retiredCheckedAt);
        // A retired release is never counted as a newer stable: 1.1.0 is behind 1.2.0 only.
        Assert.Equal(1, retiredBehind);

        var (currentDeprecated, currentCheckedAt, currentBehind) = await ReadCacheRowAsync(conn, currentId);
        Assert.Null(currentDeprecated);
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), currentCheckedAt);
        Assert.Equal(1, currentBehind);

        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), await conn.QuerySingleAsync<string?>(
            "SELECT MIN(refresh_checked_at) FROM tenant_artifact_access WHERE org_id = @orgId", new { orgId }));

        // The retirement also lands where this registry's own signed index reads it, in the same
        // shape the first fetch writes, so Mix and Rebar3 see it.
        Assert.Equal(("security", "CVE-2026-9"), await ReadHexRetirementAsync(retiredId));
        Assert.Equal((null, null), await ReadHexRetirementAsync(currentId));
        Assert.Equal(SecurityRetirement, (await AdvertisedHeldReleaseAsync(orgId, "jason", "1.1.0")).Retired);
        Assert.Null((await AdvertisedHeldReleaseAsync(orgId, "jason", "1.0.0")).Retired);
    }

    [Fact]
    public async Task CachedHexGroup_UnretiredUpstream_ClearsTheRecordedRetirement()
    {
        string orgId = await SeedOrgAsync(withKey: true);
        await SeedPackageRowAsync(orgId, "jason", upstreamLatestCheckedAt: null);
        string caId = await SeedCacheArtifactAsync(orgId, "jason", "1.1.0", retired: SecurityRetirement);
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE cache_artifact SET deprecated = @deprecated WHERE id = @id",
                new { id = caId, deprecated = HexIndexBuilder.RetirementAsDeprecation(SecurityRetirement) });
        }

        var handler = new HexUpstream();
        handler.Serve("jason", _upstreamKey, retire: false);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        var (deprecated, checkedAt, versionsBehind) = await ReadCacheRowAsync(conn, caId);
        Assert.Null(deprecated);
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), checkedAt);
        Assert.Equal(1, versionsBehind);
        Assert.Equal((null, null), await ReadHexRetirementAsync(caId));
        Assert.Null((await AdvertisedHeldReleaseAsync(orgId, "jason", "1.1.0")).Retired);
    }

    [Fact]
    public async Task HostedOnlyHexPackage_IsRefreshed()
    {
        string orgId = await SeedOrgAsync(withKey: true);
        var (packageId, versionId) = await SeedHostedOnlyAsync(orgId, "hex", "plug_internal", "1.0.0");

        var handler = new HexUpstream();
        handler.Serve("plug_internal", _upstreamKey);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal($"{UpstreamUrl}/packages/plug_internal", Assert.Single(handler.Urls));
        await using var conn = await _db.OpenAsync();
        var (latest, checkedAt) = await conn.QuerySingleAsync<(string? Latest, string? CheckedAt)>(
            "SELECT upstream_latest_version, upstream_latest_checked_at FROM packages WHERE id = @id",
            new { id = packageId });
        Assert.Equal("1.2.0", latest);
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), checkedAt);
        Assert.Equal(1, await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM package_versions WHERE id = @id", new { id = versionId }));
    }

    [Fact]
    public async Task ReservedHexName_MakesNoRequest_AndRecordsNoUpstreamFact()
    {
        string orgId = await SeedOrgAsync(withKey: true);
        string packageId = await SeedPackageRowAsync(orgId, "acme_internal", upstreamLatestCheckedAt: null);
        string caId = await SeedCacheArtifactAsync(orgId, "acme_internal", "1.0.0");
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE packages SET upstream_latest_version = '9.9.9' WHERE id = @id", new { id = packageId });
            await seed.ExecuteAsync(
                "UPDATE cache_artifact SET versions_behind = 4, deprecated = 'old notice' WHERE id = @id", new { id = caId });
        }
        await _reserved.AddAsync(orgId, "hex", "acme_*", createdBy: null);

        var handler = new HexUpstream();
        handler.Serve("acme_internal", _upstreamKey);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Empty(handler.Urls);
        await using var conn = await _db.OpenAsync();
        Assert.Null(await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId }));
        var (rowDeprecated, rowCheckedAt, rowBehind) = await ReadCacheRowAsync(conn, caId);
        Assert.Equal("old notice", rowDeprecated);
        Assert.Equal(4, rowBehind);
        Assert.Null(rowCheckedAt);
    }

    [Fact]
    public async Task UpstreamWithoutPublicKey_IsNotRead_AndRecordedRetirementIsKept()
    {
        string orgId = await SeedOrgAsync(withKey: false);
        string packageId = await SeedPackageRowAsync(orgId, "jason", upstreamLatestCheckedAt: null);
        string caId = await SeedCacheArtifactAsync(orgId, "jason", "1.1.0", retired: SecurityRetirement);
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE packages SET upstream_latest_version = '1.2.0' WHERE id = @id", new { id = packageId });
            await seed.ExecuteAsync(
                "UPDATE cache_artifact SET versions_behind = 1, deprecated = 'retired: security' WHERE id = @id", new { id = caId });
        }

        var handler = new HexUpstream();
        handler.Serve("jason", _upstreamKey);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Empty(handler.Urls);
        await AssertUntouchedAsync(orgId, packageId, caId, "1.2.0", "retired: security", 1);
    }

    [Fact]
    public async Task NoUpstreamListsThePackage_RecordsNothing_AndRecordedRetirementIsKept()
    {
        // Every keyed upstream answers 404: no verified answer, so the recorded retirement and
        // latest stay as they were and the group still yields its slot.
        string orgId = await SeedOrgAsync(withKey: true);
        string packageId = await SeedPackageRowAsync(orgId, "jason", upstreamLatestCheckedAt: null);
        string caId = await SeedCacheArtifactAsync(orgId, "jason", "1.1.0", retired: SecurityRetirement);
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE packages SET upstream_latest_version = '1.2.0' WHERE id = @id", new { id = packageId });
            await seed.ExecuteAsync(
                "UPDATE cache_artifact SET versions_behind = 1, deprecated = 'retired: security' WHERE id = @id", new { id = caId });
        }

        var handler = new HexUpstream();
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal($"{UpstreamUrl}/packages/jason", Assert.Single(handler.Urls));
        await AssertUntouchedAsync(orgId, packageId, caId, "1.2.0", "retired: security", 1);
    }

    [Fact]
    public async Task MixedPass_UnverifiableResourceRecordsNothing_VerifiedOneIsRecorded()
    {
        // Two Hex groups in one pass: one upstream answer is signed by a key other than the
        // configured one, the other verifies. The forged answer neither clears the recorded
        // retirement nor stops the verified group from being refreshed.
        string orgId = await SeedOrgAsync(withKey: true);
        string forgedPkg = await SeedPackageRowAsync(orgId, "forged", upstreamLatestCheckedAt: null);
        string forgedCa = await SeedCacheArtifactAsync(orgId, "forged", "1.1.0", retired: SecurityRetirement);
        string goodPkg = await SeedPackageRowAsync(orgId, "jason", upstreamLatestCheckedAt: null);
        string goodCa = await SeedCacheArtifactAsync(orgId, "jason", "1.1.0");
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "UPDATE packages SET upstream_latest_version = '1.2.0' WHERE id = @id", new { id = forgedPkg });
            await seed.ExecuteAsync(
                "UPDATE cache_artifact SET versions_behind = 1, deprecated = 'retired: security' WHERE id = @id", new { id = forgedCa });
        }

        using var otherKey = RSA.Create(2048);
        var handler = new HexUpstream();
        handler.Serve("forged", otherKey, retire: false);
        handler.Serve("jason", _upstreamKey);
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(2, handler.Urls.Count);
        await AssertUntouchedAsync(orgId, forgedPkg, forgedCa, "1.2.0", "retired: security", 1);
        await using var conn = await _db.OpenAsync();
        Assert.Equal("1.2.0", await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = goodPkg }));
        Assert.Equal(HexIndexBuilder.RetirementAsDeprecation(SecurityRetirement), (await ReadCacheRowAsync(conn, goodCa)).Deprecated);
        Assert.Equal(("security", "CVE-2026-9"), await ReadHexRetirementAsync(goodCa));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private async Task AssertUntouchedAsync(
        string orgId, string packageId, string caId, string latest, string deprecated, int versionsBehind)
    {
        await using var conn = await _db.OpenAsync();
        Assert.Equal(latest, await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE id = @id", new { id = packageId }));
        var (rowDeprecated, rowCheckedAt, rowBehind) = await ReadCacheRowAsync(conn, caId);
        Assert.Equal(deprecated, rowDeprecated);
        Assert.Equal(versionsBehind, rowBehind);
        Assert.Null(rowCheckedAt);
        Assert.Equal(("security", "CVE-2026-9"), await ReadHexRetirementAsync(caId));
        // The group still yields its slot, so it cannot hold the head of the queue.
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), await conn.QuerySingleAsync<string?>(
            "SELECT refresh_checked_at FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId, caId }));
    }

    private static Task<(string? Deprecated, string? CheckedAt, int? VersionsBehind)> ReadCacheRowAsync(
        System.Data.Common.DbConnection conn, string id) =>
        conn.QuerySingleAsync<(string? Deprecated, string? CheckedAt, int? VersionsBehind)>(
            "SELECT deprecated, deprecation_checked_at, versions_behind FROM cache_artifact WHERE id = @id",
            new { id });

    private async Task<string> SeedOrgAsync(bool withKey)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry(
            "hex", UpstreamUrl, PublicKeyPem: withKey ? HexRegistrySigner.ExportPublicKeyPem(_upstreamKey) : null));
        return orgId;
    }

    private async Task<string> SeedPackageRowAsync(
        string orgId, string name, string? upstreamLatestCheckedAt, string ecosystem = "hex")
    {
        string packageId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, upstream_latest_checked_at)
            VALUES (@id, @orgId, @ecosystem, @name, @name, 1, @upstreamLatestCheckedAt)
            """,
            new { id = packageId, orgId, ecosystem, name, upstreamLatestCheckedAt });
        return packageId;
    }

    // A Hex row also gets the hex_release row the first fetch writes beside it, carrying
    // <paramref name="retired"/> as its recorded retirement.
    private async Task<string> SeedCacheArtifactAsync(
        string orgId, string name, string version, string ecosystem = "hex", HexRetirementStatus? retired = null)
    {
        string caId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, @contentHash, @purl)
            """,
            new
            {
                id = caId,
                ecosystem,
                name,
                version,
                filename = $"{name}-{version}.tar",
                blobKey = $"proxy/{caId}/{name}-{version}.tar",
                contentHash = new string('a', 64),
                purl = $"pkg:{ecosystem}/{name}@{version}",
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        if (ecosystem == "hex")
        {
            await new HexReleaseRepository(_db).UpsertCachedAsync(caId, new HexReleaseFacts(
                new string('b', 64), [], name, ["mix"], null, retired?.Reason, retired?.Message, false, null));
        }

        return caId;
    }

    private async Task<(string? Reason, string? Message)> ReadHexRetirementAsync(string caId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(string? Reason, string? Message)>(
            "SELECT retired_reason, retired_message FROM hex_release WHERE owner_kind = 'cache_artifact' AND cache_artifact_id = @caId",
            new { caId });
    }

    // The org's own /packages/NAME resource as the read plane builds it from what the org holds
    // (no upstream answer merged in, nothing blocked), so a held release's advertised retirement
    // is exactly what hex_release records.
    private async Task<HexRelease> AdvertisedHeldReleaseAsync(string orgId, string name, string version)
    {
        var held = await new HexReleaseRepository(_db).ListForPackageAsync(orgId, name);
        var package = HexIndexBuilder.BuildPackage(
            name, held, upstream: null, new HashSet<string>(), [], new BlockPolicy(), _clock.GetUtcNow());
        var decoded = HexRegistryCodec.DecodePackage(HexRegistryCodec.EncodePackage(package));
        return Assert.Single(decoded.Releases, r => r.Version == version);
    }

    private async Task SeedCachedAsync(string orgId, string ecosystem, string name, string version)
    {
        await SeedPackageRowAsync(orgId, name, upstreamLatestCheckedAt: null, ecosystem);
        await SeedCacheArtifactAsync(orgId, name, version, ecosystem);
    }

    // A package proxied once (so its upstream_latest_checked_at is set, and stale) whose proxy
    // rows are gone, leaving one hosted version.
    private async Task<(string PackageId, string VersionId)> SeedHostedOnlyAsync(
        string orgId, string ecosystem, string name, string version)
    {
        string packageId = await SeedPackageRowAsync(
            orgId, name, upstreamLatestCheckedAt: _clock.GetUtcNow().AddDays(-30).ToUtcIso(), ecosystem);
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin)
            VALUES (@id, @packageId, @version, @purl, @blobKey, 'uploaded')
            """,
            new { id = versionId, packageId, version, purl = $"pkg:{ecosystem}/{name}@{version}", blobKey = $"blobs/{versionId}" });
        return (packageId, versionId);
    }

    private DeprecationRefreshService BuildService(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-refresh-hex-{Guid.NewGuid():N}"),
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = "100",
            })
            .Build();
        var blobs = new InMemoryBlobStore();
        var urlValidator = Substitute.For<IUpstreamUrlValidator>();
        urlValidator.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(UpstreamUrlBlock.None));
        var airGap = Substitute.For<IAirGapMode>();
        var upstream = new UpstreamClient(
            new SingleHandlerFactory(handler), new TieredBlobStorage(blobs, blobs), new AuditRepository(_db),
            urlValidator, airGap, new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        return new DeprecationRefreshService(
            new PackageRepository(_db, time: _clock), new CacheArtifactRepository(_db), new AuditRepository(_db),
            upstream, new UpstreamLatestVersionResolver(upstream, registries, _reserved), registries, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock), _reserved, new Dependably.Infrastructure.Hex.HexReleaseRepository(_db));
    }

    /// <summary>
    /// Serves signed Hex <c>/packages/NAME</c> resources and records every outbound request URL.
    /// Each package lists 1.0.0, 1.1.0 (retired for security unless <c>retire</c> is false),
    /// a 2.0.0 pre-release, and 1.2.0 — so the latest stable, non-retired release is 1.2.0.
    /// </summary>
    private sealed class HexUpstream : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _resources = new(StringComparer.Ordinal);

        public List<string> Urls { get; } = [];

        public void Serve(string name, RSA signingKey, bool retire = true)
        {
            static HexRelease Release(string v, int day, HexRetirementStatus? retired = null) =>
                new(v, new byte[32], Array.Empty<HexDependency>(), retired, new byte[32], null,
                    HexTimestamp.FromDateTimeOffset(Epoch.AddDays(day)));
            var package = new HexPackage(name, "upstream-repo", new[]
            {
                Release("1.0.0", 1),
                Release("1.1.0", 2, retire ? SecurityRetirement : null),
                Release("2.0.0-rc.1", 3),
                Release("1.2.0", 4),
            }, Array.Empty<HexSecurityAdvisory>());
            _resources[$"/packages/{name}"] = HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), signingKey);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (Urls)
            {
                Urls.Add(request.RequestUri!.ToString());
            }

            return Task.FromResult(_resources.TryGetValue(request.RequestUri!.AbsolutePath, out byte[]? body)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }
}
