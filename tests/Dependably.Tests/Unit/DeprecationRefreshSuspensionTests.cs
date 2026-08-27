using System.Net;
using System.Text;
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
/// A suspended/archived/deleting org's proxy groups are excluded from
/// <see cref="DeprecationRefreshService"/>'s group enumeration (see TenantLifecycle) — the pass
/// otherwise fetches the npm packument / PyPI project JSON on the org's behalf, exactly the
/// tenant-facing egress the suspension is meant to stop.
///
/// Every mixed-pass assertion pairs the negative probe (no upstream request naming the non-active
/// org's package is ever made, and its row stays unstamped) with its adversarial twin (an active
/// org's group in the SAME pass is still fetched and stamped).
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeprecationRefreshSuspensionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // Seeds an org, an upstream registry, and one npm proxy group (cache_artifact +
    // tenant_artifact_access) named after the org so a request URL can be attributed back to it.
    private async Task SeedOrgWithProxyGroupAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)",
            new { orgId, status });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        string name = "pkg-" + orgId;
        string caId = orgId + "-ca";
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES (@id, 'npm', @name, '1.0.0', @filename, @blobKey, 'h', @purl)
            """,
            new
            {
                id = caId,
                name,
                filename = name + "-1.0.0.tgz",
                blobKey = "proxy/" + caId + "/" + name + "-1.0.0.tgz",
                purl = $"pkg:npm/{name}@1.0.0",
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });

        var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry("npm", "http://npm.test"));
    }

    private async Task<string?> DeprecationCheckedAtAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT deprecation_checked_at FROM cache_artifact WHERE id = @id",
            new { id = orgId + "-ca" });
    }

    // Seeds an org, an upstream registry, and a HOSTED-ONLY package: a packages row with a stale
    // upstream_latest_checked_at, an uploaded package_versions row under it, and deliberately NO
    // cache_artifact/tenant_artifact_access rows — the second, hosted-only enumeration
    // (PackageRepository.ListHostedGroupsNeedingUpstreamRefreshAsync) that a package which was
    // never proxied (or whose proxy rows were evicted) is picked up through, distinct from the
    // cache-plane query SeedOrgWithProxyGroupAsync exercises.
    private async Task SeedOrgWithHostedOnlyGroupAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)",
            new { orgId, status });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });

        string name = "hosted-pkg-" + orgId;
        string packageId = orgId + "-pkg";
        string staleCheckedAt = _clock.GetUtcNow().AddHours(-48).ToUtcIso();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, upstream_latest_checked_at)
            VALUES (@id, @orgId, 'npm', @name, @name, @staleCheckedAt)
            """,
            new { id = packageId, orgId, name, staleCheckedAt });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin)
            VALUES (@id, @packageId, '1.0.0', @purl, @blobKey, 'uploaded')
            """,
            new
            {
                id = orgId + "-v1",
                packageId,
                purl = $"pkg:npm/{name}@1.0.0",
                blobKey = "hosted/" + orgId + "/npm/" + name + "/1.0.0/pkg.tgz",
            });

        var registries = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await registries.AddAsync(orgId, new NewUpstreamRegistry("npm", "http://npm.test"));
    }

    private async Task<string?> UpstreamLatestCheckedAtAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT upstream_latest_checked_at FROM packages WHERE id = @id",
            new { id = orgId + "-pkg" });
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task RefreshPass_NeverFetchesUpstreamFor_ANonActiveOrgsGroup_ButStillFetchesAnActiveOrgInTheSamePass(
        string nonActiveStatus)
    {
        await SeedOrgWithProxyGroupAsync("locked", nonActiveStatus);
        await SeedOrgWithProxyGroupAsync("live", "active");

        var handler = new RecordingUrlHandler();
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        // Negative probe: no request naming the non-active org's package, and its row is never
        // stamped (it stays selectable by the next pass rather than reading as "checked").
        Assert.DoesNotContain(handler.RequestedUrls, u => u.Contains("pkg-locked", StringComparison.Ordinal));
        Assert.Null(await DeprecationCheckedAtAsync("locked"));

        // Adversarial twin, same pass: the active org's group IS fetched and stamped.
        Assert.Contains(handler.RequestedUrls, u => u.Contains("pkg-live", StringComparison.Ordinal));
        Assert.NotNull(await DeprecationCheckedAtAsync("live"));
    }

    /// <summary>
    /// The hosted-plane twin of <see cref="RefreshPass_NeverFetchesUpstreamFor_ANonActiveOrgsGroup_ButStillFetchesAnActiveOrgInTheSamePass"/>.
    /// That test only ever exercises <c>CacheArtifactRepository.ListGroupsNeedingDeprecationRefreshAsync</c>
    /// (the cache-plane query); a package that was never proxied (or whose proxy rows were
    /// evicted) is picked up instead through <c>PackageRepository.ListHostedGroupsNeedingUpstreamRefreshAsync</c>,
    /// a second, independent query with its own <c>o.status = 'active'</c> predicate. A regression
    /// in that second predicate alone — the exact gap a prior version of this test suite left open
    /// — would pass every other test in this file while still fetching upstream metadata for a
    /// suspended org's hosted-only package.
    /// </summary>
    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task RefreshPass_NeverFetchesUpstreamFor_ANonActiveOrgsHostedOnlyPackage_ButStillFetchesAnActiveOrgInTheSamePass(
        string nonActiveStatus)
    {
        await SeedOrgWithHostedOnlyGroupAsync("hlocked", nonActiveStatus);
        await SeedOrgWithHostedOnlyGroupAsync("hlive", "active");
        string seededStaleStamp = _clock.GetUtcNow().AddHours(-48).ToUtcIso();

        var handler = new RecordingUrlHandler();
        await BuildService(handler).RunRefreshPassAsync(CancellationToken.None);

        // Negative probe: no request naming the non-active org's hosted-only package, and its
        // upstream_latest_checked_at stamp is left exactly as seeded — still stale, never
        // advanced to "now" the way a processed group's would be.
        Assert.DoesNotContain(handler.RequestedUrls, u => u.Contains("hosted-pkg-hlocked", StringComparison.Ordinal));
        Assert.Equal(seededStaleStamp, await UpstreamLatestCheckedAtAsync("hlocked"));

        // Adversarial twin, same pass: the active org's hosted-only package IS fetched and its
        // stamp advances past the stale value it was seeded with.
        Assert.Contains(handler.RequestedUrls, u => u.Contains("hosted-pkg-hlive", StringComparison.Ordinal));
        Assert.NotEqual(seededStaleStamp, await UpstreamLatestCheckedAtAsync("hlive"));
    }

    [Fact]
    public async Task RefreshPass_ResumesFetching_OnceTheOrgIsReinstated()
    {
        await SeedOrgWithProxyGroupAsync("reinstated", "suspended");

        var handler = new RecordingUrlHandler();
        var svc = BuildService(handler);
        await svc.RunRefreshPassAsync(CancellationToken.None);
        Assert.Empty(handler.RequestedUrls);
        Assert.Null(await DeprecationCheckedAtAsync("reinstated"));

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE orgs SET status = 'active' WHERE id = 'reinstated'");
        }

        await svc.RunRefreshPassAsync(CancellationToken.None);
        Assert.Contains(handler.RequestedUrls, u => u.Contains("pkg-reinstated", StringComparison.Ordinal));
        Assert.NotNull(await DeprecationCheckedAtAsync("reinstated"));
    }

    private DeprecationRefreshService BuildService(HttpMessageHandler handler)
    {
        var factory = new SingleHandlerFactory(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        var audit = new AuditRepository(_db);
        var validator = new AllowAllValidator();
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dep-refresh-susp-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = stagingDir,
                ["DEPRECATION_REFRESH_BATCH_DELAY_MS"] = "0",
                ["DEPRECATION_REFRESH_AGE_HOURS"] = "24",
                ["DEPRECATION_REFRESH_BATCH_SIZE"] = "100",
            })
            .Build();
        var airGap = new StubAirGap();
        var upstream = new UpstreamClient(
            factory, tiered, new AuditRepository(_db), validator, airGap,
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        var packages = new PackageRepository(_db, time: _clock);
        var cacheArtifacts = new CacheArtifactRepository(_db);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        var latestResolver = new UpstreamLatestVersionResolver(upstream, registries);
        return new DeprecationRefreshService(
            packages, cacheArtifacts, audit, upstream, latestResolver, registries, airGap, config,
            NullLogger<DeprecationRefreshService>.Instance,
            _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>Records every request URL, so a test can assert an org's package was never sent
    /// upstream at all — not merely that its stamp is absent.</summary>
    private sealed class RecordingUrlHandler : HttpMessageHandler
    {
        public List<string> RequestedUrls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            RequestedUrls.Add(request.RequestUri!.ToString());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}""",
                    Encoding.UTF8, "application/json")
            });
        }
    }

    private sealed class SingleHandlerFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerFactory(HttpMessageHandler h) => _client = new HttpClient(h);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
