using Dapper;
using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pins <see cref="NuGetFlatContainerHandler.FlatcontainerVersionsAsync"/>'s failure
/// classification against real upstream hosts (two distinct loopback WireMock servers, unlike
/// its sibling <c>NuGetFlatContainerHandlerProxyTests</c> which routes every request through
/// one server): a genuine "every configured upstream confirmed absent (404/410)" outcome with
/// no local row stays a plain 404, but a non-clean upstream failure (5xx, ...) with no local
/// row and no upstream giving a clean answer must surface as
/// <see cref="UpstreamFetchFailedException"/> instead — the exception the pipeline middleware
/// maps to 502/503 rather than the silent, non-retryable 404 that makes <c>dotnet restore</c>
/// report NU1101 for a package that genuinely exists. Multi-upstream fallback (a failure on
/// upstream #1 must not stop upstream #2 from being tried) is pinned alongside the
/// classification.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetFlatContainerHandlerVersionListFailureTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private WireMockServer _serverA = null!;
    private WireMockServer _serverB = null!;
    private string _orgId = null!;

    private OrgRepository _orgs = null!;
    private PackageRepository _packages = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _serverA = WireMockServer.Start();
        _serverB = WireMockServer.Start();

        _orgs = new OrgRepository(_db);
        _packages = new PackageRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "acme-vlist");
        await SetAnonymousPullAsync(true);
    }

    public async Task DisposeAsync()
    {
        _serverA.Stop();
        _serverB.Stop();
        await _db.DisposeAsync();
    }

    private async Task SeedUpstreamsAsync(params string[] urls)
    {
        await using var conn = await _db.OpenAsync();
        int position = 0;
        foreach (string url in urls)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                VALUES (@id, @org, 'nuget', @url, @position)
                """,
                new { id = Guid.NewGuid().ToString("N"), org = _orgId, url, position });
            position++;
        }
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    // Stubs the flatcontainer version-list coordinate the handler builds:
    // {upstream}/flatcontainer/{lower-id}/index.json
    private static void StubVersionList(WireMockServer server, string id, int status, string body)
        => server.Given(Request.Create()
                      .WithPath($"/flatcontainer/{id.ToLowerInvariant()}/index.json").UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(status).WithBody(body).WithHeader("Content-Type", "application/json"));

    [Fact]
    public async Task VersionList_AllUpstreamsConfirmAbsent_NoLocalRow_StaysA404()
    {
        await SeedUpstreamsAsync(_serverA.Urls[0]);
        StubVersionList(_serverA, "missing-pkg", 404, "");

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);
        var result = await handler.FlatcontainerVersionsAsync(http, _orgId, "missing-pkg", CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task VersionList_UpstreamServerError_NoLocalRow_ThrowsTransientUpstreamFetchFailure()
    {
        await SeedUpstreamsAsync(_serverA.Urls[0]);
        StubVersionList(_serverA, "flaky-pkg", 500, "boom");

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(
            () => handler.FlatcontainerVersionsAsync(http, _orgId, "flaky-pkg", CancellationToken.None));

        Assert.True(ex.Transient);
        Assert.False(ex.Refused);
    }

    [Fact]
    public async Task VersionList_FirstUpstreamServerError_SecondUpstreamServes_FallsThroughAndSucceeds()
    {
        // Upstream #1 (higher priority) 500s; upstream #2 answers cleanly. The failure on #1
        // must not stop #2 from being tried, and no exception should propagate.
        await SeedUpstreamsAsync(_serverA.Urls[0], _serverB.Urls[0]);
        StubVersionList(_serverA, "fallback-pkg", 500, "boom");
        StubVersionList(_serverB, "fallback-pkg", 200, """{"versions":["1.0.0","2.0.0"]}""");

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);
        var result = await handler.FlatcontainerVersionsAsync(http, _orgId, "fallback-pkg", CancellationToken.None);

        var json = Assert.IsType<JsonResult>(result);
        var versions = Assert.IsAssignableFrom<IEnumerable<string>>(json.Value!.GetType().GetProperty("versions")!.GetValue(json.Value));
        Assert.Equal(new[] { "1.0.0", "2.0.0" }, versions);
    }

    [Fact]
    public async Task VersionList_LocalRowExists_AllUpstreamsTransientFailure_ServesLocalFallback_NoThrow()
    {
        // A local package row exists (uploaded version). Every configured upstream fails
        // transiently (500) — the caller must still serve the local version list instead of
        // throwing, exactly as it did before this fix (the availability-regression risk this
        // fix must not introduce).
        const string id = "local-fallback-pkg";
        await SeedLocalPackageAsync(id, "9.9.9");
        // A hosted version makes the name implicitly local_only (dependency-confusion guard) —
        // an explicit "mixed" claim is the deliberate operator opt-in back to upstream merging,
        // which is what this scenario needs to reach MergeUpstreamVersionsAsync at all.
        await SeedMixedClaimAsync("nuget", id);
        await SeedUpstreamsAsync(_serverA.Urls[0]);
        StubVersionList(_serverA, id, 500, "boom");

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);
        var result = await handler.FlatcontainerVersionsAsync(http, _orgId, id, CancellationToken.None);

        var json = Assert.IsType<JsonResult>(result);
        var versions = Assert.IsAssignableFrom<IEnumerable<string>>(json.Value!.GetType().GetProperty("versions")!.GetValue(json.Value));
        Assert.Equal(new[] { "9.9.9" }, versions);
        Assert.Equal("error", http.Response.Headers["X-Upstream-Status"].ToString());
    }

    [Fact]
    public async Task VersionList_AllUpstreamsAuthenticatedRefusal_NoLocalRow_ThrowsRefusedUpstreamFetchFailure()
    {
        // A 401 from an upstream this request AUTHENTICATED to is a deterministic auth/policy
        // refusal — non-transient (502, not 503) and never carries a Retry-After.
        await SeedAuthenticatedUpstreamAsync(_serverA.Urls[0], "test-bearer-token");
        StubVersionList(_serverA, "refused-pkg", 401, "");

        var handler = BuildHandler();
        var http = BuildHttpContext(_orgId);

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(
            () => handler.FlatcontainerVersionsAsync(http, _orgId, "refused-pkg", CancellationToken.None));

        Assert.True(ex.Refused);
        Assert.False(ex.Transient);
        Assert.Null(ex.RetryAfter);
    }

    // ── Helpers / wiring (mirrors NuGetFlatContainerHandlerProxyTests.BuildHandler, but with a
    // direct HttpClient — no host-rewriting handler — so two distinct WireMock servers act as
    // genuinely different upstream hosts) ──────────────────────────────────────────────────

    // Seeds an authenticated (bearer) upstream. The stored secret is plaintext (no "enc:v1:"
    // prefix), so EnvelopeProtector.Unprotect passes it through unchanged even under
    // TestEnvelope.Unconfigured() — legacy-plaintext pass-through, not a real encrypted value.
    private async Task SeedAuthenticatedUpstreamAsync(string url, string bearerToken)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, secret)
            VALUES (@id, @org, 'nuget', @url, 0, 'bearer', @secret)
            """,
            new { id = Guid.NewGuid().ToString("N"), org = _orgId, url, secret = bearerToken });
    }

    // Opts a name into upstream merging (mirrors DependablyFactory.SeedMixedClaim). A hosted
    // name is implicitly local_only until an explicit "mixed" claim overrides it — without
    // this, a name with a local version never reaches MergeUpstreamVersionsAsync at all.
    private async Task SeedMixedClaimAsync(string ecosystem, string name)
    {
        var claims = new ClaimRepository(_db);
        await claims.ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString(),
            HistoryId = Guid.NewGuid().ToString(),
            OrgId = _orgId,
            Ecosystem = ecosystem,
            Name = name,
            PriorState = null,
            NewState = ClaimStateMachine.Mixed,
            Reason = "test: opt in to upstream merging",
            OccurredAt = TimeProvider.System.GetUtcNow(),
        });
    }

    // Seeds a local (uploaded) package version so the flatcontainer version list has a local
    // fallback to serve when every configured upstream fails.
    private async Task SeedLocalPackageAsync(string id, string version)
    {
        string normalizedId = id.ToLowerInvariant();
        string pkgId = $"pkg-{normalizedId}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@pkgId, @org, 'nuget', @id, @normalizedId, 0)
            """,
            new { pkgId, org = _orgId, id, normalizedId });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, filename, created_at)
            VALUES (@verId, @pkgId, @version, @purl, @blobKey, 'uploaded', @filename, @ts)
            """,
            new
            {
                verId = $"ver-{normalizedId}",
                pkgId,
                version,
                purl = $"pkg:nuget/{normalizedId}@{version}",
                blobKey = $"registry/{normalizedId}.{version}.nupkg",
                filename = $"{normalizedId}.{version}.nupkg",
                ts = TimeProvider.System.GetUtcNow().ToUtcIso(),
            });
    }

    private NuGetFlatContainerHandler BuildHandler()
    {
        var httpFactory = new StaticHttpClientFactory(new HttpClient());
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-nuget-vlisttest-{Guid.NewGuid():N}"),
            })
            .Build();
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var osv = TestOsvSource.Create();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config, new StubAirGapMode(),
            NullLogger<VulnerabilityScanService>.Instance, TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, TimeProvider.System)));

        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var blockGate = TestBlockGate.Create(_db, TimeProvider.System);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess, NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate,
            _audit, TimeProvider.System,
            new SourcePinRepository(_db, new ConfigurationBuilder().Build()));

        var allowlist = new AllowlistService(_db, _audit);
        var blocklist = new BlocklistRepository(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var claimResolver = new ClaimResolver(new ClaimRepository(_db), new StubAirGapMode());
        var reserved = new ReservedNamespaceService(
            _db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured()));
        var inventory = new ArtifactInventoryRepository(_db, _packages, cacheArtifact, vulns);
        var provenance = new NuGetProvenanceVerifier(
            new NuGetSignatureTrustStore(new StubPerOrgTrustAnchorStore()),
            NullLogger<NuGetProvenanceVerifier>.Instance);

        return new NuGetFlatContainerHandler(
            _orgs, _packages, cacheArtifact, tenantAccess, _tokens, _audit,
            tiered.Cache, upstreamClient, registries, allowlist, blocklist,
            blockGate, vulns, inventory, claimResolver, reserved, proxyFetch, provenance,
            TimeProvider.System, NullLogger<NuGetFlatContainerHandler>.Instance);
    }

    private static DefaultHttpContext BuildHttpContext(string orgId)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "acme-vlist");
        return http;
    }

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }
}
