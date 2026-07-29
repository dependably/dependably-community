using Dapper;
using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pins the registration-index proxy path's failure classification: a genuine "every
/// configured upstream confirmed absent (404/410)" outcome with no local row stays a plain
/// 404, but a non-clean upstream failure (5xx, connection refusal, ...) with no local row and
/// no upstream giving a clean answer must surface as <see cref="UpstreamFetchFailedException"/>
/// instead — the exception the pipeline middleware maps to 502/503 rather than the silent,
/// non-retryable 404 that makes <c>dotnet restore</c> report NU1101 for a package that
/// genuinely exists. Multi-upstream fallback (a failure on upstream #1 must not stop upstream
/// #2 from being tried) is pinned alongside the failure classification.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetRegistrationHandlerProxyFailureTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private WireMockServer _serverA = null!;
    private WireMockServer _serverB = null!;
    private string _orgId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _serverA = WireMockServer.Start();
        _serverB = WireMockServer.Start();
        _orgId = await OrgSeeder.InsertAsync(_db, "nuget-proxy-failure-org");
        await SetAnonymousPullAsync(true);
    }

    public async Task DisposeAsync()
    {
        _serverA.Stop();
        _serverB.Stop();
        await _db.DisposeAsync();
    }

    [Fact]
    public async Task RegistrationIndex_AllUpstreamsConfirmAbsent_NoLocalRow_StaysA404()
    {
        await SeedUpstreamsAsync(_serverA.Urls[0]);
        StubIndex(_serverA, "missing-pkg", 404, "");

        var handler = BuildHandler();
        var http = BuildContext();
        var result = await handler.RegistrationIndexAsync(http, _orgId, "missing-pkg", semVer2: false, CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task RegistrationIndex_UpstreamServerError_NoLocalRow_ThrowsTransientUpstreamFetchFailure()
    {
        await SeedUpstreamsAsync(_serverA.Urls[0]);
        StubIndex(_serverA, "flaky-pkg", 500, "boom");

        var handler = BuildHandler();
        var http = BuildContext();

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(
            () => handler.RegistrationIndexAsync(http, _orgId, "flaky-pkg", semVer2: false, CancellationToken.None));

        Assert.True(ex.Transient);
        Assert.False(ex.Refused);
    }

    [Fact]
    public async Task RegistrationIndex_FirstUpstreamServerError_SecondUpstreamServes_FallsThroughAndSucceeds()
    {
        // Upstream #1 (higher priority) 500s; upstream #2 answers cleanly. The failure on #1
        // must not stop #2 from being tried, and no exception should propagate. The body must
        // actually come from upstream #2's response — a regression that returns upstream #1's
        // (failed) data or an empty document must not silently pass.
        await SeedUpstreamsAsync(_serverA.Urls[0], _serverB.Urls[0]);
        StubIndex(_serverA, "fallback-pkg", 500, "boom");
        StubIndex(_serverB, "fallback-pkg", 200, """
            {"count":1,"items":[{"count":1,"items":[
            {"@id":"x","catalogEntry":{"id":"fallback-pkg","version":"9.9.9-from-upstream-b","listed":true}}
            ]}]}
            """);

        var handler = BuildHandler();
        var http = BuildContext();
        var result = await handler.RegistrationIndexAsync(http, _orgId, "fallback-pkg", semVer2: false, CancellationToken.None);

        var fileResult = Assert.IsType<FileContentResult>(result);
        string body = System.Text.Encoding.UTF8.GetString(fileResult.FileContents);
        Assert.Contains("9.9.9-from-upstream-b", body);
    }

    [Fact]
    public async Task RegistrationIndex_LocalRowExists_AllUpstreamsTransientFailure_ServesLocalFallback_NoThrow()
    {
        // A local package row exists (uploaded version). Every configured upstream fails
        // transiently (500) — the caller must fall back to serving the local-only registration
        // instead of throwing, exactly as it did before this fix (the availability-regression
        // risk this fix must not introduce).
        const string id = "local-fallback-pkg";
        await SeedLocalPackageAsync(id, "9.9.9");
        // A hosted version makes the name implicitly local_only (dependency-confusion guard) —
        // an explicit "mixed" claim is the deliberate operator opt-in back to upstream merging,
        // which is what this scenario needs to reach the proxy-merge path at all.
        await SeedMixedClaimAsync("nuget", id);
        await SeedUpstreamsAsync(_serverA.Urls[0]);
        StubIndex(_serverA, id, 500, "boom");

        var handler = BuildHandler();
        var http = BuildContext();
        var result = await handler.RegistrationIndexAsync(http, _orgId, id, semVer2: false, CancellationToken.None);

        var fileResult = Assert.IsType<FileContentResult>(result);
        string body = System.Text.Encoding.UTF8.GetString(fileResult.FileContents);
        Assert.Contains("9.9.9", body);
        // upstreamReached=false on the local fallback path confirms this went through the
        // failed-upstream branch, not a cache hit or a genuine upstream success.
        Assert.Equal("error", http.Response.Headers["X-Upstream-Status"].ToString());
    }

    [Fact]
    public async Task RegistrationIndex_AllUpstreamsAuthenticatedRefusal_NoLocalRow_ThrowsRefusedUpstreamFetchFailure()
    {
        // A 401 from an upstream this request AUTHENTICATED to is a deterministic auth/policy
        // refusal — non-transient (502, not 503) and never carries a Retry-After.
        await SeedAuthenticatedUpstreamAsync(_serverA.Urls[0], "test-bearer-token");
        StubIndex(_serverA, "refused-pkg", 401, "");

        var handler = BuildHandler();
        var http = BuildContext();

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(
            () => handler.RegistrationIndexAsync(http, _orgId, "refused-pkg", semVer2: false, CancellationToken.None));

        Assert.True(ex.Refused);
        Assert.False(ex.Transient);
        Assert.Null(ex.RetryAfter);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private static void StubIndex(WireMockServer server, string id, int status, string body)
        => server.Given(Request.Create()
                      .WithPath($"/registration5-semver1/{id.ToLowerInvariant()}/index.json").UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(status).WithBody(body).WithHeader("Content-Type", "application/json"));

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
    // this, a name with a local version never reaches the proxy-merge path at all.
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

    // Seeds a local (uploaded) package version so the registration index has a local fallback
    // to serve when every configured upstream fails.
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

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    private NuGetRegistrationHandler BuildHandler()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dependably-nuget-regfailtest-{Guid.NewGuid():N}"),
            })
            .Build();

        var db = _db;
        var orgs = new OrgRepository(db);
        var packages = new PackageRepository(db);
        var tokens = new TokenRepository(db, TimeProvider.System);
        var vulns = new VulnerabilityRepository(db, TimeProvider.System);
        var cacheArtifacts = new CacheArtifactRepository(db);
        var inventory = new ArtifactInventoryRepository(db, packages, cacheArtifacts, vulns);
        var claims = new ClaimResolver(new ClaimRepository(db), new AirGapMode(config));
        var reserved = new ReservedNamespaceService(db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
        var registries = new UpstreamRegistryResolver(
            new UpstreamRegistryRepository(db, TimeProvider.System, TestEnvelope.Unconfigured()));
        var urls = new RequestPublicUrlBuilder(config);
        var epochStore = new OrgCacheEpochStore();
        var cache = new RenderedResponseCache<NuGetRegistrationKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 32 * 1024 * 1024 }),
            MetadataCacheKeys.NuGetRegistration, epochStore);

        var httpFactory = new StaticHttpClientFactory(new HttpClient());
        var audit = new AuditRepository(db);
        string stagingDir = config["PROXY_STAGING_PATH"]!;
        var upstream = new UpstreamClient(
            httpFactory,
            new TieredBlobStorage(new InMemoryBlobStore(), new InMemoryBlobStore()),
            audit,
            new AllowAllValidator(),
            new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(stagingDir),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);

        return new NuGetRegistrationHandler(
            orgs, packages, tokens, vulns, inventory,
            upstream, registries, claims, reserved, cache,
            new RenderedMetadataCacheOptions(TimeSpan.FromSeconds(600), TimeSpan.FromSeconds(300)),
            urls, TimeProvider.System, NullLogger<NuGetRegistrationHandler>.Instance);
    }

    private DefaultHttpContext BuildContext()
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "nuget-proxy-failure-org");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        return http;
    }

    // ── test doubles ─────────────────────────────────────────────────────────────

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }
}
