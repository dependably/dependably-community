using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// End-to-end coverage of the Maven proxy cache-miss download path through the real stack:
/// <see cref="MavenController"/> → WireMock-backed <see cref="MavenUpstreamFetcher"/> /
/// <see cref="UpstreamClient"/> (so the SSRF guard, hash-and-stage, and sidecar pre-fetch all
/// run) → the shared <see cref="ProxyFetchService"/> (record → synchronous OSV scan →
/// <see cref="BlockGateService"/>). The OSV source is the only stub — it decides whether the
/// freshly-fetched version is vulnerable. This is the integration test for the gate the unit
/// tests in <see cref="MavenControllerUnitTests"/> can only exercise on the cache-hit side.
///
/// Tagged Unit (not Integration) to match its sibling <see cref="MavenUpstreamFetcherTests"/>:
/// both drive a real UpstreamClient over a loopback WireMock server rather than the
/// WebApplicationFactory harness the Integration category uses, so they belong in the fast suite.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenControllerProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private WireMockServer _server = null!;
    private string _upstream = null!;

    private string _orgId = null!;
    private string _userId = null!;

    private OrgRepository _orgs = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private PackageRepository _packages = null!;

    // Shared across BuildController calls so the metadata cache (single-flight + TTL) persists
    // between the first and second GET — that's what makes the second metadata poll a cache hit.
    private readonly Dependably.Infrastructure.Caching.RenderedResponseCache<Dependably.Infrastructure.Caching.MavenMetadataKey> _metadataCache =
        new(new Microsoft.Extensions.Caching.Memory.MemoryCache(
                new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions { SizeLimit = 8 * 1024 * 1024 }),
            Dependably.Infrastructure.Caching.MetadataCacheKeys.MavenMetadata);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');

        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);
        _packages = new PackageRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "acme");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "owner@acme.test", "owner");
        await SetAnonymousPullAsync(true);
        // The controller now resolves the upstream from the per-org registry list rather than
        // Maven:Upstream config — seed one pointing at the WireMock server so proxy paths fire.
        await SeedMavenRegistryAsync(_upstream);
    }

    private async Task SeedMavenRegistryAsync(string url)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @org, 'maven', @url, 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), org = _orgId, url });
    }

    // Source pinning is opt-in per instance (PROXY_SOURCE_PINNING), so a test that wants the
    // dependency-confusion guard active has to turn it on the way an operator would.
    private static IConfiguration SourcePinConfig(bool enabled) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_SOURCE_PINNING"] = enabled ? "true" : "false",
            })
            .Build();

    private async Task ClearMavenRegistriesAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE org_id = @org AND ecosystem = 'maven'",
            new { org = _orgId });
    }

    private async Task<string?> PinnedHostAsync(string purlName)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT upstream_host FROM upstream_source_pin
            WHERE org_id = @org AND ecosystem = 'maven' AND name = @name
            """,
            new { org = _orgId, name = purlName });
    }

    private async Task<long> PinViolationCountAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE org_id = @org AND action = 'upstream_source_pin_violation'
            """,
            new { org = _orgId });
    }

    // The scheme+authority of a configured upstream base — the granularity a source pin records,
    // which is why two repository paths under one host collapse to a single pinned value.
    private static string Authority(string url) => new Uri(url).GetLeftPart(UriPartial.Authority);

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private void StubArtifact(string path, byte[] body)
        => _server.Given(Request.Create().WithPath("/" + path).UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

    private void StubSidecar(string path, string sha256)
        => _server.Given(Request.Create().WithPath("/" + path + ".sha256").UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(sha256 + "  some-file.jar\n"));

    /// <summary>
    /// Stubs the artifact GET with a <c>Last-Modified</c> response header — the signal the
    /// fetch-then-hash path (no <c>.sha256</c> sidecar stubbed) reads as the artifact's upstream
    /// publish timestamp. No <c>.sha256</c>/<c>.sha1</c>/<c>.md5</c> sidecar is stubbed alongside
    /// this, so <see cref="MavenUpstreamFetcher"/> falls back to fetch-then-hash and caches the
    /// artifact unverified — mirroring the real Maven Central case this fix targets.
    /// </summary>
    private void StubArtifactWithLastModified(string path, byte[] body, DateTimeOffset lastModified)
        => _server.Given(Request.Create().WithPath("/" + path).UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(body)
                      .WithHeader("Last-Modified", lastModified.UtcDateTime.ToString("R", System.Globalization.CultureInfo.InvariantCulture)));

    private async Task SetMinReleaseAgeAsync(int hours)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET min_release_age_hours = @h WHERE org_id = @org",
            new { h = hours, org = _orgId });
    }

    private void StubUpstreamMetadata(string artifactPath, params string[] versions)
    {
        string versionXml = string.Concat(versions.Select(v => $"<version>{v}</version>"));
        string xml =
            "<metadata><groupId>com.example</groupId><artifactId>meta</artifactId>" +
            $"<versioning><versions>{versionXml}</versions></versioning></metadata>";
        _server.Given(Request.Create().WithPath("/" + artifactPath + "/maven-metadata.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(xml));
    }

    private long UpstreamMetadataGetCount(string artifactPath)
        => _server.LogEntries.Count(e =>
            e.RequestMessage?.Path?.EndsWith(artifactPath + "/maven-metadata.xml") == true);

    private async Task PublishLocalVersionAsync(string groupId, string artifactId, string version)
    {
        string purlName = $"{groupId}:{artifactId}";
        var pkg = await _packages.GetOrCreateAsync(_orgId, "maven", purlName, purlName, isProxy: false);
        await using var conn = await _db.OpenAsync();
        string pvId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, 1, 'deadbeef', 'uploaded')
            """,
            new
            {
                id = pvId,
                pkgId = pkg.Id,
                version,
                purl = PurlNormalizer.Maven(groupId, artifactId, version),
                blobKey = $"hosted/{_orgId}/maven/{groupId}/{artifactId}/{version}/{artifactId}-{version}.jar",
                filename = $"{artifactId}-{version}.jar",
            });
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    private async Task SetMaxOsvToleranceAsync(double tolerance)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_osv_score_tolerance = @t WHERE org_id = @org",
            new { t = tolerance, org = _orgId });
    }

    private static IOsvSource CleanOsv()
    {
        return TestOsvSource.Create();
    }

    private static IOsvSource VulnOsv(double cvssScore) => TestOsvSource.WithAdvisory(cvssScore);

    private long ArtifactGetCount(string filename)
        => _server.LogEntries.Count(e => e.RequestMessage?.Path?.EndsWith(filename) == true);

    private MavenController BuildController(
        IOsvSource osv, TimeProvider? clock = null, bool verifyWithUpstreamSha256 = true,
        bool sourcePinning = false)
    {
        var time = clock ?? TimeProvider.System;
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Maven:Upstream"] = _upstream,
                ["Maven:VerifyWithUpstreamSha256"] = verifyWithUpstreamSha256 ? "true" : "false",
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-maven-proxytest-{Guid.NewGuid():N}"),
            })
            .Build();

        // Single blob store seen by both the UpstreamClient (which writes the proxied blob at
        // BlobKeys.Proxy(sha)) and the controller (which reads it back on a cache hit).
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler()));
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(false),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            Dependably.Infrastructure.StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
        var upstream = new MavenUpstreamFetcher(
            upstreamClient, tiered, _db, config, NullLogger<MavenUpstreamFetcher>.Instance, time);

        var vulns = new VulnerabilityRepository(_db, time);
        var licenses = new LicenseRepository(_db, time, TestNormalizers.License(_db));
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config,
            new StubAirGapMode(false),
            NullLogger<VulnerabilityScanService>.Instance,
            time,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(time),
            Dependably.Tests.Infrastructure.TestAlerts.NoOp(_db, time)));
        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var blockGate = Dependably.Tests.Infrastructure.TestBlockGate.Create(_db, time);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance, time);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate, _audit, time,
            new Dependably.Infrastructure.SourcePinRepository(_db, SourcePinConfig(sourcePinning)));

        var svc = new MavenControllerServices(
            Packages: _packages, Tokens: _tokens, Audit: _audit, Orgs: _orgs,
            Blobs: _blobs, Db: _db, Upstream: upstream, Config: config,
            ProxyFetch: proxyFetch, BlockGate: blockGate,
            ReservedNamespaces: new ReservedNamespaceService(
                _db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), time),
            Registries: new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, time, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured())),
            MetadataCache: _metadataCache,
            Invalidation: Dependably.Tests.Infrastructure.TestMetadataInvalidation.ForMaven(_metadataCache),
            CacheOptions: new Dependably.Infrastructure.RenderedMetadataCacheOptions(
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(5)),
            Log: NullLogger<MavenController>.Instance,
            CacheArtifacts: cacheArtifact,
            TenantAccess: tenantAccess,
            Vulns: new VulnerabilityRepository(_db, TimeProvider.System),
            Time: time,
            CacheRecorder: cacheRecorder,
            // No Maven trust anchors configured — IsConfiguredForAsync returns false, provenance skipped.
            MavenProvenance: new Dependably.Protocol.Provenance.MavenProvenanceVerifier(
                new Dependably.Tests.Infrastructure.StubPerOrgTrustAnchorStore(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.MavenProvenanceVerifier>.Instance),
            EdgeGuard: Dependably.Tests.Infrastructure.TestEdgeMode.DisabledPublishGuard(),
            Staging: new Dependably.Infrastructure.StagingOptions(System.IO.Path.GetTempPath(), 0),
            Licenses: licenses);

        return new MavenController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ProxyMiss_VulnerableArtifactOverTolerance_Returns403_AndRecordsNoServeRow()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("vulnerable-jar-payload");
        string path = "com/example/vuln/1.0/vuln-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));
        await SetMaxOsvToleranceAsync(4.0);

        var ctl = BuildController(VulnOsv(9.8));
        var result = await ctl.Download(path, CancellationToken.None);

        Assert.Equal(403, Assert.IsType<StatusCodeResult>(result).StatusCode);

        // Refused on the very first fetch: the block gate fired after the scan, so the artefact
        // is never written to maven_version_files (which holds only locally-published files) and a
        // later attempt re-fetches and re-gates rather than serving from cache.
        await using var conn = await _db.OpenAsync();
        long fileRows = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.purl_name = 'com.example:vuln'
            """,
            new { org = _orgId });
        Assert.Equal(0, fileRows);
    }

    // ── Release-age cooldown (min_release_age_hours) ─────────────────────────
    //
    // Maven's proxy fetch path has no per-version metadata document carrying an upstream publish
    // date (unlike, say, the terraform registry protocol), so the fetch-then-hash path — the norm
    // for Maven Central, which serves no .sha256 sidecar for most artifacts — reads the upstream
    // response's Last-Modified header instead. These tests never stub a .sha256/.sha1/.md5
    // sidecar, so MavenUpstreamFetcher takes that fallback and the captured header is what the
    // cooldown gate evaluates.

    [Fact]
    public async Task ProxyMiss_RecentlyPublishedArtifact_IsBlockedByTheReleaseAgeCooldown()
    {
        var clock = TestTime.Frozen();
        byte[] bytes = Encoding.UTF8.GetBytes("freshly-published-jar");
        string path = "com/example/fresh/1.0/fresh-1.0.jar";
        StubArtifactWithLastModified(path, bytes, clock.GetUtcNow().AddHours(-1));
        await SetMinReleaseAgeAsync(72);

        var ctl = BuildController(CleanOsv(), clock: clock);
        var result = await ctl.Download(path, CancellationToken.None);

        Assert.Equal(403, Assert.IsType<StatusCodeResult>(result).StatusCode);
    }

    [Fact]
    public async Task ProxyMiss_ArtifactOlderThanTheCooldownWindow_IsServed()
    {
        // Adversarial twin: the gate keys on age, not a blanket block. A version published 100h
        // ago clears the same 72h hold and serves — proving the block above is the cooldown
        // firing on a real captured timestamp, not the fetch path breaking every request.
        var clock = TestTime.Frozen();
        byte[] bytes = Encoding.UTF8.GetBytes("long-settled-jar");
        string path = "com/example/settled/1.0/settled-1.0.jar";
        StubArtifactWithLastModified(path, bytes, clock.GetUtcNow().AddHours(-100));
        await SetMinReleaseAgeAsync(72);

        var ctl = BuildController(CleanOsv(), clock: clock);
        var result = await ctl.Download(path, CancellationToken.None);

        var file = Dependably.Tests.Infrastructure.MavenServe.File(result);
        Assert.Equal(bytes, file.FileContents);
    }

    [Fact]
    public async Task ProxyMiss_Sha256SidecarKnownPath_CapturesNoTimestamp_CooldownFailsOpen()
    {
        // The adversarial twin at the OTHER seam: when the upstream serves a .sha256 sidecar, the
        // streaming (known-checksum) fetch path is taken instead of fetch-then-hash, and it never
        // reads response headers — PublishedAt stays null and the cooldown fails open rather than
        // blocking every artifact from a sidecar-serving upstream. Documents the fix's known gap
        // rather than letting it silently regress into looking fully covered.
        var clock = TestTime.Frozen();
        byte[] bytes = Encoding.UTF8.GetBytes("sha256-sidecar-path-jar");
        string path = "com/example/sidecar/1.0/sidecar-1.0.jar";
        StubArtifactWithLastModified(path, bytes, clock.GetUtcNow().AddHours(-1));
        StubSidecar(path, Sha256Hex(bytes));
        await SetMinReleaseAgeAsync(72);

        var ctl = BuildController(CleanOsv(), clock: clock);
        var result = await ctl.Download(path, CancellationToken.None);

        var file = Dependably.Tests.Infrastructure.MavenServe.File(result);
        Assert.Equal(bytes, file.FileContents);
    }

    // A percent-encoded traversal survives the {**path} catch-all undecoded (ASP.NET does not
    // decode %2F/%2E in route values), so without the segment guard it would ride into the
    // composed upstream URL and be decoded to '../' by the upstream — a same-host path escape
    // the host-only SSRF guard cannot see. The download path must reject it before any fetch.
    [Theory]
    [InlineData("com%2f..%2f..%2fsecret/lib/1.0/lib-1.0.jar")]  // '%' in the group segment
    [InlineData("com/example/%2e%2e%2f%2e%2e/1.0/lib-1.0.jar")] // '%' in an interior segment
    [InlineData("com/example/lib/1.0/lib-1.0.jar%2f..%2fx")]    // '%' in the filename segment
    public async Task ProxyDownload_PercentEncodedTraversal_Returns400_AndNeverContactsUpstream(string path)
    {
        var ctl = BuildController(CleanOsv());

        var result = await ctl.Download(path, CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Empty(_server.LogEntries);
    }

    [Fact]
    public async Task ProxyMiss_VulnScoreWithinTolerance_Serves()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("tolerable-jar-payload");
        string path = "com/example/tolerable/1.0/tolerable-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));
        await SetMaxOsvToleranceAsync(10.0);

        var ctl = BuildController(VulnOsv(5.0));
        var result = await ctl.Download(path, CancellationToken.None);

        var file = Dependably.Tests.Infrastructure.MavenServe.File(result);
        Assert.Equal(bytes, file.FileContents);
    }

    [Fact]
    public async Task ProxyMiss_CleanArtifact_Serves_ThenSecondRequestIsCacheHit_NoSecondUpstreamFetch()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("clean-jar-payload");
        string path = "com/example/clean/1.0/clean-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));

        var ctl1 = BuildController(CleanOsv());
        var first = await ctl1.Download(path, CancellationToken.None);
        var file = Dependably.Tests.Infrastructure.MavenServe.File(first);
        Assert.Equal(bytes, file.FileContents);
        Assert.Equal("MISS", ctl1.Response.Headers["X-Cache"].ToString());

        long artifactCallsAfterMiss = ArtifactGetCount("clean-1.0.jar");

        // Second request resolves the cache_artifact row the first fetch wrote → served from the
        // blob store as a cache HIT, with no further upstream artifact fetch.
        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download(path, CancellationToken.None);
        Assert.IsType<FileStreamResult>(second).FileStream.Dispose();
        Assert.Equal("HIT", ctl2.Response.Headers["X-Cache"].ToString());

        Assert.Equal(artifactCallsAfterMiss, ArtifactGetCount("clean-1.0.jar"));
    }

    [Fact]
    public async Task Metadata_SecondGet_IsCacheHit_NoSecondUpstreamMetadataFetch()
    {
        const string artifactPath = "com/example/meta";
        StubUpstreamMetadata(artifactPath, "1.0", "2.0");

        var ctl1 = BuildController(CleanOsv());
        var first = await ctl1.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        var content1 = Assert.IsType<ContentResult>(first);
        Assert.Contains("2.0", content1.Content);
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));

        // Second poll is served from the rendered-body cache — no further upstream metadata fetch.
        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        var content2 = Assert.IsType<ContentResult>(second);
        Assert.Equal(content1.Content, content2.Content);
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));
    }

    [Fact]
    public async Task Metadata_PublishEvictsCache_NewVersionAppearsImmediately()
    {
        // No upstream stub for this coordinate → local-only metadata; isolates eviction from TTL.
        await PublishLocalVersionAsync("com.example", "evict", "1.0");

        var ctl1 = BuildController(CleanOsv());
        var first = await ctl1.Download("com/example/evict/maven-metadata.xml", CancellationToken.None);
        var content1 = Assert.IsType<ContentResult>(first);
        Assert.Contains("1.0", content1.Content);
        Assert.DoesNotContain("2.0", content1.Content);

        // Publishing a second version through the controller must evict the warmed cache entry.
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            _orgId, _userId, """["publish:maven"]""", expiresAt: null);
        var ctlPub = BuildController(CleanOsv());
        ctlPub.Request.Headers.Authorization = $"Bearer {raw}";
        ctlPub.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("jar-bytes-v2"));
        ctlPub.Request.ContentLength = 12;
        var put = await ctlPub.Publish(
            "com/example/evict/2.0/evict-2.0.jar", CancellationToken.None);
        Assert.Equal(201, Assert.IsType<StatusCodeResult>(put).StatusCode);

        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download("com/example/evict/maven-metadata.xml", CancellationToken.None);
        var content2 = Assert.IsType<ContentResult>(second);
        Assert.Contains("2.0", content2.Content);
    }

    // Seeds a proxied Maven version on the shared cache plane (cache_artifact +
    // tenant_artifact_access) — where every current Maven proxy fetch lands — without any
    // package_versions row, the way a real proxy fetch leaves it.
    private async Task SeedProxiedMavenCacheVersionAsync(string groupId, string artifactId, string version)
    {
        string purlName = $"{groupId}:{artifactId}";
        string caId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
            VALUES (@id, 'maven', @name, @version, @filename, @blobKey, 'cafeba', 1)
            """,
            new { id = caId, name = purlName, version, filename = $"{artifactId}-{version}.jar", blobKey = $"proxy/sha256/{caId}" });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@org, @id)",
            new { org = _orgId, id = caId });
    }

    [Fact]
    public async Task Metadata_ListsCachedProxyVersion_WhenUpstreamReturnsNothing()
    {
        // A version proxied earlier lives only on the cache plane. No upstream stub for this
        // coordinate, so the upstream merge returns nothing and only the local (both-plane) set
        // drives the document. Reading package_versions alone would 404 this coordinate.
        await SeedProxiedMavenCacheVersionAsync("com.example", "cached", "3.1.4");

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download("com/example/cached/maven-metadata.xml", CancellationToken.None);
        var content = Assert.IsType<ContentResult>(result);
        Assert.Contains("3.1.4", content.Content);
    }

    [Fact]
    public async Task Metadata_UnionsCachedProxyVersionWithHostedVersion()
    {
        // com.example:mix has one hosted publish and one proxied (cache-plane) version. Both must
        // appear — reading package_versions alone would drop the cached one when the upstream merge
        // returns nothing (here: no upstream stub for this coordinate).
        await PublishLocalVersionAsync("com.example", "mix", "1.0");
        await SeedProxiedMavenCacheVersionAsync("com.example", "mix", "2.0");

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download("com/example/mix/maven-metadata.xml", CancellationToken.None);
        var content = Assert.IsType<ContentResult>(result);
        Assert.Contains("1.0", content.Content);
        Assert.Contains("2.0", content.Content);
    }

    [Fact]
    public async Task Metadata_SidecarHashesSameServedBytes()
    {
        const string artifactPath = "com/example/meta";
        StubUpstreamMetadata(artifactPath, "1.0", "2.0");

        var ctl1 = BuildController(CleanOsv());
        var doc = Assert.IsType<ContentResult>(
            await ctl1.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None));
        byte[] served = Encoding.UTF8.GetBytes(doc.Content!);

        var ctl2 = BuildController(CleanOsv());
        var sidecar = Assert.IsType<ContentResult>(
            await ctl2.Download(artifactPath + "/maven-metadata.xml.sha1", CancellationToken.None));

        string expected = Convert.ToHexString(SHA1.HashData(served)).ToLowerInvariant();
        Assert.Equal(expected, sidecar.Content);
    }

    [Fact]
    public async Task Metadata_ETag_HonorsIfNoneMatch_AgainstCachedBody()
    {
        const string artifactPath = "com/example/meta";
        StubUpstreamMetadata(artifactPath, "1.0", "2.0");

        var ctl1 = BuildController(CleanOsv());
        await ctl1.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        string etag = ctl1.Response.Headers.ETag.ToString();
        Assert.False(string.IsNullOrEmpty(etag));

        var ctl2 = BuildController(CleanOsv());
        ctl2.Request.Headers.IfNoneMatch = etag;
        var second = await ctl2.Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        Assert.Equal(304, Assert.IsType<StatusCodeResult>(second).StatusCode);
    }

    [Fact]
    public async Task ProxyMiss_Pom_ExtractsLicenses_ToCachePlane()
    {
        byte[] pom = Encoding.UTF8.GetBytes("""
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>lic</artifactId>
              <version>1.0</version>
              <licenses>
                <license>
                  <name>The Apache Software License, Version 2.0</name>
                  <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
                </license>
              </licenses>
            </project>
            """);
        string path = "com/example/lic/1.0/lic-1.0.pom";
        StubArtifact(path, pom);
        StubSidecar(path, Sha256Hex(pom));

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download(path, CancellationToken.None);
        Assert.Equal(pom, Dependably.Tests.Infrastructure.MavenServe.File(result).FileContents);

        await using var conn = await _db.OpenAsync();
        var spdx = (await conn.QueryAsync<string>(
            "SELECT license_spdx FROM package_version_licenses WHERE owner_kind = 'cache_artifact'"))
            .ToList();
        Assert.Equal(new[] { "Apache-2.0" }, spdx);
    }

    // Regression: Maven recorded the repository-RELATIVE path in cache_artifact.upstream_url
    // ("com/example/abs/1.0/abs-1.0.jar") while every other ecosystem records an absolute URL.
    // A relative value cannot identify the upstream host, so any consumer that gates on origin
    // (the registry-page link) can never resolve it and silently renders nothing.
    [Fact]
    public async Task ProxyMiss_RecordsAbsoluteUpstreamUrl_NotRepositoryRelativePath()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("absolute-url-regression");
        const string path = "com/example/abs/1.0/abs-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));

        var ctl = BuildController(CleanOsv());
        await ctl.Download(path, CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? recorded = await conn.ExecuteScalarAsync<string?>(
            "SELECT upstream_url FROM cache_artifact WHERE ecosystem = 'maven' AND filename = 'abs-1.0.jar'");

        Assert.False(string.IsNullOrEmpty(recorded));
        // Must parse as an ABSOLUTE URL — the whole point of the fix.
        Assert.True(
            Uri.TryCreate(recorded, UriKind.Absolute, out var absolute),
            $"upstream_url must be an absolute URL, got '{recorded}'.");
        // ...pointing at the upstream we actually fetched from, and still carrying the repo path.
        Assert.Equal(new Uri(_upstream).Host, absolute!.Host);
        Assert.EndsWith(path, recorded);
    }

    [Fact]
    public async Task ProxyMiss_Jar_WritesNoLicenseRows()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("just-a-jar-no-pom");
        string path = "com/example/nolic/1.0/nolic-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download(path, CancellationToken.None);
        Assert.Equal(bytes, Dependably.Tests.Infrastructure.MavenServe.File(result).FileContents);

        await using var conn = await _db.OpenAsync();
        long licRows = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses");
        Assert.Equal(0, licRows);
    }

    // ── Source pinning (dependency confusion across a multi-repository upstream list) ─────
    //
    // Maven's normal configuration is several upstream repositories walked in priority order, so
    // the shadowing these tests describe is not hypothetical: a public repository ordered ahead of
    // a private one answers for a coordinate the private one owns. The pin is opt-in
    // (PROXY_SOURCE_PINNING), and it keys off exactly one input — the top-level
    // ProxyFetchRequest.UpstreamUrl — so every test here is also a check that the field is
    // supplied at all. The pinned value is an authority, not a full base URL, which is what keeps
    // the ordinary releases/snapshots/central-proxy-on-one-host layout from reading as shadowing.

    [Fact]
    public async Task ProxyMiss_BindsTheCoordinateToTheUpstreamThatServedIt()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("pinned-jar-payload");
        string path = "com/example/pinned/1.0/pinned-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));

        var ctl = BuildController(CleanOsv(), sourcePinning: true);
        var result = await ctl.Download(path, CancellationToken.None);

        Assert.Equal(bytes, Dependably.Tests.Infrastructure.MavenServe.File(result).FileContents);

        // Without the pin row nothing downstream can ever fire: the violation arm compares against
        // it, so an absent row is the whole control being absent rather than merely unproven.
        Assert.Equal(Authority(_upstream), await PinnedHostAsync("com.example:pinned"));
    }

    [Fact]
    public async Task ProxyMiss_WithPinningDisabled_BindsNothing()
    {
        // Adversarial twin: the pin is an operator opt-in, so the default instance must record
        // nothing. A pin written while the switch is off would start refusing serves on an
        // upgrade for deployments that never asked for the control.
        byte[] bytes = Encoding.UTF8.GetBytes("unpinned-jar-payload");
        string path = "com/example/unpinned/1.0/unpinned-1.0.jar";
        StubArtifact(path, bytes);
        StubSidecar(path, Sha256Hex(bytes));

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download(path, CancellationToken.None);

        Assert.Equal(bytes, Dependably.Tests.Infrastructure.MavenServe.File(result).FileContents);
        Assert.Null(await PinnedHostAsync("com.example:unpinned"));
    }

    [Fact]
    public async Task ProxyMiss_SameCoordinateFromASecondUpstreamHost_IsRefusedAsAPinViolation()
    {
        // The dependency-confusion shape: com.example:lib resolves from the org's own repository,
        // then a second repository on a different host answers for the same coordinate. Serving it
        // is how a squatted groupId reaches a build; the pin is what refuses it.
        byte[] owned = Encoding.UTF8.GetBytes("owned-lib-1.0");
        string ownedPath = "com/example/lib/1.0/lib-1.0.jar";
        StubArtifact(ownedPath, owned);
        StubSidecar(ownedPath, Sha256Hex(owned));

        var served = await BuildController(CleanOsv(), sourcePinning: true)
            .Download(ownedPath, CancellationToken.None);
        Assert.Equal(owned, Dependably.Tests.Infrastructure.MavenServe.File(served).FileContents);

        using var squatter = WireMockServer.Start();
        string squatterBase = squatter.Urls[0].TrimEnd('/');
        byte[] shadowed = Encoding.UTF8.GetBytes("shadowed-lib-2.0");
        string shadowedPath = "com/example/lib/2.0/lib-2.0.jar";
        squatter.Given(Request.Create().WithPath("/" + shadowedPath).UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(shadowed));
        await ClearMavenRegistriesAsync();
        await SeedMavenRegistryAsync(squatterBase);

        var result = await BuildController(CleanOsv(), sourcePinning: true)
            .Download(shadowedPath, CancellationToken.None);

        Assert.Equal(403, Assert.IsType<StatusCodeResult>(result).StatusCode);
        Assert.Equal(1, await PinViolationCountAsync());

        // First-serve wins: the refusal must not re-point the pin at the host it just refused,
        // which would hand the attacker the binding on the second attempt.
        Assert.Equal(Authority(_upstream), await PinnedHostAsync("com.example:lib"));

        // The refusal lands before any cache_artifact row is written and Maven's cache-hit lookup
        // is row-driven, so a replay re-enters the fetch path and re-refuses rather than serving
        // the staged bytes ungated.
        var replay = await BuildController(CleanOsv(), sourcePinning: true)
            .Download(shadowedPath, CancellationToken.None);
        Assert.Equal(403, Assert.IsType<StatusCodeResult>(replay).StatusCode);
        Assert.Equal(2, await PinViolationCountAsync());
    }

    [Fact]
    public async Task ProxyMiss_AnotherVersionFromThePinnedUpstream_IsServedWithNoViolation()
    {
        // Adversarial twin: the pin keys on the serving authority, not on "this name was fetched
        // before". A second version arriving from the upstream already bound to the coordinate is
        // the ordinary case and must serve — otherwise the block above is the fetch path breaking,
        // not the guard firing.
        byte[] first = Encoding.UTF8.GetBytes("same-host-lib-1.0");
        string firstPath = "com/example/same/1.0/same-1.0.jar";
        StubArtifact(firstPath, first);
        StubSidecar(firstPath, Sha256Hex(first));
        await BuildController(CleanOsv(), sourcePinning: true).Download(firstPath, CancellationToken.None);

        byte[] second = Encoding.UTF8.GetBytes("same-host-lib-2.0");
        string secondPath = "com/example/same/2.0/same-2.0.jar";
        StubArtifact(secondPath, second);
        StubSidecar(secondPath, Sha256Hex(second));

        var result = await BuildController(CleanOsv(), sourcePinning: true)
            .Download(secondPath, CancellationToken.None);

        Assert.Equal(second, Dependably.Tests.Infrastructure.MavenServe.File(result).FileContents);
        Assert.Equal(0, await PinViolationCountAsync());
    }

    [Fact]
    public async Task ProxyMiss_ASecondRepositoryOnThePinnedHost_IsNotShadowing()
    {
        // Adversarial twin for Maven's defining shape: one Nexus/Artifactory host commonly exposes
        // several repositories (releases, snapshots, a central proxy) under distinct paths, and a
        // coordinate legitimately resolving from a second one of them is not dependency confusion.
        // Pinning the scheme+authority rather than the full base URL is what keeps that from
        // raising a violation — a false refusal here would be worse than the gap it closes.
        await ClearMavenRegistriesAsync();
        await SeedMavenRegistryAsync($"{_upstream}/releases");

        byte[] release = Encoding.UTF8.GetBytes("multi-repo-lib-1.0");
        string releasePath = "com/example/multi/1.0/multi-1.0.jar";
        StubArtifact("releases/" + releasePath, release);
        StubSidecar("releases/" + releasePath, Sha256Hex(release));
        await BuildController(CleanOsv(), sourcePinning: true).Download(releasePath, CancellationToken.None);
        Assert.Equal(Authority(_upstream), await PinnedHostAsync("com.example:multi"));

        await ClearMavenRegistriesAsync();
        await SeedMavenRegistryAsync($"{_upstream}/snapshots");
        byte[] snapshot = Encoding.UTF8.GetBytes("multi-repo-lib-2.0");
        string snapshotPath = "com/example/multi/2.0/multi-2.0.jar";
        StubArtifact("snapshots/" + snapshotPath, snapshot);
        StubSidecar("snapshots/" + snapshotPath, Sha256Hex(snapshot));

        var result = await BuildController(CleanOsv(), sourcePinning: true)
            .Download(snapshotPath, CancellationToken.None);

        Assert.Equal(snapshot, Dependably.Tests.Infrastructure.MavenServe.File(result).FileContents);
        Assert.Equal(0, await PinViolationCountAsync());
    }

    // ── test doubles (mirror MavenUpstreamFetcherTests) ─────────────────────────

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
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

    /// <summary>
    /// Forwards each outgoing request to the loopback authority it actually names. Pinning every
    /// request onto one mock server would make a two-upstream scenario impossible to express: the
    /// second host's requests would be silently answered by the first, and a source-pin test would
    /// then be asserting against a single authority while believing it had two.
    /// </summary>
    private sealed class WireMockHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            var url = request.RequestUri!;
            using var innerRequest = new HttpRequestMessage(request.Method, url);
            foreach (var h in request.Headers)
            {
                innerRequest.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }
}
