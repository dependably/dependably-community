using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
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
/// Covers the two gaps closed by the Maven proxy completeness fix:
///
/// 1. SNAPSHOT proxying: a SNAPSHOT artifact absent from the local cache resolves through
///    upstream via the version-level <c>maven-metadata.xml</c> (timestamped build selected),
///    is fetched, cached, and served.
///
/// 2. Sidecar-before-primary: a checksum sidecar request for a not-yet-cached primary
///    triggers a recursive primary fetch, caches the primary, then serves the sidecar from
///    the stored checksum columns.
///
/// Mixed scenario (house rule): a batch of cached + uncached primaries and their sidecars
/// all resolve correctly in a single test.
///
/// Tagged Unit to match the sibling <see cref="MavenControllerProxyTests"/>: uses a real
/// UpstreamClient over a loopback WireMock server rather than WebApplicationFactory.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenSnapshotProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private WireMockServer _server = null!;
    private string _upstream = null!;

    private string _orgId = null!;

    private OrgRepository _orgs = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private PackageRepository _packages = null!;

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
        await UserSeeder.InsertAsync(_db, _orgId, "owner@acme.test", "owner");
        await SetAnonymousPullAsync(true);
        await SeedMavenRegistryAsync(_upstream);
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static string Sha1Hex(byte[] data)
        => Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant();

    private static string Md5Hex(byte[] data)
        => Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant();

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

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    private void StubArtifact(string path, byte[] body)
        => _server.Given(Request.Create().WithPath("/" + path).UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

    private void StubSha256Sidecar(string path, string sha256)
        => _server.Given(Request.Create().WithPath("/" + path + ".sha256").UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(200).WithBody(sha256));

    private void StubSnapshotMetadata(string groupPath, string artifactId, string version, string xml)
        => _server.Given(Request.Create()
                .WithPath($"/{groupPath}/{artifactId}/{version}/maven-metadata.xml")
                .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(xml));

    private void StubMissing(string path)
        => _server.Given(Request.Create().WithPath("/" + path).UsingGet())
                  .RespondWith(Response.Create().WithStatusCode(404));

    private static string SnapshotMetadataXml(
        string groupId, string artifactId, string version,
        string timestamp, int buildNumber,
        string extension = "jar", string? classifier = null)
    {
        string classifierEl = classifier is not null
            ? $"<classifier>{classifier}</classifier>"
            : "";
        string timestampedValue = $"{version[..^"-SNAPSHOT".Length]}-{timestamp}-{buildNumber}";
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <metadata>
              <groupId>{groupId}</groupId>
              <artifactId>{artifactId}</artifactId>
              <version>{version}</version>
              <versioning>
                <snapshot>
                  <timestamp>{timestamp}</timestamp>
                  <buildNumber>{buildNumber}</buildNumber>
                </snapshot>
                <lastUpdated>20240101120000</lastUpdated>
                <snapshotVersions>
                  <snapshotVersion>
                    {classifierEl}
                    <extension>{extension}</extension>
                    <value>{timestampedValue}</value>
                    <updated>20240101120000</updated>
                  </snapshotVersion>
                </snapshotVersions>
              </versioning>
            </metadata>
            """;
    }

    private static IOsvSource CleanOsv()
    {
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult(new List<OsvAdvisory>()));
        return osv;
    }

    private MavenController BuildController(IOsvSource osv, string? authHeader = null)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");
        if (authHeader is not null)
        {
            http.Request.Headers.Authorization = authHeader;
        }

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Maven:Upstream"] = _upstream,
                ["Maven:VerifyWithUpstreamSha256"] = "true",
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-maven-snaptest-{Guid.NewGuid():N}"),
            })
            .Build();

        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var upstreamClient = new UpstreamClient(
            httpFactory, tiered, _audit, new AllowAllValidator(), new StubAirGapMode(false),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            Dependably.Infrastructure.StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
        var upstream = new MavenUpstreamFetcher(
            upstreamClient, tiered, _db, config, NullLogger<MavenUpstreamFetcher>.Instance, TimeProvider.System);

        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var licenses = new LicenseRepository(_db, TimeProvider.System);
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, _audit, config,
            new StubAirGapMode(false),
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System));
        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(_packages, _audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var blockGate = new BlockGateService(vulns, _audit, new QuarantineRepository(_db, TimeProvider.System), new InstallScriptAllowlistService(_db, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), TimeProvider.System), NullLogger<BlockGateService>.Instance, TimeProvider.System);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifact, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var proxyFetch = new ProxyFetchService(
            cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate, _packages, _audit, TimeProvider.System);

        var svc = new MavenControllerServices(
            Packages: _packages, Tokens: _tokens, Audit: _audit, Orgs: _orgs,
            Blobs: _blobs, Db: _db, Upstream: upstream, Config: config,
            ProxyFetch: proxyFetch, BlockGate: blockGate,
            ReservedNamespaces: new ReservedNamespaceService(
                _db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), TimeProvider.System),
            Registries: new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, TimeProvider.System)),
            MetadataCache: _metadataCache,
            Log: NullLogger<MavenController>.Instance,
            CacheArtifacts: cacheArtifact,
            TenantAccess: tenantAccess,
            Time: TimeProvider.System,
            CacheRecorder: cacheRecorder,
            // No Maven:SignatureKeys configured — IsConfigured=false, provenance skipped.
            MavenProvenance: new Dependably.Protocol.Provenance.MavenProvenanceVerifier(
                new Dependably.Protocol.Provenance.MavenSignatureKeyStore(
                    new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(),
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.MavenSignatureKeyStore>.Instance),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.MavenProvenanceVerifier>.Instance));

        return new MavenController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    // ── SNAPSHOT proxying ─────────────────────────────────────────────────────

    /// <summary>
    /// A SNAPSHOT artifact absent from the local cache resolves through the upstream
    /// version-level metadata, fetches the timestamped artifact, and serves the bytes.
    /// Verifies that the OLD code (early NotFound for IsSnapshot) would have failed this test.
    /// </summary>
    [Fact]
    public async Task Snapshot_UpstreamOnly_ResolvesTimestampedBuildAndServes()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("snapshot-jar-payload");
        string sha256 = Sha256Hex(bytes);
        const string groupPath = "com/example/snap";
        const string artifactId = "snap";
        const string version = "1.0-SNAPSHOT";
        const string timestamp = "20240101.120000";
        const int buildNumber = 3;

        // The controller requests lib-1.0-20240101.120000-3.jar, not lib-1.0-SNAPSHOT.jar.
        string timestampedFilename = $"{artifactId}-1.0-{timestamp}-{buildNumber}.jar";
        string artifactPath = $"{groupPath}/{artifactId}/{version}/{timestampedFilename}";

        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml("com.example.snap", artifactId, version, timestamp, buildNumber));
        StubArtifact(artifactPath, bytes);
        StubSha256Sidecar(artifactPath, sha256);

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download($"{groupPath}/{artifactId}/{version}/{artifactId}-{version}.jar", CancellationToken.None);

        var file = Assert.IsType<FileContentResult>(result);
        Assert.Equal(bytes, file.FileContents);
        Assert.Equal("MISS", ctl.Response.Headers["X-Cache"].ToString());
    }

    [Fact]
    public async Task Snapshot_SecondRequest_IsCacheHit_NoSecondUpstreamFetch()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("snapshot-hit-payload");
        string sha256 = Sha256Hex(bytes);
        const string groupPath = "com/example/snaphit";
        const string artifactId = "snaphit";
        const string version = "2.0-SNAPSHOT";
        const string timestamp = "20240202.090000";
        const int buildNumber = 1;

        string timestampedFilename = $"{artifactId}-2.0-{timestamp}-{buildNumber}.jar";
        string artifactPath = $"{groupPath}/{artifactId}/{version}/{timestampedFilename}";

        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml("com.example.snaphit", artifactId, version, timestamp, buildNumber));
        StubArtifact(artifactPath, bytes);
        StubSha256Sidecar(artifactPath, sha256);

        // First GET → upstream fetch + cache write.
        var ctl1 = BuildController(CleanOsv());
        await ctl1.Download($"{groupPath}/{artifactId}/{version}/{artifactId}-{version}.jar", CancellationToken.None);

        long artifactCallsAfterMiss = _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(timestampedFilename) == true);

        // Second GET → local cache hit (maven_version_files row written by first GET).
        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download($"{groupPath}/{artifactId}/{version}/{timestampedFilename}", CancellationToken.None);

        // Served from cache — no additional upstream call for the artifact.
        Assert.IsType<FileStreamResult>(second).FileStream.Dispose();
        Assert.Equal("HIT", ctl2.Response.Headers["X-Cache"].ToString());
        Assert.Equal(artifactCallsAfterMiss, _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(timestampedFilename) == true));
    }

    /// <summary>
    /// FRESHNESS: when upstream publishes a newer SNAPSHOT build (N+1) after build N was
    /// cached, a subsequent literal <c>-SNAPSHOT.jar</c> request must serve build N+1 —
    /// NOT the stale build N pinned in the alias row.
    ///
    /// Fails on the DO-NOTHING alias implementation because the alias row is never updated
    /// and the literal cache-hit path serves the stale cached bytes forever.
    /// </summary>
    [Fact]
    public async Task Snapshot_LiteralRequest_ServesFreshBuild_WhenUpstreamPublishesNewerBuild()
    {
        const string groupPath = "com/example/freshsnap";
        const string artifactId = "freshsnap";
        const string version = "7.0-SNAPSHOT";

        // Build N (first upstream publish).
        byte[] bytesN = Encoding.UTF8.GetBytes("snapshot-build-N-payload");
        string sha256N = Sha256Hex(bytesN);
        const string timestampN = "20240101.100000";
        const int buildNumN = 1;
        string tsFilenameN = $"{artifactId}-7.0-{timestampN}-{buildNumN}.jar";
        string artifactPathN = $"{groupPath}/{artifactId}/{version}/{tsFilenameN}";

        // Build N+1 (newer upstream publish).
        byte[] bytesNplus1 = Encoding.UTF8.GetBytes("snapshot-build-Nplus1-payload");
        string sha256Nplus1 = Sha256Hex(bytesNplus1);
        const string timestampNplus1 = "20240102.120000";
        const int buildNumNplus1 = 2;
        string tsFilenameNplus1 = $"{artifactId}-7.0-{timestampNplus1}-{buildNumNplus1}.jar";
        string artifactPathNplus1 = $"{groupPath}/{artifactId}/{version}/{tsFilenameNplus1}";

        string literalFilename = $"{artifactId}-{version}.jar";

        // Seed build N stubs and run the first literal request.
        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml("com.example.freshsnap", artifactId, version, timestampN, buildNumN));
        StubArtifact(artifactPathN, bytesN);
        StubSha256Sidecar(artifactPathN, sha256N);

        var ctl1 = BuildController(CleanOsv());
        var firstResult = await ctl1.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);
        var firstFile = Assert.IsType<FileContentResult>(firstResult);
        Assert.Equal(bytesN, firstFile.FileContents);
        Assert.Equal("MISS", ctl1.Response.Headers["X-Cache"].ToString());

        // Upstream publishes build N+1: reset WireMock HTTP stubs and register N+1 stubs.
        // The local DB and upstream registry are unchanged — only the HTTP stubs change.
        // The literal alias row (pointing at build N) still exists in the DB; the freshness
        // re-check must detect that N+1 is not cached yet and proxy it, returning fresh bytes.
        _server.ResetMappings();
        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml("com.example.freshsnap", artifactId, version, timestampNplus1, buildNumNplus1));
        StubArtifact(artifactPathNplus1, bytesNplus1);
        StubSha256Sidecar(artifactPathNplus1, sha256Nplus1);

        var ctl2 = BuildController(CleanOsv());
        var secondResult = await ctl2.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);
        var secondFile = Assert.IsType<FileContentResult>(secondResult);

        // Must serve N+1 bytes, NOT the stale N bytes.
        Assert.Equal(bytesNplus1, secondFile.FileContents);
        Assert.Equal("MISS", ctl2.Response.Headers["X-Cache"].ToString());
    }

    /// <summary>
    /// CACHE-EFFICIENCY: when upstream metadata reports the same SNAPSHOT build on two
    /// consecutive literal <c>-SNAPSHOT.jar</c> requests, the second request must NOT
    /// re-download the artifact bytes — it re-fetches metadata (cheap), confirms the
    /// timestamped artifact row is already cached, and serves it from the local store.
    /// </summary>
    [Fact]
    public async Task Snapshot_LiteralRequest_NoByteFetch_WhenUpstreamBuildUnchanged()
    {
        const string groupPath = "com/example/efficientsnap";
        const string artifactId = "efficientsnap";
        const string version = "8.0-SNAPSHOT";
        const string timestamp = "20240301.090000";
        const int buildNumber = 3;

        byte[] bytes = Encoding.UTF8.GetBytes("snapshot-efficient-payload");
        string sha256 = Sha256Hex(bytes);
        string tsFilename = $"{artifactId}-8.0-{timestamp}-{buildNumber}.jar";
        string artifactPath = $"{groupPath}/{artifactId}/{version}/{tsFilename}";
        string literalFilename = $"{artifactId}-{version}.jar";

        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml("com.example.efficientsnap", artifactId, version, timestamp, buildNumber));
        StubArtifact(artifactPath, bytes);
        StubSha256Sidecar(artifactPath, sha256);

        // First literal request → MISS: fetches metadata + artifact bytes.
        var ctl1 = BuildController(CleanOsv());
        await ctl1.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);

        long artifactCallsAfterFirstFetch = _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(tsFilename) == true);

        // Second literal request → upstream still reports same build; artifact already cached.
        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);

        // Served from cache — no additional upstream call for the artifact bytes.
        Assert.IsType<FileStreamResult>(second).FileStream.Dispose();
        Assert.Equal("HIT", ctl2.Response.Headers["X-Cache"].ToString());
        Assert.Equal(artifactCallsAfterFirstFetch, _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(tsFilename) == true));
    }

    /// <summary>
    /// After a first SNAPSHOT fetch resolves and caches the timestamped artifact, a second
    /// request using the LITERAL <c>-SNAPSHOT.jar</c> filename must be a cache hit — no
    /// second upstream fetch. This is the realistic client path: Maven/Gradle requests the
    /// artifact under the SNAPSHOT coordinate and lets the repo resolve the timestamp.
    ///
    /// Fails on the pre-fix code because the stored row is under the timestamped filename
    /// and the literal-name cache-hit lookup finds nothing, causing a second upstream call.
    /// </summary>
    [Fact]
    public async Task Snapshot_LiteralSecondRequest_IsCacheHit_NoSecondUpstreamFetch()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("literal-second-hit-payload");
        string sha256 = Sha256Hex(bytes);
        const string groupPath = "com/example/litcachehit";
        const string artifactId = "litcachehit";
        const string version = "4.0-SNAPSHOT";
        const string timestamp = "20240404.110000";
        const int buildNumber = 5;

        string timestampedFilename = $"{artifactId}-4.0-{timestamp}-{buildNumber}.jar";
        string artifactPath = $"{groupPath}/{artifactId}/{version}/{timestampedFilename}";
        string literalFilename = $"{artifactId}-{version}.jar";

        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml("com.example.litcachehit", artifactId, version, timestamp, buildNumber));
        StubArtifact(artifactPath, bytes);
        StubSha256Sidecar(artifactPath, sha256);

        // First GET using the LITERAL -SNAPSHOT filename → upstream fetch + cache write.
        var ctl1 = BuildController(CleanOsv());
        var first = await ctl1.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);
        Assert.IsType<FileContentResult>(first);
        Assert.Equal("MISS", ctl1.Response.Headers["X-Cache"].ToString());

        long artifactCallsAfterMiss = _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(timestampedFilename) == true);

        // Second GET using the SAME LITERAL filename → must be a cache hit.
        var ctl2 = BuildController(CleanOsv());
        var second = await ctl2.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);

        // Served from cache — no additional upstream call for the artifact.
        Assert.IsType<FileStreamResult>(second).FileStream.Dispose();
        Assert.Equal("HIT", ctl2.Response.Headers["X-Cache"].ToString());
        Assert.Equal(artifactCallsAfterMiss, _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(timestampedFilename) == true));
    }

    /// <summary>
    /// When a SNAPSHOT sidecar (<c>-SNAPSHOT.jar.sha1</c>) is requested before the primary
    /// has been cached, the recursive primary fetch resolves the timestamped artifact and
    /// caches it; the subsequent sidecar re-query must find the row using the LITERAL
    /// <c>-SNAPSHOT.jar</c> filename and return the stored SHA-1.
    ///
    /// Fails on the pre-fix code because the sidecar re-query filters by the literal
    /// filename but the row is stored under the timestamped name, returning NotFound.
    /// </summary>
    [Fact]
    public async Task Snapshot_LiteralSidecarBeforePrimary_ResolvesFromStoredChecksum()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("literal-sidecar-before-primary");
        string sha256 = Sha256Hex(bytes);
        string sha1 = Sha1Hex(bytes);
        const string groupPath = "com/example/litsidecar";
        const string artifactId = "litsidecar";
        const string version = "5.0-SNAPSHOT";
        const string timestamp = "20240505.120000";
        const int buildNumber = 2;

        string timestampedFilename = $"{artifactId}-5.0-{timestamp}-{buildNumber}.jar";
        string artifactPath = $"{groupPath}/{artifactId}/{version}/{timestampedFilename}";
        string literalFilename = $"{artifactId}-{version}.jar";

        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml("com.example.litsidecar", artifactId, version, timestamp, buildNumber));
        StubArtifact(artifactPath, bytes);
        StubSha256Sidecar(artifactPath, sha256);

        var ctl = BuildController(CleanOsv());
        // Request the SHA-1 sidecar using the LITERAL -SNAPSHOT sidecar name,
        // before the primary has been cached.
        var result = await ctl.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}.sha1", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(200, content.StatusCode);
        Assert.Equal(sha1, content.Content);
    }

    [Fact]
    public async Task Snapshot_MetadataAbsent_FallsThroughWithLiteralSnapshotFilename()
    {
        // When upstream returns 404 for the version-level metadata, the controller falls
        // through with the original -SNAPSHOT literal filename. If the repo serves it
        // directly under that name, the fetch succeeds.
        byte[] bytes = Encoding.UTF8.GetBytes("snapshot-literal-payload");
        string sha256 = Sha256Hex(bytes);
        const string groupPath = "com/example/snaplit";
        const string artifactId = "snaplit";
        const string version = "3.0-SNAPSHOT";
        string literalFilename = $"{artifactId}-{version}.jar";
        string artifactPath = $"{groupPath}/{artifactId}/{version}/{literalFilename}";

        // 404 for version-level metadata — no snapshotVersions to parse.
        StubMissing($"{groupPath}/{artifactId}/{version}/maven-metadata.xml");
        StubArtifact(artifactPath, bytes);
        StubSha256Sidecar(artifactPath, sha256);

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);

        var file = Assert.IsType<FileContentResult>(result);
        Assert.Equal(bytes, file.FileContents);
    }

    // ── Sidecar-before-primary ─────────────────────────────────────────────────

    /// <summary>
    /// Requesting a checksum sidecar for a primary not yet in the local cache triggers a
    /// recursive primary fetch, caches the primary, and serves the sidecar computed from
    /// the stored checksum columns.
    /// </summary>
    [Fact]
    public async Task SidecarBeforePrimary_FetchesPrimaryThenServesSidecar()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("sidecar-first-jar");
        string sha256 = Sha256Hex(bytes);
        string sha1 = Sha1Hex(bytes);
        const string path = "com/example/sidecar/1.0/sidecar-1.0.jar";

        StubArtifact(path, bytes);
        StubSha256Sidecar(path, sha256);

        var ctl = BuildController(CleanOsv());
        // Request the SHA-1 sidecar before any primary has been cached.
        var result = await ctl.Download(path + ".sha1", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(sha1, content.Content);
    }

    [Fact]
    public async Task SidecarBeforePrimary_Sha256Sidecar_MatchesPrimaryStoredHash()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("sha256-sidecar-before-primary");
        string sha256 = Sha256Hex(bytes);
        const string path = "com/example/s256/1.0/s256-1.0.jar";

        StubArtifact(path, bytes);
        StubSha256Sidecar(path, sha256);

        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download(path + ".sha256", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(sha256, content.Content);
    }

    // ── Mixed partial-failure scenario (house rule) ───────────────────────────

    /// <summary>
    /// Mixed batch: some primaries are already cached, some are upstream-only; their
    /// sidecars are requested in a mix of cached-primary-first and sidecar-before-primary
    /// orderings. Includes both the TIMESTAMPED and LITERAL -SNAPSHOT request paths for
    /// artifact C so partial-cache state is exercised across all combinations.
    /// All cached entries resolve from the local store; all upstream misses proxy correctly.
    /// </summary>
    [Fact]
    public async Task Mixed_CachedAndUncached_PrimariesAndSidecars_AllResolve()
    {
        // Artifact A: cached (we'll proxy it first, then request via second controller).
        byte[] bytesA = Encoding.UTF8.GetBytes("artifact-a-payload");
        string sha256A = Sha256Hex(bytesA);
        string sha1A = Sha1Hex(bytesA);
        const string pathA = "com/example/mixed/1.0/mixed-1.0.jar";
        StubArtifact(pathA, bytesA);
        StubSha256Sidecar(pathA, sha256A);

        // Artifact B: upstream-only (never cached before).
        byte[] bytesB = Encoding.UTF8.GetBytes("artifact-b-payload");
        string sha256B = Sha256Hex(bytesB);
        string sha1B = Sha1Hex(bytesB);
        const string pathB = "com/example/mixed/2.0/mixed-2.0.jar";
        StubArtifact(pathB, bytesB);
        StubSha256Sidecar(pathB, sha256B);

        // Artifact C: SNAPSHOT only present upstream; fetched via LITERAL name first,
        // then both timestamped and literal paths are verified as cache hits.
        byte[] bytesC = Encoding.UTF8.GetBytes("snapshot-c-payload");
        string sha256C = Sha256Hex(bytesC);
        string sha1C = Sha1Hex(bytesC);
        const string groupPathC = "com/example/mixedsnap";
        const string artifactIdC = "mixedsnap";
        const string versionC = "1.0-SNAPSHOT";
        const string timestampC = "20240303.080000";
        const int buildNumC = 2;
        string tsFilenameC = $"{artifactIdC}-1.0-{timestampC}-{buildNumC}.jar";
        string pathC = $"{groupPathC}/{artifactIdC}/{versionC}/{tsFilenameC}";
        string literalPathC = $"{groupPathC}/{artifactIdC}/{versionC}/{artifactIdC}-{versionC}.jar";
        StubSnapshotMetadata(groupPathC, artifactIdC, versionC,
            SnapshotMetadataXml("com.example.mixedsnap", artifactIdC, versionC, timestampC, buildNumC));
        StubArtifact(pathC, bytesC);
        StubSha256Sidecar(pathC, sha256C);

        // Step 1: Warm artifact A's cache.
        var ctl0 = BuildController(CleanOsv());
        var warmA = await ctl0.Download(pathA, CancellationToken.None);
        Assert.IsType<FileContentResult>(warmA);

        // Step 2: Artifact A — cached primary (HIT).
        var ctl1 = BuildController(CleanOsv());
        var resultA = await ctl1.Download(pathA, CancellationToken.None);
        Assert.IsType<FileStreamResult>(resultA).FileStream.Dispose();
        Assert.Equal("HIT", ctl1.Response.Headers["X-Cache"].ToString());

        // Step 3: Artifact A — sidecar from cache (computed from stored SHA-1).
        var ctl2 = BuildController(CleanOsv());
        var sidecarA = Assert.IsType<ContentResult>(
            await ctl2.Download(pathA + ".sha1", CancellationToken.None));
        Assert.Equal(sha1A, sidecarA.Content);

        // Step 4: Artifact B — upstream MISS primary.
        var ctl3 = BuildController(CleanOsv());
        var resultB = Assert.IsType<FileContentResult>(
            await ctl3.Download(pathB, CancellationToken.None));
        Assert.Equal(bytesB, resultB.FileContents);
        Assert.Equal("MISS", ctl3.Response.Headers["X-Cache"].ToString());

        // Step 5: Artifact B — sidecar-before-re-request (primary already cached after step 4).
        var ctl4 = BuildController(CleanOsv());
        var sidecarB = Assert.IsType<ContentResult>(
            await ctl4.Download(pathB + ".sha1", CancellationToken.None));
        Assert.Equal(sha1B, sidecarB.Content);

        // Step 6: Artifact C — SNAPSHOT upstream MISS via LITERAL name; resolves via metadata.
        var ctl5 = BuildController(CleanOsv());
        var resultC = Assert.IsType<FileContentResult>(
            await ctl5.Download(literalPathC, CancellationToken.None));
        Assert.Equal(bytesC, resultC.FileContents);
        Assert.Equal("MISS", ctl5.Response.Headers["X-Cache"].ToString());

        long tsCallsAfterFirstFetch = _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(tsFilenameC) == true);

        // Step 7: Artifact C — literal SNAPSHOT second request must be a cache hit;
        // no additional upstream call for the artifact.
        var ctl6 = BuildController(CleanOsv());
        var secondC = await ctl6.Download(literalPathC, CancellationToken.None);
        Assert.IsType<FileStreamResult>(secondC).FileStream.Dispose();
        Assert.Equal("HIT", ctl6.Response.Headers["X-Cache"].ToString());
        Assert.Equal(tsCallsAfterFirstFetch, _server.LogEntries.Count(
            e => e.RequestMessage?.Path?.EndsWith(tsFilenameC) == true));

        // Step 8: Artifact C — literal SNAPSHOT sidecar must resolve from stored checksum.
        var ctl7 = BuildController(CleanOsv());
        var sidecarC = Assert.IsType<ContentResult>(
            await ctl7.Download(literalPathC + ".sha1", CancellationToken.None));
        Assert.Equal(sha1C, sidecarC.Content);

        // Step 9: Artifact C — timestamped sidecar also still resolves (regression guard).
        var ctl8 = BuildController(CleanOsv());
        var tsidecarC = Assert.IsType<ContentResult>(
            await ctl8.Download($"{pathC}.sha256", CancellationToken.None));
        Assert.Equal(sha256C, tsidecarC.Content);
    }

    // ── Uploaded-SNAPSHOT dependency-confusion protection ────────────────────
    //
    // An uploaded (locally published) SNAPSHOT artifact must NEVER consult upstream,
    // regardless of what upstream serves at the same coordinate. The freshness block
    // is gated on origin='proxy'; origin='uploaded' skips it entirely and goes straight
    // to the cache-hit path where the uploaded-origin auth gate (token + ReadArtifact)
    // enforces access control. The DO-UPDATE alias SQL in RecordMavenFileAsync is only
    // reachable from ProxyFetchAndCacheAsync, which is only reached when the freshness
    // block determines a proxy miss — so an uploaded row can never be overwritten by
    // that path.

    private static string BasicAuthHeader(string rawToken)
    {
        string encoded = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"user:{rawToken}"));
        return $"Basic {encoded}";
    }

    private async Task<string> IssueReadArtifactTokenAsync()
    {
        string userId = await UserSeeder.InsertAsync(_db, _orgId, $"reader-{Guid.NewGuid():N}@acme.test", "member");
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            _orgId, userId, """["read:artifact","read:metadata"]""", expiresAt: null);
        return raw;
    }

    private async Task SeedUploadedSnapshotAsync(
        string groupId, string artifactId, string version,
        string filename, byte[] bytes)
    {
        string purlName = $"{groupId}:{artifactId}";
        string blobKey = BlobKeys.Hosted(
            _orgId, "maven",
            groupId.Replace('.', '/') + "/" + artifactId,
            version,
            filename);

        await _blobs.PutAsync(blobKey, new MemoryStream(bytes), CancellationToken.None);

        string sha256 = Sha256Hex(bytes);
        string sha1 = Sha1Hex(bytes);
        string md5 = Md5Hex(bytes);

        await using var conn = await _db.OpenAsync();
        string? existingPkgId = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM packages WHERE org_id = @org AND ecosystem = 'maven' AND purl_name = @purl",
            new { org = _orgId, purl = purlName });
        string pkgId = existingPkgId ?? Guid.NewGuid().ToString("N");
        if (existingPkgId is null)
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @org, 'maven', @name, @purl, 0)",
                new { id = pkgId, org = _orgId, name = purlName, purl = purlName });
        }

        string verId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, checksum_sha1, origin)
            VALUES (@id, @pkg, @ver, @purl, @blobKey, @filename, @size, @sha256, @sha1, 'uploaded')
            """,
            new
            {
                id = verId,
                pkg = pkgId,
                ver = version,
                purl = $"pkg:maven/{groupId}/{artifactId}@{version}",
                blobKey,
                filename,
                size = (long)bytes.Length,
                sha256,
                sha1,
            });

        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pv, @filename, NULL, 'jar', @blobKey, @size, @sha256, @sha1, @md5, 'uploaded')
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pv = verId,
                filename,
                blobKey,
                size = (long)bytes.Length,
                sha256,
                sha1,
                md5,
            });
    }

    /// <summary>
    /// Uploading a literal SNAPSHOT artifact (origin='uploaded') and then requesting it
    /// must serve the LOCAL bytes — not upstream bytes — even when upstream hosts the same
    /// coordinate with different content (dependency-confusion scenario).
    ///
    /// This test FAILS on the pre-fix code because the freshness block enters for any
    /// literal-SNAPSHOT hit (including uploaded rows), resolves a upstream timestamped
    /// filename, finds it not cached, and falls through to ProxyFetchAndCacheAsync which
    /// fetches the upstream bytes and overwrites the alias row.
    /// </summary>
    [Fact]
    public async Task UploadedSnapshot_ServesLocalBytes_NotUpstreamBytes()
    {
        byte[] localBytes = System.Text.Encoding.UTF8.GetBytes("uploaded-snapshot-LOCAL-payload");
        byte[] upstreamBytes = System.Text.Encoding.UTF8.GetBytes("upstream-snapshot-DIFFERENT-payload");
        string upstreamSha256 = Sha256Hex(upstreamBytes);

        const string groupId = "com.example.uploaded";
        const string artifactId = "uploaded-snap";
        const string version = "1.0-SNAPSHOT";
        string literalFilename = $"{artifactId}-{version}.jar";

        // Seed the uploaded artifact — this is the locally-published SNAPSHOT.
        await SeedUploadedSnapshotAsync(groupId, artifactId, version, literalFilename, localBytes);

        // Upstream has a DIFFERENT build at the same coordinate (dependency-confusion).
        const string upstreamTimestamp = "20240101.120000";
        const int upstreamBuildNumber = 1;
        string tsFilename = $"{artifactId}-1.0-{upstreamTimestamp}-{upstreamBuildNumber}.jar";
        string groupPath = groupId.Replace('.', '/');
        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml(groupId, artifactId, version, upstreamTimestamp, upstreamBuildNumber));
        StubArtifact($"{groupPath}/{artifactId}/{version}/{tsFilename}", upstreamBytes);
        StubSha256Sidecar($"{groupPath}/{artifactId}/{version}/{tsFilename}", upstreamSha256);

        // Anonymous pull is enabled; uploaded artifacts still require ReadArtifact.
        string rawToken = await IssueReadArtifactTokenAsync();
        var ctl = BuildController(CleanOsv(), BasicAuthHeader(rawToken));
        var result = await ctl.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);

        // Must serve the LOCAL uploaded bytes.
        var file = Assert.IsType<FileStreamResult>(result);
        using var ms = new MemoryStream();
        await file.FileStream.CopyToAsync(ms);
        Assert.Equal(localBytes, ms.ToArray());

        // Must be a HIT (served from local cache), not a MISS (upstream fetch).
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());

        // Upstream must NOT have been consulted for the artifact bytes.
        Assert.DoesNotContain(_server.LogEntries,
            e => e.RequestMessage?.Path?.EndsWith(tsFilename) == true);
    }

    /// <summary>
    /// Requesting an uploaded SNAPSHOT without a token returns 401 — the uploaded-origin
    /// auth gate must fire even when AnonymousPull is enabled, and even though the
    /// freshness block is no longer entered for uploaded rows.
    ///
    /// This test FAILS on the pre-fix code because the freshness block enters, resolves
    /// an upstream timestamped name, finds it uncached, and ProxyFetchAndCacheAsync
    /// bypasses the uploaded-origin auth gate (it calls the proxy pipeline, which has
    /// no per-origin token requirement).
    /// </summary>
    [Fact]
    public async Task UploadedSnapshot_WithoutToken_Returns401()
    {
        byte[] localBytes = System.Text.Encoding.UTF8.GetBytes("uploaded-snapshot-auth-gate-payload");
        byte[] upstreamBytes = System.Text.Encoding.UTF8.GetBytes("upstream-snapshot-auth-gate-payload");
        string upstreamSha256 = Sha256Hex(upstreamBytes);

        const string groupId = "com.example.uploadedauth";
        const string artifactId = "uploaded-auth-snap";
        const string version = "2.0-SNAPSHOT";
        string literalFilename = $"{artifactId}-{version}.jar";

        await SeedUploadedSnapshotAsync(groupId, artifactId, version, literalFilename, localBytes);

        // Upstream has a build at the same coordinate.
        const string upstreamTimestamp = "20240202.090000";
        const int upstreamBuildNumber = 1;
        string tsFilename = $"{artifactId}-2.0-{upstreamTimestamp}-{upstreamBuildNumber}.jar";
        string groupPath = groupId.Replace('.', '/');
        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml(groupId, artifactId, version, upstreamTimestamp, upstreamBuildNumber));
        StubArtifact($"{groupPath}/{artifactId}/{version}/{tsFilename}", upstreamBytes);
        StubSha256Sidecar($"{groupPath}/{artifactId}/{version}/{tsFilename}", upstreamSha256);

        // No token — even with AnonymousPull enabled, uploaded artifacts require ReadArtifact.
        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}", CancellationToken.None);

        // Must be 401, not 200 (from either the local uploaded bytes or upstream bytes).
        Assert.Equal(401, (result as UnauthorizedResult)?.StatusCode
            ?? (result as StatusCodeResult)?.StatusCode
            ?? (result as ObjectResult)?.StatusCode
            ?? 0);

        // Upstream must NOT have been fetched.
        Assert.DoesNotContain(_server.LogEntries,
            e => e.RequestMessage?.Path?.EndsWith(tsFilename) == true);
    }

    /// <summary>
    /// Requesting the sidecar (<c>.sha1</c>) of an uploaded SNAPSHOT without a token
    /// returns 401 — the uploaded-origin auth gate must also fire on the sidecar path.
    ///
    /// On the pre-fix code the sidecar path is isLiteralSnapshot=true, the uploaded row
    /// is found, the freshness block enters, resolves upstream timestamped name, finds it
    /// uncached, and ProxyFetchAndCacheAsync serves the upstream sidecar — bypassing auth.
    /// </summary>
    [Fact]
    public async Task UploadedSnapshot_Sidecar_WithoutToken_Returns401_NoUpstreamFetch()
    {
        byte[] localBytes = System.Text.Encoding.UTF8.GetBytes("uploaded-snapshot-sidecar-auth-payload");
        byte[] upstreamBytes = System.Text.Encoding.UTF8.GetBytes("upstream-snapshot-sidecar-payload");
        string upstreamSha256 = Sha256Hex(upstreamBytes);

        const string groupId = "com.example.uploadedsidecarauth";
        const string artifactId = "uploaded-sidecar-snap";
        const string version = "3.0-SNAPSHOT";
        string literalFilename = $"{artifactId}-{version}.jar";

        await SeedUploadedSnapshotAsync(groupId, artifactId, version, literalFilename, localBytes);

        const string upstreamTimestamp = "20240303.080000";
        const int upstreamBuildNumber = 2;
        string tsFilename = $"{artifactId}-3.0-{upstreamTimestamp}-{upstreamBuildNumber}.jar";
        string groupPath = groupId.Replace('.', '/');
        StubSnapshotMetadata(groupPath, artifactId, version,
            SnapshotMetadataXml(groupId, artifactId, version, upstreamTimestamp, upstreamBuildNumber));
        StubArtifact($"{groupPath}/{artifactId}/{version}/{tsFilename}", upstreamBytes);
        StubSha256Sidecar($"{groupPath}/{artifactId}/{version}/{tsFilename}", upstreamSha256);

        // No token — sidecar must also be gated by the uploaded-origin auth check.
        var ctl = BuildController(CleanOsv());
        var result = await ctl.Download($"{groupPath}/{artifactId}/{version}/{literalFilename}.sha1", CancellationToken.None);

        Assert.Equal(401, (result as UnauthorizedResult)?.StatusCode
            ?? (result as StatusCodeResult)?.StatusCode
            ?? (result as ObjectResult)?.StatusCode
            ?? 0);

        // Upstream must NOT have been fetched.
        Assert.DoesNotContain(_server.LogEntries,
            e => e.RequestMessage?.Path?.EndsWith(tsFilename) == true);
    }

    /// <summary>
    /// Mixed partial-failure: one uploaded SNAPSHOT (dep-confusion protection) and one
    /// proxy SNAPSHOT (normal freshness-check path) coexist correctly.
    ///
    /// - The uploaded SNAPSHOT serves local bytes and enforces the auth gate.
    /// - The proxy SNAPSHOT exercises the normal freshness path and falls through to upstream
    ///   when the build is not cached.
    ///
    /// Fails on pre-fix code because the uploaded SNAPSHOT enters the freshness block and
    /// the proxy fetch replaces the local artifact with upstream bytes.
    /// </summary>
    [Fact]
    public async Task Mixed_UploadedAndProxySnapshot_UploadedWins_ProxyFetchesUpstream()
    {
        // Artifact U: uploaded SNAPSHOT — local bytes must win.
        byte[] localBytesU = System.Text.Encoding.UTF8.GetBytes("uploaded-mixed-LOCAL");
        byte[] upstreamBytesU = System.Text.Encoding.UTF8.GetBytes("upstream-mixed-DIFFERENT");
        string upstreamSha256U = Sha256Hex(upstreamBytesU);

        const string groupIdU = "com.example.mixeduploaded";
        const string artifactIdU = "mixed-uploaded";
        const string versionU = "1.0-SNAPSHOT";
        string literalFilenameU = $"{artifactIdU}-{versionU}.jar";
        string groupPathU = groupIdU.Replace('.', '/');

        await SeedUploadedSnapshotAsync(groupIdU, artifactIdU, versionU, literalFilenameU, localBytesU);

        const string tsU = "20240101.120000";
        const int bnU = 1;
        string tsFilenameU = $"{artifactIdU}-1.0-{tsU}-{bnU}.jar";
        StubSnapshotMetadata(groupPathU, artifactIdU, versionU,
            SnapshotMetadataXml(groupIdU, artifactIdU, versionU, tsU, bnU));
        StubArtifact($"{groupPathU}/{artifactIdU}/{versionU}/{tsFilenameU}", upstreamBytesU);
        StubSha256Sidecar($"{groupPathU}/{artifactIdU}/{versionU}/{tsFilenameU}", upstreamSha256U);

        // Artifact P: proxy SNAPSHOT — absent from local cache; upstream fetch expected.
        byte[] upstreamBytesP = System.Text.Encoding.UTF8.GetBytes("proxy-mixed-upstream");
        string upstreamSha256P = Sha256Hex(upstreamBytesP);

        const string groupIdP = "com.example.mixedproxy";
        const string artifactIdP = "mixed-proxy";
        const string versionP = "2.0-SNAPSHOT";
        string literalFilenameP = $"{artifactIdP}-{versionP}.jar";
        string groupPathP = groupIdP.Replace('.', '/');

        const string tsP = "20240202.090000";
        const int bnP = 3;
        string tsFilenameP = $"{artifactIdP}-2.0-{tsP}-{bnP}.jar";
        string artifactPathP = $"{groupPathP}/{artifactIdP}/{versionP}/{tsFilenameP}";
        StubSnapshotMetadata(groupPathP, artifactIdP, versionP,
            SnapshotMetadataXml(groupIdP, artifactIdP, versionP, tsP, bnP));
        StubArtifact(artifactPathP, upstreamBytesP);
        StubSha256Sidecar(artifactPathP, upstreamSha256P);

        // Step 1: Uploaded SNAPSHOT with a token that carries ReadArtifact.
        string rawToken = await IssueReadArtifactTokenAsync();
        var ctlU = BuildController(CleanOsv(), BasicAuthHeader(rawToken));
        var resultU = await ctlU.Download($"{groupPathU}/{artifactIdU}/{versionU}/{literalFilenameU}", CancellationToken.None);

        var streamU = Assert.IsType<FileStreamResult>(resultU);
        using var msU = new MemoryStream();
        await streamU.FileStream.CopyToAsync(msU);
        Assert.Equal(localBytesU, msU.ToArray());         // LOCAL bytes, not upstream
        Assert.Equal("HIT", ctlU.Response.Headers["X-Cache"].ToString());
        Assert.DoesNotContain(_server.LogEntries,          // upstream artifact NOT fetched
            e => e.RequestMessage?.Path?.EndsWith(tsFilenameU) == true);

        // Step 2: Uploaded SNAPSHOT without a token must return 401.
        var ctlUNoAuth = BuildController(CleanOsv());
        var resultUNoAuth = await ctlUNoAuth.Download($"{groupPathU}/{artifactIdU}/{versionU}/{literalFilenameU}", CancellationToken.None);
        Assert.Equal(401, (resultUNoAuth as UnauthorizedResult)?.StatusCode
            ?? (resultUNoAuth as StatusCodeResult)?.StatusCode
            ?? (resultUNoAuth as ObjectResult)?.StatusCode
            ?? 0);

        // Step 3: Proxy SNAPSHOT (normal path) fetches from upstream.
        var ctlP = BuildController(CleanOsv());
        var resultP = await ctlP.Download($"{groupPathP}/{artifactIdP}/{versionP}/{literalFilenameP}", CancellationToken.None);
        var fileP = Assert.IsType<FileContentResult>(resultP);
        Assert.Equal(upstreamBytesP, fileP.FileContents);
        Assert.Equal("MISS", ctlP.Response.Headers["X-Cache"].ToString());
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class WireMockHandler : HttpMessageHandler
    {
        private readonly WireMockServer _server;
        public WireMockHandler(WireMockServer server) => _server = server;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            string url = _server.Urls[0] + request.RequestUri!.PathAndQuery;
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
