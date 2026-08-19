using System.Security.Claims;
using System.Security.Cryptography;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The supply-chain invariant these pin for the hosted Maven publish path (which writes the
/// blob and its rows directly, outside <c>IPackagePublishService</c>): for every committed row —
/// both the per-file <c>maven_version_files</c> row and the shared <c>package_versions</c> row —
/// the bytes stored under the row's <c>blob_key</c> hash to the row's <c>checksum_sha256</c>.
/// The ingest-time digest is the only integrity check this registry performs (nothing re-verifies
/// at download, and the digest is what the client's checksum sidecar request is answered from),
/// so a row that outlives its bytes silently serves an artifact nobody vouched for.
///
/// Maven's two rows diverge independently: <c>package_versions</c> is written once per version
/// (whichever file was pushed first), while <c>maven_version_files</c> is upserted per file and
/// repointed on republish. The gate (no sleeps) parks one publisher inside PutAsync at each of
/// the two points that turn a shared coordinate-addressed key into a permanent swap: parking
/// before the write strands the shared version row over the wrong bytes; parking after it strands
/// the per-file row.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenPublishBlobRaceTests : IAsyncLifetime
{
    private const string Path = "com/example/racelib/1.0/racelib-1.0.jar";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private string _orgId = null!;
    private string _userId = null!;
    private TokenRepository _tokens = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _tokens = new TokenRepository(_db, _clock);
        _orgId = await OrgSeeder.InsertAsync(_db, "acme-maven-race");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "owner@acme.test", "owner");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task ConcurrentPublish_SameFile_DifferentBytes_VersionRowChecksumMatchesStoredBytes()
    {
        // Publisher A is parked BEFORE its bytes reach the store, so A's artifact lands AFTER B
        // has committed both rows. Sharing one coordinate-addressed key, that leaves the shared
        // package_versions row advertising sha(B) over a blob holding A's bytes.
        string token = await IssueTokenAsync();
        byte[] bytesA = Bytes(0xAA, 128);
        byte[] bytesB = Bytes(0xBB, 200);

        var gate = new GatedPutBlobStore(_blobs, writeBeforePark: false);
        var slow = BuildController(gate, token, bytesA);
        var fast = BuildController(_blobs, token, bytesB);

        var slowPublish = Task.Run(() => slow.Publish(Path, CancellationToken.None));
        await gate.Reached;

        Assert.Equal(201, ((StatusCodeResult)await fast.Publish(Path, CancellationToken.None)).StatusCode);

        gate.Release();
        Assert.Equal(201, ((StatusCodeResult)await slowPublish).StatusCode);

        // The version row was created by B and is never repointed, so it must still name B's bytes.
        var version = await VersionRowAsync();
        Assert.Equal(Sha256(bytesB), version.Sha256);
        await AssertStoredBytesHashToAsync(version.BlobKey, version.Sha256);

        // The per-file row was upserted last by A, so it must name A's bytes. Both artifacts
        // survive under their own content-addressed keys — neither publisher overwrote the
        // bytes the other's committed row points at.
        var file = await FileRowAsync();
        Assert.Equal(Sha256(bytesA), file.Sha256);
        await AssertStoredBytesHashToAsync(file.BlobKey, file.Sha256);
    }

    [Fact]
    public async Task ConcurrentPublish_SameFile_DifferentBytes_FileRowChecksumMatchesStoredBytes()
    {
        // Same race, opposite interleaving: publisher A is parked AFTER its bytes reach the store,
        // so the puts land A-then-B while the row writes land B-then-A. Sharing one
        // coordinate-addressed key, the blob ends up holding B's bytes while the
        // maven_version_files row (upserted last by A) advertises sha(A) — the per-file checksum
        // and the artifact behind it swap, which is what a client's sidecar checksum request and
        // every downstream integrity claim are answered from.
        string token = await IssueTokenAsync();
        byte[] bytesA = Bytes(0xCC, 96);
        byte[] bytesB = Bytes(0xDD, 160);

        var gate = new GatedPutBlobStore(_blobs, writeBeforePark: true);
        var slow = BuildController(gate, token, bytesA);
        var fast = BuildController(_blobs, token, bytesB);

        var slowPublish = Task.Run(() => slow.Publish(Path, CancellationToken.None));
        await gate.Reached;

        Assert.Equal(201, ((StatusCodeResult)await fast.Publish(Path, CancellationToken.None)).StatusCode);

        gate.Release();
        Assert.Equal(201, ((StatusCodeResult)await slowPublish).StatusCode);

        var file = await FileRowAsync();
        Assert.Equal(Sha256(bytesA), file.Sha256);
        await AssertStoredBytesHashToAsync(file.BlobKey, file.Sha256);

        var version = await VersionRowAsync();
        Assert.Equal(Sha256(bytesB), version.Sha256);
        await AssertStoredBytesHashToAsync(version.BlobKey, version.Sha256);
    }

    [Fact]
    public async Task Republish_DifferentBytes_BothRowsStillNameTheirOwnBytes()
    {
        // Sequential republish of one file coordinate. The maven_version_files row is repointed
        // (ON CONFLICT DO UPDATE) at the new artifact, but the shared package_versions row keeps
        // the first publish's blob_key and checksum. A coordinate-addressed key put the new bytes
        // on top of the old ones, so that untouched version row was left advertising a digest its
        // blob no longer had. Content-addressing gives the republished bytes their own key: the
        // repointed file row names the new artifact, the version row still names the old one, and
        // both are true. The superseded blob is unreferenced only once no row names it.
        string token = await IssueTokenAsync();
        byte[] first = Bytes(0x11, 64);
        byte[] second = Bytes(0x22, 112);

        Assert.Equal(201, ((StatusCodeResult)await BuildController(_blobs, token, first)
            .Publish(Path, CancellationToken.None)).StatusCode);
        Assert.Equal(201, ((StatusCodeResult)await BuildController(_blobs, token, second)
            .Publish(Path, CancellationToken.None)).StatusCode);

        var file = await FileRowAsync();
        Assert.Equal(Sha256(second), file.Sha256);
        await AssertStoredBytesHashToAsync(file.BlobKey, file.Sha256);

        var version = await VersionRowAsync();
        Assert.Equal(Sha256(first), version.Sha256);
        await AssertStoredBytesHashToAsync(version.BlobKey, version.Sha256);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static byte[] Bytes(byte fill, int length)
    {
        byte[] bytes = new byte[length];
        Array.Fill(bytes, fill);
        return bytes;
    }

    private static string Sha256(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private async Task<(string BlobKey, string Sha256)> VersionRowAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = (await conn.QueryAsync<(string BlobKey, string Sha256)>(
            """
            SELECT pv.blob_key AS BlobKey, pv.checksum_sha256 AS Sha256
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.ecosystem = 'maven'
            """,
            new { org = _orgId })).ToList();
        return Assert.Single(rows);
    }

    private async Task<(string BlobKey, string Sha256)> FileRowAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = (await conn.QueryAsync<(string BlobKey, string Sha256)>(
            """
            SELECT mvf.blob_key AS BlobKey, mvf.checksum_sha256 AS Sha256
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND mvf.filename = 'racelib-1.0.jar'
            """,
            new { org = _orgId })).ToList();
        return Assert.Single(rows);
    }

    private async Task AssertStoredBytesHashToAsync(string blobKey, string expectedSha256)
    {
        await using var stored = await _blobs.GetAsync(BlobKeys.StoreKey(blobKey));
        Assert.NotNull(stored);
        using var buffer = new MemoryStream();
        await stored!.CopyToAsync(buffer);
        Assert.Equal(expectedSha256, Sha256(buffer.ToArray()));
    }

    private async Task<string> IssueTokenAsync()
    {
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            _orgId, _userId, """["publish:maven"]""", expiresAt: null);
        return raw;
    }

    // Builds a MavenController over the given blob store with the body and bearer token already
    // bound, so two of them can be driven concurrently against one metadata store.
    private MavenController BuildController(IBlobStore blobs, string token, byte[] body)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme-maven-race.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme-maven-race");
        http.Request.Headers.Authorization = $"Bearer {token}";
        http.Request.Body = new MemoryStream(body);
        http.Request.ContentLength = body.LongLength;
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, _userId),
                new Claim("sub", _userId),
                new Claim("org_id", _orgId),
                new Claim("tid", _orgId),
                new Claim("role", "owner"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var metadataCache = new Dependably.Infrastructure.Caching.RenderedResponseCache<Dependably.Infrastructure.Caching.MavenMetadataKey>(
            new MemoryCache(new MemoryCacheOptions { SizeLimit = 8 * 1024 * 1024 }),
            Dependably.Infrastructure.Caching.MetadataCacheKeys.MavenMetadata);
        var svc = new MavenControllerServices(
            Packages: new PackageRepository(_db),
            Tokens: _tokens,
            Audit: new AuditRepository(_db),
            Orgs: new OrgRepository(_db),
            Blobs: blobs,
            Db: _db,
            Upstream: null!,
            Config: null!,
            ProxyFetch: null!,
            BlockGate: TestBlockGate.Create(_db, _clock),
            ReservedNamespaces: new ReservedNamespaceService(
                _db, new MemoryCache(new MemoryCacheOptions()), _clock),
            Registries: new UpstreamRegistryResolver(
                new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured())),
            MetadataCache: metadataCache,
            Invalidation: Dependably.Tests.Infrastructure.TestMetadataInvalidation.ForMaven(metadataCache),
            CacheOptions: new RenderedMetadataCacheOptions(TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(5)),
            Log: NullLogger<MavenController>.Instance,
            CacheArtifacts: new CacheArtifactRepository(_db),
            TenantAccess: new TenantArtifactAccessRepository(_db),
            Vulns: new VulnerabilityRepository(_db, TimeProvider.System),
            Time: _clock,
            CacheRecorder: new CacheAccessRecorder(
                new CacheArtifactRepository(_db),
                new TenantArtifactAccessRepository(_db),
                NullLogger<CacheAccessRecorder>.Instance,
                _clock),
            MavenProvenance: new Dependably.Protocol.Provenance.MavenProvenanceVerifier(
                new StubPerOrgTrustAnchorStore(),
                NullLogger<Dependably.Protocol.Provenance.MavenProvenanceVerifier>.Instance),
            EdgeGuard: TestEdgeMode.DisabledPublishGuard(),
            Staging: new StagingOptions(System.IO.Path.GetTempPath(), 0),
            Licenses: new LicenseRepository(_db, _clock, TestNormalizers.License(_db)));

        return new MavenController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }
}
