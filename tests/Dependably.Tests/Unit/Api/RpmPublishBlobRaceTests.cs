using System.Security.Cryptography;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The supply-chain invariant these pin for the hosted RPM publish path (which writes the
/// registry tier and the version row directly, outside <c>IPackagePublishService</c>): for every
/// committed <c>package_versions</c> row, the bytes stored under the row's <c>blob_key</c> hash
/// to the row's <c>checksum_sha256</c>. The ingest-time digest is the only integrity check this
/// registry performs — nothing re-verifies at download, and <c>repodata/primary.xml</c> seals
/// that same digest for <c>dnf</c> — so a row that outlives its bytes silently serves an
/// artifact nobody vouched for.
///
/// The race is forced with a gate, not a sleep: one uploader is parked inside
/// <see cref="GatedPutBlobStore.PutAsync"/> until the other has committed its version row, so
/// the loser's bytes and the winner's row land in the order that a coordinate-addressed blob
/// key (last writer wins on the shared key) turns into permanent divergence.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmPublishBlobRaceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private string _orgId = null!;
    private TokenRepository _tokens = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, 'acme-rpm-race')", new { id = _orgId });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, anonymous_pull) VALUES (@id, 1)", new { id = _orgId });
        _tokens = new TokenRepository(_db, _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task ConcurrentUpload_SameNevra_DifferentBytes_RowChecksumMatchesStoredBytes()
    {
        // Uploader A is parked BEFORE its bytes reach the store, so A's artifact lands AFTER B
        // has already committed its version row. Sharing one coordinate-addressed key, that
        // leaves B's row advertising sha(B) over a blob holding A's bytes — forever, because
        // nothing re-hashes a hosted artifact after ingest.
        string raw = await SeedUserTokenAsync();
        byte[] bytesA = Rpm(fill: 0xAA, filler: 128);
        byte[] bytesB = Rpm(fill: 0xBB, filler: 200);

        var gate = new GatedPutBlobStore(_blobs, writeBeforePark: false);
        var slow = BuildController(gate, raw, bytesA);
        var fast = BuildController(_blobs, raw, bytesB);

        var slowUpload = Task.Run(() => slow.Upload(CancellationToken.None));
        await gate.Reached;

        Assert.Equal(201, ((StatusCodeResult)await fast.Upload(CancellationToken.None)).StatusCode);

        gate.Release();
        Assert.Equal(201, ((StatusCodeResult)await slowUpload).StatusCode);

        // One version row for the NEVRA — and it must name bytes that hash to the checksum
        // stored beside it.
        var row = await SingleVersionRowAsync();
        Assert.Equal(Sha256(bytesB), row.Sha256);
        await AssertStoredBytesHashToAsync(row.BlobKey, row.Sha256);

        // The parked uploader's bytes went to their own content-addressed key rather than over
        // the committed row's artifact: both artifacts survive, neither row is a lie. The
        // unreferenced one is the orphan reconciler's to reclaim.
        Assert.True(await _blobs.ExistsAsync(
            BlobKeys.HostedArtifact(_orgId, "rpm", "zlib", "1.2.11-39.el9", Sha256(bytesA),
                "zlib-1.2.11-39.el9.x86_64.rpm")));
    }

    [Fact]
    public async Task Reupload_SameNevra_DifferentBytes_CommittedRowStillNamesItsOwnBytes()
    {
        // Sequential re-upload of a NEVRA the tenant already holds. The version row is written
        // once and never repointed, so a coordinate-addressed key let the second upload replace
        // the bytes underneath the committed row while its checksum (the one repodata seals for
        // dnf) kept naming the first upload's digest. Content-addressing gives the new bytes
        // their own key, so the committed row and the artifact it names stay in agreement.
        string raw = await SeedUserTokenAsync();
        byte[] first = Rpm(fill: 0x11, filler: 64);
        byte[] second = Rpm(fill: 0x22, filler: 96);

        Assert.Equal(201, ((StatusCodeResult)await BuildController(_blobs, raw, first)
            .Upload(CancellationToken.None)).StatusCode);
        Assert.Equal(201, ((StatusCodeResult)await BuildController(_blobs, raw, second)
            .Upload(CancellationToken.None)).StatusCode);

        var row = await SingleVersionRowAsync();
        Assert.Equal(Sha256(first), row.Sha256);
        await AssertStoredBytesHashToAsync(row.BlobKey, row.Sha256);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    // A synthetic RPM for one fixed NEVRA (zlib-1.2.11-39.el9.x86_64), made byte-distinct by a
    // filler tail. The header the validator reads sits at the file start, so the tail changes
    // the artifact's SHA-256 without changing its coordinate.
    private static byte[] Rpm(byte fill, int filler)
    {
        byte[] header = RpmControllerUnitTests.BuildSyntheticRpm("zlib", "1.2.11", "39.el9", "x86_64");
        byte[] tail = new byte[filler];
        Array.Fill(tail, fill);
        return [.. header, .. tail];
    }

    private static string Sha256(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private async Task<(string BlobKey, string Sha256)> SingleVersionRowAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = (await conn.QueryAsync<(string BlobKey, string Sha256)>(
            """
            SELECT pv.blob_key AS BlobKey, pv.checksum_sha256 AS Sha256
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.ecosystem = 'rpm'
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

    private async Task<string> SeedUserTokenAsync()
    {
        string userId = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @t, @e, 'x', 'owner')",
                new { id = userId, t = _orgId, e = $"{userId}@test" });
        }

        var (raw, _) = await _tokens.CreateUserTokenAsync(
            _orgId, userId, """["publish:rpm"]""", expiresAt: null);
        return raw;
    }

    // Builds an RpmController over the given registry-tier blob store with the body and bearer
    // token already bound, so two of them can be driven concurrently against one metadata store.
    private RpmController BuildController(IBlobStore registry, string token, byte[] body)
    {
        var cacheArtifacts = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var svc = new RpmControllerServices(
            new PackageRepository(_db),
            _tokens,
            new AuditRepository(_db),
            new OrgRepository(_db),
            new TieredBlobStorage(_blobs, registry),
            _db,
            new RpmRepodataService(_db, NullLogger<RpmRepodataService>.Instance, _clock),
            new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured())),
            new MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache>(
                new MemoryCache(new MemoryCacheOptions()), MetadataCacheKeys.RpmMergedRepodata),
            new RenderedResponseCache<RpmLocalRepodataKey>(
                new MemoryCache(new MemoryCacheOptions()), MetadataCacheKeys.RpmLocalRepodata),
            _clock,
            new CacheAccessRecorder(cacheArtifacts, tenantAccess,
                NullLogger<CacheAccessRecorder>.Instance, _clock),
            cacheArtifacts,
            tenantAccess,
            new Dependably.Protocol.Provenance.RpmProvenanceVerifier(
                new StubPerOrgTrustAnchorStore(),
                NullLogger<Dependably.Protocol.Provenance.RpmProvenanceVerifier>.Instance),
            TestEdgeMode.DisabledPublishGuard(),
            TestBlockGate.Create(_db, _clock),
            new StagingOptions(Path.GetTempPath(), 0),
            new LicenseRepository(_db, _clock, TestNormalizers.License(_db)));

        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme-rpm-race");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme-rpm-race.example.test");
        http.Request.Body = new MemoryStream(body);
        http.Request.ContentLength = body.Length;
        http.Request.Headers.Authorization = $"Bearer {token}";

        return new RpmController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }
}
