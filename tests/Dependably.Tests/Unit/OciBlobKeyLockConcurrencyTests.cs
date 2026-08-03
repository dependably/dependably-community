using System.Security.Claims;
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
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Concurrency regression tests for the content-addressed OCI blob-key lock that serialises
/// finalize and delete of a single physical blob.
///
/// Covers:
/// - <see cref="OciBlobKeyLock"/> primitive: same key is mutually exclusive; distinct keys on
///   distinct stripes proceed concurrently.
/// - Quota double-charge race (MEDIUM): two concurrent finalizes of the same new blob must
///   reserve the tenant's storage quota exactly once, not twice.
/// - Dangling-row race (LOW): a dedup skip-the-write push racing a refcount-guarded physical
///   delete of the same key must never leave a metadata row pointing at a deleted blob. There are
///   two production delete sites — the Distribution-Spec digest delete (<c>OciController.Delete</c>)
///   and the management-API version yank (<c>OrgController.DeleteVersion</c>) — and both are driven
///   here as themselves, racing a real <c>OciUploadService.StoreManifestAsync</c>. Neither side is
///   re-implemented in the test: a copy of the code under test would keep passing if the production
///   lock were removed, which is exactly what these tests exist to catch.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciBlobKeyLockConcurrencyTests : IAsyncLifetime
{
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
    private const string Repository = "library/app";

    // How long a blocked delete is given to (wrongly) complete before the test concludes it really
    // is waiting on the lock. Only ever consumed in full on a regression, so it costs nothing on a
    // green run; the pass/fail signal is the lock, not the duration.
    private static readonly TimeSpan RaceWindow = TimeSpan.FromSeconds(2);

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _registry = new();
    private readonly InMemoryBlobStore _cache = new();

    private OrgRepository _orgs = null!;
    private PackageRepository _packages = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private string _orgA = null!;
    private string _orgB = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgs = new OrgRepository(_db);
        _packages = new PackageRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);
        await using var conn = await _db.OpenAsync();
        _orgA = Guid.NewGuid().ToString("N");
        _orgB = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, 'org-a')", new { id = _orgA });
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, 'org-b')", new { id = _orgB });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Lock primitive ─────────────────────────────────────────────────────────

    [Fact]
    public async Task OciBlobKeyLock_SameKey_SerialisesHolders()
    {
        var locks = new OciBlobKeyLock();
        int concurrent = 0;
        int maxConcurrent = 0;

        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            await using (await locks.AcquireAsync("sha256:same-key", default))
            {
                int now = Interlocked.Increment(ref concurrent);
                RecordMax(ref maxConcurrent, now);
                await Task.Delay(15);
                Interlocked.Decrement(ref concurrent);
            }
        })).ToArray();

        await Task.WhenAll(tasks);

        Assert.Equal(1, maxConcurrent);
    }

    [Fact]
    public async Task OciBlobKeyLock_DistinctKeysOnDistinctStripes_DoNotBlock()
    {
        const int stripes = 64;
        var locks = new OciBlobKeyLock(stripes);
        (string first, string second) = TwoKeysOnDistinctStripes(stripes);

        await using (await locks.AcquireAsync(first, default))
        {
            // Acquiring a different stripe must not block on the held key. If they shared a stripe
            // this would never complete within the timeout.
            var acquireSecond = locks.AcquireAsync(second, default);
            var winner = await Task.WhenAny(acquireSecond, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(acquireSecond, winner);
            await using (await acquireSecond) { }
        }
    }

    // ── Finding 1: quota double-charge race ──────────────────────────────────────

    [Fact]
    public async Task BlobFinalize_ConcurrentSameNewBlob_ReservesQuotaOnce()
    {
        // Two concurrent finalizes of the SAME new content-addressed blob (same tenant). Without
        // the per-key lock both observe "does not exist" and both reserve the byte count, so one
        // physically-stored blob is charged twice. The lock serialises them, so the second
        // finalize sees the blob the first stored and reserves nothing.
        //
        // The quota is pinned to exactly one blob's worth, which is what gives that its teeth: a
        // second reservation taken while the first is still in flight would be weighed against
        // the same ceiling and refused outright.
        byte[] blob = RandomBytes(4096);
        await _orgs.SetStorageQuotaBytesAsync(_orgA, blob.Length);
        string hex = HexOf(blob);
        string digest = "sha256:" + hex;
        string blobKey = BlobKeys.OciBlob("sha256", hex);

        var gate = new GatingBlobStore(_registry) { GatePutKey = blobKey };
        var svc = BuildService(gate, new OciBlobKeyLock());

        var session1 = await StartAndStageAsync(svc, _orgA, blob);
        var session2 = await StartAndStageAsync(svc, _orgA, blob);

        var t1 = Task.Run(() => svc.FinalizeBlobAsync(_orgA, session1, digest, default));
        // t1 is now blocked inside its (first, gated) PutAsync — it has already reserved quota.
        await gate.FirstPutEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var t2 = Task.Run(() => svc.FinalizeBlobAsync(_orgA, session2, digest, default));
        // OLD (no lock): t2 sees the blob still absent, reserves again, reaches its own ungated
        // Put, stores, and completes. NEW: t2 blocks on the per-key lock until t1 releases.
        bool t2CompletedEarly = await Task.WhenAny(t2, Task.Delay(TimeSpan.FromSeconds(2))) == t2;

        gate.ReleaseFirstPut();
        var r1 = await t1;
        var r2 = await t2;

        Assert.Equal(OciFinalizeStatus.Ok, r1.Status);
        Assert.Equal(OciFinalizeStatus.Ok, r2.Status);
        // The lock keeps t2 from finalizing before t1 releases; on the fixed code it must NOT have
        // completed during the bounded wait.
        Assert.False(t2CompletedEarly);

        Assert.Equal(blob.Length, await _orgs.GetLiveStorageBytesAsync(_orgA));
    }

    // ── Finding 2: dangling-row race (push vs refcount-guarded delete) ────────────
    //
    // Both tests below run the same interleave against a different production delete site:
    //
    //   1. Org A holds the only reference to a manifest blob (row + physical file present).
    //   2. Org B pushes the SAME manifest. Its registry blocks inside the exists-check, so B sits
    //      in its critical section having observed "present" but not yet recorded its row — the
    //      real TOCTOU window a dedup push occupies.
    //   3. Org A's delete runs concurrently. It must not be able to count references and remove
    //      the file while B is mid-push.
    //   4. B finishes: it skips the write (dedup) and records its row.
    //
    // Unserialised, A's count reads zero, the file is deleted, and B's row is left dangling.

    [Fact]
    public async Task ManifestDigestDelete_RacingDedupPush_WaitsForTheLock_AndKeepsTheReferencedBlob()
    {
        // Drives the real OciController.Delete (Distribution-Spec digest delete).
        var race = await ArrangeRaceAsync();

        string rawToken = await SeedYankTokenAsync(_orgA);
        var controller = BuildOciController(_orgA, rawToken, race.SharedLock);

        var delete = Task.Run(() => controller.Delete($"{Repository}/manifests/{race.Digest}", default));
        bool deleteCompletedEarly = await CompletesWithin(delete, RaceWindow);

        var result = await race.CompletePushAndAwaitDeleteAsync(delete);

        Assert.False(deleteCompletedEarly,
            "the digest delete must block on the per-key lock the in-flight push holds");
        Assert.Equal(StatusCodes.Status204NoContent, Assert.IsAssignableFrom<StatusCodeResult>(result).StatusCode);
        await AssertNoDanglingRowAsync(race);
    }

    [Fact]
    public async Task ManagementVersionYank_RacingDedupPush_WaitsForTheLock_AndKeepsTheReferencedBlob()
    {
        // Drives the real OrgController.DeleteVersion (management-API yank, the OCI arm).
        var race = await ArrangeRaceAsync();

        string ownerId = await SeedOwnerAsync(_orgA);
        await SeedOciVersionRowsAsync(_orgA, race.Digest, race.BlobKey);
        var controller = BuildOrgController(_orgA, ownerId, race.SharedLock);

        var delete = Task.Run(() => controller.DeleteVersion("oci", Repository, race.Digest, default));
        bool deleteCompletedEarly = await CompletesWithin(delete, RaceWindow);

        var result = await race.CompletePushAndAwaitDeleteAsync(delete);

        Assert.False(deleteCompletedEarly,
            "the version yank must block on the per-key lock the in-flight push holds");
        Assert.IsType<NoContentResult>(result);
        await AssertNoDanglingRowAsync(race);
    }

    // ── Race arrangement ─────────────────────────────────────────────────────────

    // Org A holds the sole reference to a manifest blob; org B's real manifest push is parked
    // inside its critical section, having observed the blob present but not yet recorded its row.
    private sealed record RaceState(
        string Digest,
        string BlobKey,
        OciBlobKeyLock SharedLock,
        GatingBlobStore Gate,
        Task<OciManifestStoreResult> Push)
    {
        // Releases org B's push and waits for both sides to settle.
        public async Task<T> CompletePushAndAwaitDeleteAsync<T>(Task<T> delete)
        {
            Gate.ReleaseFirstExists();
            Assert.Equal(OciManifestStatus.Ok, (await Push).Status);
            return await delete;
        }
    }

    private async Task<RaceState> ArrangeRaceAsync()
    {
        // StoreManifestAsync validates that every referenced blob exists for the pushing org, so
        // org B gets the config blob its manifest names. The race is about the manifest's own
        // content-addressed blob, which both orgs share.
        byte[] config = Encoding.UTF8.GetBytes("{}");
        string configDigest = "sha256:" + HexOf(config);
        await SeedConfigBlobAsync(_orgB, configDigest, config);

        byte[] manifest = Encoding.UTF8.GetBytes(
            $$"""
            {"schemaVersion":2,"mediaType":"{{ManifestMediaType}}",
             "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{{configDigest}}","size":{{config.Length}}},
             "layers":[]}
            """);
        string hex = HexOf(manifest);
        string digest = "sha256:" + hex;
        string blobKey = BlobKeys.OciBlob("sha256", hex);

        await SeedManifestBlobAsync(_orgA, digest, blobKey, manifest);
        Assert.True(await _registry.ExistsAsync(blobKey));

        var sharedLock = new OciBlobKeyLock();

        // Org B's push runs against a registry that blocks inside the exists-check for this key.
        var gate = new GatingBlobStore(_registry) { GateExistsKey = blobKey };
        var svcB = BuildService(gate, sharedLock);
        var push = Task.Run(() => svcB.StoreManifestAsync(_orgB, Repository, "v1", manifest, ManifestMediaType, default));
        await gate.FirstExistsEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));

        return new RaceState(digest, blobKey, sharedLock, gate, push);
    }

    // The invariant both delete sites must hold: org B recorded a row, so the blob it names stays.
    private async Task AssertNoDanglingRowAsync(RaceState race)
    {
        Assert.True(await BlobRowExistsAsync(_orgB, race.Digest), "org B should have recorded its blob row");
        Assert.True(await _registry.ExistsAsync(race.BlobKey), "the physical blob org B references must exist");
    }

    private static async Task<bool> CompletesWithin(Task task, TimeSpan window)
        => await Task.WhenAny(task, Task.Delay(window)) == task;

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private OciUploadService BuildService(IBlobStore registry, OciBlobKeyLock blobKeyLock)
    {
        var tiered = new TieredBlobStorage(_cache, registry);
        var cfg = new ConfigurationBuilder().Build();
        var stagingOptions = new StagingOptions(Path.GetTempPath(), FloorBytes: 0);
        var recorder = new OciImageLicenseRecorder(_db, tiered, TimeProvider.System, NullLogger<OciImageLicenseRecorder>.Instance,
            new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)));
        return new OciUploadService(new OciUploadService.Dependencies(
            _db, tiered, _orgs, new UnlimitedDisk(), stagingOptions, cfg, recorder,
            blobKeyLock, NullLogger<OciUploadService>.Instance, TimeProvider.System));
    }

    private static async Task<OciUploadSession> StartAndStageAsync(OciUploadService svc, string orgId, byte[] bytes)
    {
        var session = await svc.StartUploadAsync(orgId, "team/app", default);
        await svc.AppendChunkAsync(orgId, session, new MemoryStream(bytes), default);
        return session;
    }

    // ── Seeding ──────────────────────────────────────────────────────────────────

    // The config blob a pushed manifest references. Keyed off the manifest's blob key, so the
    // exists-gate never fires on it.
    private async Task SeedConfigBlobAsync(string orgId, string digest, byte[] config)
    {
        string blobKey = BlobKeys.OciBlob("sha256", digest["sha256:".Length..]);
        await _registry.PutAsync(blobKey, new MemoryStream(config));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.config.v1+json', @size, @blobKey, 'uploaded')
            """,
            new { digest, orgId, size = (long)config.Length, blobKey });
    }

    // Gives an org the sole reference to a manifest blob: the physical file plus the oci_blobs /
    // oci_tags shadow rows a push leaves behind.
    private async Task SeedManifestBlobAsync(string orgId, string digest, string blobKey, byte[] manifest)
    {
        await _registry.PutAsync(blobKey, new MemoryStream(manifest));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, @mediaType, @size, @blobKey, 'uploaded')
            """,
            new { digest, orgId, mediaType = ManifestMediaType, size = (long)manifest.Length, blobKey });
        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES (@orgId, @repo, 'v1', @digest)",
            new { orgId, repo = Repository, digest });
    }

    // The packages / package_versions rows the management yank resolves before it reaches the OCI
    // arm. An OCI version is keyed by its manifest digest.
    private async Task SeedOciVersionRowsAsync(string orgId, string digest, string blobKey)
    {
        string packageId = await PackageSeeder.InsertAsync(_db, orgId, "oci", Repository);
        await PackageSeeder.InsertVersionAsync(
            _db, packageId, digest, $"pkg:oci/{Repository}@{digest}", blobKey: blobKey);
    }

    private async Task<string> SeedOwnerAsync(string orgId)
    {
        string userId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @t, @e, 'x', 'owner')",
            new { id = userId, t = orgId, e = $"{userId}@blobkey-lock.test" });
        return userId;
    }

    private async Task<string> SeedYankTokenAsync(string orgId)
    {
        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            orgId, "yank-race", """["yank:oci","read:artifact"]""", expiresAt: null);
        return rawToken;
    }

    // ── Controller construction ──────────────────────────────────────────────────

    private static DefaultHttpContext HttpContextForOrg(string orgId)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("org-a.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "org-a");
        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();
        return http;
    }

    // Only the dependencies the digest-delete path touches are real; the rest are unreachable from
    // OciController.Delete and would drag the whole upstream-proxy graph into a lock test.
    private OciController BuildOciController(string orgId, string rawToken, OciBlobKeyLock sharedLock)
    {
        var http = HttpContextForOrg(orgId);
        http.Request.Headers.Authorization = $"Bearer {rawToken}";

        var svc = new OciControllerServices(
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: new TieredBlobStorage(_cache, _registry),
            Db: _db,
            Upstream: null!,
            Uploads: null!,
            OrphanBlobs: new OciOrphanBlobDeleter(_db, new TieredBlobStorage(_cache, _registry), sharedLock),
            BlockGate: null!,
            EdgeGuard: TestEdgeMode.DisabledPublishGuard(),
            Packages: _packages,
            TenantArtifactAccess: new TenantArtifactAccessRepository(_db));

        return new OciController(svc, NullLogger<OciController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    // As above: only what DeleteVersion's OCI arm reaches is real.
    private OrgController BuildOrgController(string orgId, string ownerId, OciBlobKeyLock sharedLock)
    {
        var http = HttpContextForOrg(orgId);
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, ownerId),
            new Claim("sub", ownerId),
            new Claim("org_id", orgId),
            new Claim("tid", orgId),
            new Claim("role", "owner"),
            new Claim("scope", "tenant"),
        ], authenticationType: "test"));

        var svc = new OrgControllerServices(
            Orgs: _orgs,
            Packages: _packages,
            Inventory: null!,
            VersionFiles: new PackageVersionFilesRepository(_db),
            SymbolIndex: new NuGetSymbolIndexRepository(_db, TimeProvider.System),
            PackageAnalytics: null!,
            StatsSnapshots: null!,
            Tokens: _tokens,
            Invites: null!,
            Allowlist: null!,
            Blocklist: null!,
            Audit: _audit,
            Guard: new OrgAccessGuard(_db),
            Blobs: _registry,
            BlobStorage: new TieredBlobStorage(_cache, _registry),
            OrphanBlobs: new OciOrphanBlobDeleter(_db, new TieredBlobStorage(_cache, _registry), sharedLock),
            Config: null!,
            Logger: NullLogger<OrgController>.Instance,
            Problems: null!,
            Licenses: null!,
            Vulns: null!,
            Urls: null!,
            AuditEmitter: null!,
            Invalidation: Dependably.Tests.Infrastructure.TestMetadataInvalidation.Coordinator(),
            CacheArtifacts: null!,
            TenantAccess: null!,
            Time: TimeProvider.System);

        return new OrgController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private async Task<bool> BlobRowExistsAsync(string orgId, string digest)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(1) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId", new { digest, orgId }) > 0;
    }

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private static string HexOf(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static void RecordMax(ref int max, int value)
    {
        int seen;
        do
        {
            seen = Volatile.Read(ref max);
            if (value <= seen)
            {
                return;
            }
        }
        while (Interlocked.CompareExchange(ref max, value, seen) != seen);
    }

    // Picks two keys that FNV-1a-hash to different stripes, replicating OciBlobKeyLock's mapping so
    // the concurrency assertion is deterministic rather than probabilistic.
    private static (string First, string Second) TwoKeysOnDistinctStripes(int stripes)
    {
        string first = "stripe-key-0";
        int firstStripe = Stripe(first, stripes);
        for (int i = 1; ; i++)
        {
            string candidate = $"stripe-key-{i}";
            if (Stripe(candidate, stripes) != firstStripe)
            {
                return (first, candidate);
            }
        }
    }

    private static int Stripe(string key, int stripes)
    {
        uint hash = 2166136261u;
        foreach (char c in key)
        {
            hash = (hash ^ c) * 16777619u;
        }
        return (int)(hash % (uint)stripes);
    }

    // Wraps an inner blob store and gates a single key's first ExistsAsync (blocks after computing
    // the result) or first PutAsync (blocks before storing) to force a deterministic interleave.
    private sealed class GatingBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private int _existsGated;
        private int _putGated;

        public GatingBlobStore(IBlobStore inner) => _inner = inner;

        public string? GateExistsKey { get; init; }
        public string? GatePutKey { get; init; }

        public TaskCompletionSource FirstExistsEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseExists = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void ReleaseFirstExists() => _releaseExists.TrySetResult();

        public TaskCompletionSource FirstPutEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releasePut = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void ReleaseFirstPut() => _releasePut.TrySetResult();

        public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            bool result = await _inner.ExistsAsync(key, ct);
            if (key == GateExistsKey && Interlocked.Exchange(ref _existsGated, 1) == 0)
            {
                FirstExistsEntered.TrySetResult();
                await _releaseExists.Task.WaitAsync(ct);
            }
            return result;
        }

        public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
        {
            if (key == GatePutKey && Interlocked.Exchange(ref _putGated, 1) == 0)
            {
                FirstPutEntered.TrySetResult();
                await _releasePut.Task.WaitAsync(ct);
            }
            await _inner.PutAsync(key, data, ct);
        }

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }
}

/// <summary>Unlimited disk stub — floor check always passes.</summary>
file sealed class UnlimitedDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => long.MaxValue;
    public long GetTotalBytes() => long.MaxValue;
    public long GetStagingDirectoryUsedBytes() => 0;
}
