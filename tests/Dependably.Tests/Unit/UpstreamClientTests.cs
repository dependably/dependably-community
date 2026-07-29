using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

// The byte[] GetOrFetchAsync adapter has been retired. All call sites here drive
// GetOrFetchStreamAsync directly and consume the returned stream — the legacy byte[]
// assertions ("Equal(data, bytes)") become "drain stream, then compare".

// BlockAllValidator drives the real IUpstreamUrlValidator.IsAllowedAsync extension, which emits
// to the process-wide static dependably.security.upstream_url_blocks counter that
// UpstreamUrlBlocksEmissionTests asserts exact counts against. See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public class UpstreamClientTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ───────────────────────────────────────────────────────────────

    private AuditRepository Audit() => new(_db);

    private static (UpstreamClient Client, FakeHttpHandler Handler) BuildClient(
        IUpstreamUrlValidator validator,
        IBlobStore? blobs = null,
        bool airGapped = false,
        ILogger<UpstreamClient>? logger = null,
        OrgRepository? orgs = null)
    {
        var handler = new FakeHttpHandler();
        var factory = new FakeHttpClientFactory(handler);
        var store = blobs ?? new InMemoryBlobStore();
        var audit = new AuditRepository(new NullMetadataStore());
        var log = logger ?? NullLogger<UpstreamClient>.Instance;
        var airGap = new StubAirGapMode(airGapped);
        // Tier-shared bootstrap: cache and registry point at the same store. UpstreamClient
        // only ever touches the Cache tier.
        var tiered = new TieredBlobStorage(store, store);
        // Staging path: route to a fresh temp dir per test so MISS-path artefacts
        // don't collide across parallel xunit runs.
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(
            factory, tiered, audit, validator, airGap,
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir),
            Dependably.Infrastructure.StagingOptions.Resolve(config), log,
            orgs: orgs);
        return (client, handler);
    }

    /// <summary>
    /// Builds a client over a caller-supplied handler and blob store. The in-flight quota ledger
    /// lives on the <see cref="UpstreamClient"/> instance (a DI singleton in production), so tests
    /// that exercise it must drive every fetch through ONE client — which in turn needs a handler
    /// that can serve more than one distinct body.
    /// </summary>
    private static UpstreamClient BuildClientWithHandler(
        HttpMessageHandler handler, IBlobStore blobs, OrgRepository orgs)
    {
        var tiered = new TieredBlobStorage(blobs, blobs);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        return new UpstreamClient(
            new FakeHttpClientFactory(handler), tiered, new AuditRepository(new NullMetadataStore()),
            new AllowAllValidator(), new StubAirGapMode(false),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir),
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance, orgs: orgs);
    }

    private sealed class StubAirGapMode : Dependably.Infrastructure.IAirGapMode
    {
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }

    private static byte[] RandomBytes(int length = 64)
    {
        byte[] b = new byte[length];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static async Task<byte[]> DrainAsync(Stream stream)
    {
        await using (stream.ConfigureAwait(false))
        {
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms);
            return ms.ToArray();
        }
    }

    // ── Cache hit ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_CacheHit_ReturnsBytesWithoutUpstreamCall()
    {
        byte[] data = RandomBytes();
        var store = new InMemoryBlobStore();
        await store.PutAsync("blobs/test-key", new MemoryStream(data));

        var (client, handler) = BuildClient(new AllowAllValidator(), store);

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/test-key", "http://upstream.invalid/pkg", null, "pypi");

        Assert.True(isHit);
        Assert.Equal(data, await DrainAsync(stream));
        Assert.Equal(0, handler.CallCount); // upstream never contacted
    }

    // ── Cache miss: valid checksum ─────────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_CacheMiss_FetchesAndCachesBlob()
    {
        byte[] data = RandomBytes();
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/new-key", "http://upstream.test/pkg", spec, "npm");

        Assert.False(isHit);
        Assert.Equal(data, await DrainAsync(stream));
        Assert.Equal(1, handler.CallCount);

        // Verify blob was cached
        var stored = await store.GetAsync("blobs/new-key");
        Assert.NotNull(stored);
    }

    // ── Cache miss: checksum mismatch ──────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_ChecksumMismatch_ThrowsChecksumException()
    {
        byte[] data = RandomBytes();
        var wrongSpec = new ChecksumSpec(ChecksumAlgorithm.Sha256,
            "0000000000000000000000000000000000000000000000000000000000000000");
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        await Assert.ThrowsAsync<ChecksumException>(() =>
            client.GetOrFetchStreamAsync("blobs/bad-hash", "http://upstream.test/pkg", wrongSpec, "pypi"));

        // Nothing should be cached after a checksum failure
        var stored = await store.GetAsync("blobs/bad-hash");
        Assert.Null(stored);
    }

    // ── SSRF blocking in GetOrFetchStreamAsync ────────────────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_SsrfBlocked_ThrowsSsrfBlockedException()
    {
        var (client, _) = BuildClient(new BlockAllValidator());

        await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/ssrf-key", "http://169.254.169.254/latest/meta-data/", null, "nuget"));
    }

    // ── SSRF blocking in GetMetadataAsync ─────────────────────────────────────

    [Fact]
    public async Task GetMetadataAsync_SsrfBlocked_ThrowsSsrfBlockedException()
    {
        var (client, _) = BuildClient(new BlockAllValidator());

        await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            client.GetMetadataAsync("http://10.0.0.1/index.json"));
    }

    // ── GetMetadataAsync: passes through response ──────────────────────────────

    [Fact]
    public async Task GetMetadataAsync_Allowed_ReturnsUpstreamResponse()
    {
        var (client, handler) = BuildClient(new AllowAllValidator());
        byte[] body = """{"version":"3.0.0"}"""u8.ToArray();
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(body)
        };

        var response = await client.GetMetadataAsync("http://upstream.test/index.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, handler.CallCount);
    }

    // ── Content-Length too large ───────────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_ContentLengthExceedsLimit_ThrowsUpstreamResponseTooLargeException()
    {
        var (client, handler) = BuildClient(new AllowAllValidator());
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>())
        };
        response.Content.Headers.ContentLength = 601L * 1024 * 1024; // 601 MB
        handler.NextResponse = response;

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            client.GetOrFetchStreamAsync("blobs/too-large", "http://upstream.test/huge", null, "nuget"));
    }

    // ── AIR_GAPPED enforcement ──────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_AirGapped_CacheHitStillServes()
    {
        // Air-gap must not block reads of artefacts already imported into the cache —
        // that would break running deployments. Only the upstream-fetch path is gated.
        byte[] data = RandomBytes();
        var store = new InMemoryBlobStore();
        await store.PutAsync("blobs/cached-key", new MemoryStream(data));
        var (client, handler) = BuildClient(new AllowAllValidator(), store, airGapped: true);

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/cached-key", "http://upstream.invalid/pkg", null, "npm");

        Assert.True(isHit);
        Assert.Equal(data, await DrainAsync(stream));
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_AirGapped_CacheMissThrowsAirGappedException()
    {
        var (client, handler) = BuildClient(new AllowAllValidator(), airGapped: true);
        // Even if upstream were reachable, the air-gap gate must fire before any HTTP call.
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(RandomBytes())
        };

        var ex = await Assert.ThrowsAsync<AirGappedException>(() =>
            client.GetOrFetchStreamAsync("blobs/missing-key", "http://upstream.test/pkg", null, "pypi"));
        Assert.Equal("blobs/missing-key", ex.Resource);
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task GetMetadataAsync_AirGapped_ThrowsAirGappedException()
    {
        var (client, handler) = BuildClient(new AllowAllValidator(), airGapped: true);

        var ex = await Assert.ThrowsAsync<AirGappedException>(() =>
            client.GetMetadataAsync("http://upstream.test/simple/lodash/"));
        Assert.Contains("simple/lodash", ex.Resource);
        Assert.Equal(0, handler.CallCount);
    }

    // ── Staging disk full: sub-floor disk rejects fetch before GET ───────────────

    private static (UpstreamClient Client, FakeHttpHandler Handler) BuildClientWithDisk(
        IStagingDiskInfo diskInfo,
        IUpstreamUrlValidator? validator = null,
        long stagingFloorBytes = 512L * 1024 * 1024)
    {
        var handler = new FakeHttpHandler();
        var factory = new FakeHttpClientFactory(handler);
        var store = new InMemoryBlobStore();
        var audit = new AuditRepository(new NullMetadataStore());
        var tiered = new TieredBlobStorage(store, store);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = stagingDir,
                ["STAGING_DISK_FLOOR_BYTES"] = stagingFloorBytes.ToString(),
            })
            .Build();
        var airGap = new StubAirGapMode(false);
        var v = validator ?? new AllowAllValidator();
        var client = new UpstreamClient(factory, tiered, audit, v, airGap, diskInfo, Dependably.Infrastructure.StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
        return (client, handler);
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_SubFloorDisk_ThrowsStagingDiskFullExceptionBeforeGet()
    {
        // Disk reports 0 bytes available — well below the default 512 MiB floor.
        // The fetch must be rejected before any upstream HTTP call is made.
        var diskInfo = new FakeDiskInfo(available: 0, total: 10L * 1024 * 1024 * 1024);
        var (client, handler) = BuildClientWithDisk(diskInfo);
        handler.NextResponse = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(RandomBytes())
        };

        var ex = await Assert.ThrowsAsync<StagingDiskFullException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/disk-full-key", "http://upstream.test/pkg", null, "npm"));

        Assert.Equal(0L, ex.AvailableBytes);
        Assert.True(ex.FloorBytes > 0);
        // Upstream must never be contacted — the guard fires before the HTTP GET.
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_DiskProbeFails_FailsClosedWithStagingDiskFullException()
    {
        // When GetAvailableBytes() throws, Phase 1 must fail closed rather than
        // proceeding with the fetch — a failing disk probe may indicate the volume is full.
        var faultyDisk = new FaultyDiskInfo();
        var (client, handler) = BuildClientWithDisk(faultyDisk);
        handler.NextResponse = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(RandomBytes())
        };

        await Assert.ThrowsAsync<StagingDiskFullException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/probe-fail-key", "http://upstream.test/pkg", null, "pypi"));

        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task StagingDiskFullMiddleware_TranslatesStagingDiskFullExceptionTo507()
    {
        // The 507 middleware must translate StagingDiskFullException to a 507 response
        // and must not include available_bytes or floor_bytes in the body.
        var logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<StagingDiskFullExceptionMiddleware>();
        bool nextCalled = false;
        var middleware = new StagingDiskFullExceptionMiddleware(
            _ =>
            {
                nextCalled = true;
                throw new StagingDiskFullException(0, 512L * 1024 * 1024);
            },
            logger);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(httpContext);

        Assert.True(nextCalled);
        Assert.Equal(507, httpContext.Response.StatusCode);
        Assert.Equal("application/problem+json", httpContext.Response.ContentType);

        httpContext.Response.Body.Seek(0, SeekOrigin.Begin);
        string body = new System.IO.StreamReader(httpContext.Response.Body).ReadToEnd();
        Assert.DoesNotContain("available_bytes", body);
        Assert.DoesNotContain("floor_bytes", body);
        Assert.Contains("Insufficient storage", body);
    }

    // ── Tenant storage quota gate on the proxy cache-fill (MISS) path ─────────
    //
    // Regression coverage for the proxy MISS write path (StreamVerifyAndStoreAsync and its
    // content-key sibling StreamHashAndStoreByContentKeyAsync) never bounding the tenant's
    // storage quota, so an authenticated tenant could grow the cache plane without bound.
    // The gate weighs each fill against the tenant's live org_storage_bytes total — the same
    // per-org ceiling, read the same way, that hosted publish and OCI push enforce.

    private async Task<string> CreateOrgAsync(string slug = "acme")
    {
        await using var conn = await _db.OpenAsync();
        string orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug });
        return orgId;
    }

    private Task<long> ReadLiveStorageBytesAsync(string orgId)
        => new OrgRepository(_db).GetLiveStorageBytesAsync(orgId);

    /// <summary>
    /// Records a proxy artefact on the cache plane exactly the way a completed proxy fetch does:
    /// the blob, a shared <c>cache_artifact</c> row, and the tenant's
    /// <c>tenant_artifact_access</c> grant. That trio is what puts the bytes into the org's
    /// <c>org_storage_bytes</c> total, so this is how a tenant legitimately arrives near its
    /// ceiling. Returns the cache_artifact id so a test can evict it.
    /// </summary>
    private async Task<string> SeedCachedArtifactAsync(
        string orgId, long sizeBytes, string version = "1.0.0", InMemoryBlobStore? blobs = null)
    {
        string blobKey = BlobKeys.Proxy(Sha256Hex(System.Text.Encoding.UTF8.GetBytes(version)));
        if (blobs is not null)
        {
            await blobs.PutAsync(blobKey, new MemoryStream(new byte[sizeBytes]));
        }

        var artifact = await new CacheArtifactRepository(_db).InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = "lodash",
            Version = version,
            Filename = $"lodash-{version}.tgz",
            BlobKey = blobKey,
            ContentHash = "sha256:x",
            SizeBytes = sizeBytes,
            FirstCachedAt = TestTime.Frozen().GetUtcNow(),
            LastAccessedAt = TestTime.Frozen().GetUtcNow().AddDays(-30)
        });
        await new TenantArtifactAccessRepository(_db).UpsertAsync(
            orgId, artifact.Id, TestTime.Frozen().GetUtcNow());
        return artifact.Id;
    }

    private async Task EvictCachedArtifactAsync(string cacheArtifactId) =>
        await new CacheArtifactRepository(_db).DeleteAsync(cacheArtifactId);

    [Fact]
    public async Task GetOrFetchStreamAsync_ProxyMissExceedsQuota_ThrowsTenantStorageQuotaExceededException_AndBlobNotWritten()
    {
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 100); // tiny cap

        byte[] data = RandomBytes(512); // 512 > 100
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        var ex = await Assert.ThrowsAsync<TenantStorageQuotaExceededException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/quota-key", "http://upstream.test/pkg", spec, "rpm", orgId: orgId));

        Assert.Equal(orgId, ex.OrgId);
        Assert.Equal(100, ex.QuotaBytes);

        // The verified bytes were fetched (the upstream call happened) but must never have
        // reached the blob store — a rejected reservation must not leave the artefact cached.
        Assert.Equal(1, handler.CallCount);
        Assert.Null(await store.GetAsync("blobs/quota-key"));

        // A rejected fill attributes no bytes to the tenant.
        Assert.Equal(0, await ReadLiveStorageBytesAsync(orgId));
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_ProxyMissUnderQuota_Succeeds_AndAttributesNothingUntilRecorded()
    {
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 10_000);

        byte[] data = RandomBytes(256);
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/quota-ok-key", "http://upstream.test/pkg", spec, "rpm", orgId: orgId);

        Assert.False(isHit);
        Assert.Equal(data, await DrainAsync(stream));

        // The fill itself attributes nothing: a tenant holds cache-plane bytes through the
        // cache_artifact + tenant_artifact_access rows the caller records after this returns, and
        // org_storage_bytes counts them from there. Charging the tenant at fill time instead would
        // be an increment nothing pays back — eviction and retention delete those rows, and
        // neither can reach back to undo a charge for content-addressed, tenant-shared bytes.
        Assert.Equal(0, await ReadLiveStorageBytesAsync(orgId));
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_RefetchAfterEviction_IsAdmittedAgain()
    {
        // The lifetime-ratchet regression. A tenant at 900/1000 bytes is refused a 200-byte
        // fill; eviction then frees those 900 bytes. The next fill must be admitted — the tenant
        // is holding nothing. A quota charged onto a counter that only ever counts up refuses
        // this fill forever, locking the tenant out of its own empty cache with no recovery.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 1000);
        string cachedId = await SeedCachedArtifactAsync(orgId, sizeBytes: 900);

        byte[] data = RandomBytes(200);
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var store = new InMemoryBlobStore();

        // 900 held + 200 incoming = 1100 > 1000 → refused.
        var (client1, handler1) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler1.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };
        await Assert.ThrowsAsync<TenantStorageQuotaExceededException>(() =>
            client1.GetOrFetchStreamAsync(
                "blobs/ratchet-key", "http://upstream.test/pkg", spec, "rpm", orgId: orgId));

        // Eviction frees the 900 bytes.
        await EvictCachedArtifactAsync(cachedId);

        // Nothing held + 200 incoming = 200 <= 1000 → admitted.
        var (client2, handler2) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler2.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };
        var (stream, isHit) = await client2.GetOrFetchStreamAsync(
            "blobs/ratchet-key", "http://upstream.test/pkg", spec, "rpm", orgId: orgId);

        Assert.False(isHit);
        Assert.Equal(data, await DrainAsync(stream));
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_ProxyMissNoQuotaConfigured_AlwaysSucceeds()
    {
        // No quota set on the org → unlimited; a large proxy fetch must still pass, and the
        // gate must be a true no-op (no reservation attempted) when unlimited.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);

        byte[] data = RandomBytes(1024 * 64);
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/quota-unlimited-key", "http://upstream.test/pkg", spec, "rpm", orgId: orgId);

        Assert.False(isHit);
        Assert.Equal(data, await DrainAsync(stream));
    }

    // ── Mixed partial-failure (house rule): first proxy fetch fits, second is rejected ─

    [Fact]
    public async Task GetOrFetchStreamAsync_MixedScenario_FirstFitsSecondRejected_QuotaTracksThePlane()
    {
        // Cap: 800 bytes. First fetch = 500 bytes (fits, and its controller records it onto the
        // cache plane the way a real fetch does). Second fetch of a different coordinate = 400
        // bytes — together 900 > 800, so it must be rejected and its blob never written.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 800);

        byte[] data1 = RandomBytes(500);
        var spec1 = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data1));
        var store = new InMemoryBlobStore();

        var (client1, handler1) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler1.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data1)
        };
        var (stream1, isHit1) = await client1.GetOrFetchStreamAsync(
            "blobs/mixed-first-key", "http://upstream.test/pkg-1", spec1, "rpm", orgId: orgId);
        Assert.False(isHit1);
        Assert.Equal(data1, await DrainAsync(stream1));
        await SeedCachedArtifactAsync(orgId, sizeBytes: 500, version: "mixed-first");

        byte[] data2 = RandomBytes(400);
        var spec2 = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data2));
        var (client2, handler2) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler2.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data2)
        };

        await Assert.ThrowsAsync<TenantStorageQuotaExceededException>(() =>
            client2.GetOrFetchStreamAsync(
                "blobs/mixed-second-key", "http://upstream.test/pkg-2", spec2, "rpm", orgId: orgId));

        // The admitted fill is on the plane, the refused one left nothing behind.
        Assert.NotNull(await store.GetAsync("blobs/mixed-first-key"));
        Assert.Null(await store.GetAsync("blobs/mixed-second-key"));
        Assert.Equal(500, await orgs.GetLiveStorageBytesAsync(orgId));
    }

    [Fact]
    public async Task ConcurrentFills_SecondExceedingQuotaWhileFirstIsInFlight_IsRefused()
    {
        // Two concurrent fills of DISTINCT artefacts for one org, together over the ceiling.
        // Neither is visible to org_storage_bytes yet — the controller records cache_artifact
        // only after the fetch returns — so a gate that reads only the committed SUM admits both.
        // Nothing tenant-scoped bounds how many of these a tenant runs at once, and upstreams are
        // tenant-admin-configured, so "both" generalises to "as many as the attacker opens".
        // The in-flight ledger is what makes the first fill visible to the second.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 350);

        // Blocks inside the first PutAsync so the first fill is provably still in flight —
        // holding its reservation, committed to the plane by nothing — while the second runs its
        // quota gate. Deterministic: no sleeps, no timing assumptions.
        var store = new BlockingPutBlobStore(new InMemoryBlobStore());
        var handler = new MultiResponseHttpHandler();
        var client = BuildClientWithHandler(handler, store, orgs);

        byte[] first = RandomBytes(300);
        byte[] second = RandomBytes(200); // 300 + 200 = 500 > 350
        handler.Map("http://upstream.test/first", first);
        handler.Map("http://upstream.test/second", second);

        var firstFill = Task.Run(() => client.GetOrFetchStreamAsync(
            "blobs/inflight-first", "http://upstream.test/first",
            new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(first)), "rpm", orgId: orgId));

        await store.PutEntered.Task; // the first fill now holds its reservation

        // 0 committed + 300 in flight + 200 incoming = 500 > 350 → must be refused.
        var ex = await Assert.ThrowsAsync<TenantStorageQuotaExceededException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/inflight-second", "http://upstream.test/second",
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(second)), "rpm", orgId: orgId));
        Assert.Equal(orgId, ex.OrgId);
        Assert.Equal(350, ex.QuotaBytes);

        store.ReleasePut.SetResult();
        var (stream, _) = await firstFill;
        Assert.Equal(first, await DrainAsync(stream));

        // The refused fill cached nothing; the admitted one did.
        Assert.Null(await store.GetAsync("blobs/inflight-second"));
        Assert.NotNull(await store.GetAsync("blobs/inflight-first"));
    }

    [Fact]
    public async Task ConcurrentFills_ReservationIsReleasedWhenTheFillCompletes()
    {
        // The ledger must not leak: once a fill completes its bytes are the committed SUM's job,
        // and a reservation left charged would refuse the tenant's next fill forever — the same
        // permanent-refusal failure the counter ratchet caused.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 350);

        var store = new InMemoryBlobStore();
        var handler = new MultiResponseHttpHandler();
        var client = BuildClientWithHandler(handler, store, orgs);

        // Three sequential 300-byte fills through ONE client. Nothing records them on the plane,
        // so each must be admitted: 300 in flight is released the moment its fill returns.
        for (int i = 0; i < 3; i++)
        {
            byte[] body = RandomBytes(300);
            string url = $"http://upstream.test/seq-{i}";
            handler.Map(url, body);
            var (stream, _) = await client.GetOrFetchStreamAsync(
                $"blobs/seq-{i}", url,
                new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(body)), "rpm", orgId: orgId);
            Assert.Equal(body, await DrainAsync(stream));
        }
    }

    [Fact]
    public async Task ConcurrentFills_ReservationIsReleasedWhenTheFillFails()
    {
        // A reservation charged before a write that then fails must come back. Otherwise a flaky
        // blob backend silently walks the tenant's headroom to zero.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 350);

        var handler = new MultiResponseHttpHandler();
        byte[] doomed = RandomBytes(300);
        handler.Map("http://upstream.test/doomed", doomed);

        var failingStore = new FailingPutBlobStore(new InMemoryBlobStore());
        var failingClient = BuildClientWithHandler(handler, failingStore, orgs);
        await Assert.ThrowsAsync<IOException>(() => failingClient.GetOrFetchStreamAsync(
            "blobs/doomed", "http://upstream.test/doomed",
            new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(doomed)), "rpm", orgId: orgId));

        // The failed fill's 300 bytes must not still be charged: a fresh 300-byte fill fits.
        byte[] good = RandomBytes(300);
        handler.Map("http://upstream.test/good", good);
        var (stream, _) = await failingClient.GetOrFetchStreamAsync(
            "blobs/good", "http://upstream.test/good",
            new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(good)), "rpm", orgId: orgId);
        Assert.Equal(good, await DrainAsync(stream));
    }

    /// <summary>
    /// Serves a distinct body per URL. The in-flight tests drive two fetches of different
    /// artefacts through ONE <see cref="UpstreamClient"/> — the ledger lives on the instance, and
    /// single-flight only collapses identical keys, so distinct bodies are the whole point.
    /// </summary>
    private sealed class MultiResponseHttpHandler : HttpMessageHandler
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte[]> _bodies =
            new(StringComparer.Ordinal);

        public void Map(string url, byte[] body) => _bodies[url] = body;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(_bodies.TryGetValue(request.RequestUri!.ToString(), out byte[]? body)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    /// <summary>Blocks inside the first <see cref="PutAsync"/> until released, pinning one fill
    /// in flight so a concurrent fill's quota gate runs against it.</summary>
    private sealed class BlockingPutBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private int _blocked;

        public TaskCompletionSource PutEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleasePut { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public BlockingPutBlobStore(IBlobStore inner) => _inner = inner;

        public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
        {
            if (Interlocked.Exchange(ref _blocked, 1) == 0)
            {
                PutEntered.SetResult();
                await ReleasePut.Task;
            }
            await _inner.PutAsync(key, data, ct);
        }

        public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) =>
            _inner.GetRangeAsync(key, from, to, ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) =>
            _inner.ListAsync(prefix, ct);
    }

    /// <summary>Fails the first <see cref="PutAsync"/> and serves the rest — a flaky blob backend.</summary>
    private sealed class FailingPutBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private int _failed;

        public FailingPutBlobStore(IBlobStore inner) => _inner = inner;

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) =>
            Interlocked.Exchange(ref _failed, 1) == 0
                ? throw new IOException("blob backend write failed")
                : _inner.PutAsync(key, data, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) =>
            _inner.GetRangeAsync(key, from, to, ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) =>
            _inner.ListAsync(prefix, ct);
    }

    [Fact]
    public async Task MixedEviction_SomeArtefactsFreedSomeFail_RefillIsAdmittedForTheFreedBytes()
    {
        // Mixed partial failure inside ONE eviction pass, and what the quota gate does after it.
        // The tenant holds three 100-byte proxy artefacts under a 350-byte ceiling. One pass
        // evicts two of them cleanly while the third's blob is unreachable, so its row stays.
        // The tenant is now holding 100 bytes and must be able to fill the 250 it has room for.
        // A ceiling charged onto a counter nothing pays back still believes the freed 200 bytes
        // are held and refuses — permanently, for a tenant that is under its real quota.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 350);

        var store = new InMemoryBlobStore();
        await SeedCachedArtifactAsync(orgId, 100, version: "v1", blobs: store);
        string keptId = await SeedCachedArtifactAsync(orgId, 100, version: "v2", blobs: store);
        await SeedCachedArtifactAsync(orgId, 100, version: "v3", blobs: store);

        // A small fill first, so the tenant has actually exercised the gate before eviction runs
        // (300 held + 40 = 340 <= 350 → admitted).
        byte[] small = RandomBytes(40);
        var smallSpec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(small));
        var (client1, handler1) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler1.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(small)
        };
        var (stream1, _) = await client1.GetOrFetchStreamAsync(
            "blobs/mixed-evict-small", "http://upstream.test/small", smallSpec, "rpm", orgId: orgId);
        Assert.Equal(small, await DrainAsync(stream1));

        // The eviction pass: v2's blob delete throws, v1's and v3's succeed.
        string keptBlobKey = BlobKeys.Proxy(Sha256Hex(System.Text.Encoding.UTF8.GetBytes("v2")));
        var clock = TestTime.Frozen();
        var evictionStore = new SelectiveFailingDeleteBlobStore(store, failKey: keptBlobKey);
        var evictionCacheArtifacts = new CacheArtifactRepository(_db);
        var eviction = new CacheEvictionService(
            evictionCacheArtifacts,
            new TieredBlobStorage(evictionStore, store),
            new Dependably.Infrastructure.CacheOrphanBlobDeleter(
                evictionCacheArtifacts, new Dependably.Infrastructure.CacheBlobKeyLock()),
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["CACHE_MAX_AGE_DAYS"] = "7" })
                .Build(),
            NullLogger<CacheEvictionService>.Instance,
            clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(clock));

        var summary = await eviction.RunOnceAsync();

        // Two evicted, one left behind for a later pass — the mixed outcome.
        Assert.Equal(2, summary.ArtifactsEvicted);
        Assert.Equal(200, summary.BytesFreed);
        Assert.NotNull(await new CacheArtifactRepository(_db).GetByCoordinateAsync(
            "npm", "lodash", "v2", "lodash-v2.tgz"));
        Assert.Equal(keptId, (await new CacheArtifactRepository(_db).GetByCoordinateAsync(
            "npm", "lodash", "v2", "lodash-v2.tgz"))!.Id);

        // 100 still held + 200 incoming = 300 <= 350 → must be admitted.
        byte[] refill = RandomBytes(200);
        var refillSpec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(refill));
        var (client2, handler2) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler2.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(refill)
        };

        var (stream2, isHit2) = await client2.GetOrFetchStreamAsync(
            "blobs/mixed-evict-refill", "http://upstream.test/refill", refillSpec, "rpm", orgId: orgId);

        Assert.False(isHit2);
        Assert.Equal(refill, await DrainAsync(stream2));
        Assert.Equal(100, await orgs.GetLiveStorageBytesAsync(orgId));
    }

    /// <summary>
    /// Cache-tier <see cref="IBlobStore"/> whose <see cref="DeleteAsync"/> throws for exactly one
    /// key and succeeds for the rest — one unreachable object among healthy ones, the mixed case
    /// a store-wide outage double cannot express.
    /// </summary>
    private sealed class SelectiveFailingDeleteBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly string _failKey;

        public SelectiveFailingDeleteBlobStore(IBlobStore inner, string failKey)
        {
            _inner = inner;
            _failKey = failKey;
        }

        public Task DeleteAsync(string key, CancellationToken ct = default) =>
            key == _failKey
                ? throw new IOException($"blob {key} unreachable")
                : _inner.DeleteAsync(key, ct);

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => _inner.PutAsync(key, data, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) =>
            _inner.GetRangeAsync(key, from, to, ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) =>
            _inner.ListAsync(prefix, ct);
    }

    [Fact]
    public async Task FetchAndCacheByUrlAsync_ProxyMissExceedsQuota_ThrowsTenantStorageQuotaExceededException_AndBlobNotWritten()
    {
        // The no-pre-known-SHA path (npm tarballs, NuGet flatcontainer) is gated the same way.
        string orgId = await CreateOrgAsync();
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync(orgId, 100);

        byte[] data = RandomBytes(512);
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store, orgs: orgs);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        var ex = await Assert.ThrowsAsync<TenantStorageQuotaExceededException>(() =>
            client.FetchAndCacheByUrlAsync("http://upstream.test/pkg.tgz", null, "npm", orgId));

        Assert.Equal(orgId, ex.OrgId);
        string blobKey = BlobKeys.Proxy(Sha256Hex(data));
        Assert.Null(await store.GetAsync(blobKey));
        Assert.Equal(0, await ReadLiveStorageBytesAsync(orgId));
    }

    [Fact]
    public async Task TenantStorageQuotaExceededExceptionMiddleware_TranslatesExceptionTo413()
    {
        var logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<TenantStorageQuotaExceededExceptionMiddleware>();
        bool nextCalled = false;
        var middleware = new TenantStorageQuotaExceededExceptionMiddleware(
            _ =>
            {
                nextCalled = true;
                throw new TenantStorageQuotaExceededException("org-1", 1_000_000);
            },
            logger);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(httpContext);

        Assert.True(nextCalled);
        Assert.Equal(413, httpContext.Response.StatusCode);
        Assert.Equal("application/problem+json", httpContext.Response.ContentType);

        httpContext.Response.Body.Seek(0, SeekOrigin.Begin);
        string body = new System.IO.StreamReader(httpContext.Response.Body).ReadToEnd();
        Assert.Contains("quota", body, StringComparison.OrdinalIgnoreCase);
    }

    // ── Transient upstream failure logs a structured Warning ──────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_TransientUpstreamFailure_LogsStructuredWarning()
    {
        // Make the upstream call throw so the generic catch in GetOrFetchStreamAsync
        // fires — ChecksumException / UpstreamResponseTooLargeException / AirGappedException
        // are deliberately not logged (already classified via outcome metric + Activity
        // status).
        var logger = new CapturingLogger<UpstreamClient>();
        var (client, handler) = BuildClient(new AllowAllValidator(), logger: logger);
        handler.NextException = new TaskCanceledException("simulated upstream timeout");

        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/transient-fail",
                "http://upstream.test/pkg-1.0.tgz",
                checksumSpec: null,
                ecosystem: "npm"));

        var record = Assert.Single(logger.Records);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.IsType<TaskCanceledException>(record.Exception);

        // Structured properties bound by Serilog positional template — assert by name.
        Assert.Equal("TaskCanceledException", record.Properties["ExceptionType"]);
        Assert.Equal("npm", record.Properties["Ecosystem"]);
        Assert.Equal("blobs/transient-fail", record.Properties["BlobKey"]);
        Assert.Equal("http://upstream.test/pkg-1.0.tgz", record.Properties["UpstreamUrl"]);
        Assert.True(record.Properties.ContainsKey("Duration"));
        Assert.True(record.Properties.ContainsKey("TraceId"));
    }

    // ── Result-returning fetch: no buffer, reuses computed SHA-256 (Cargo path) ────

    // Builds a client whose audit repository writes to the persistent _db so audit rows
    // can be read back after the fetch.
    private (UpstreamClient Client, FakeHttpHandler Handler) BuildAuditingClient(IBlobStore store)
    {
        var handler = new FakeHttpHandler();
        var factory = new FakeHttpClientFactory(handler);
        var tiered = new TieredBlobStorage(store, store);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-audit-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(
            factory, tiered, new AuditRepository(_db), new AllowAllValidator(),
            new StubAirGapMode(false), new DriveInfoStagingDiskInfo(stagingDir),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
        return (client, handler);
    }

    [Fact]
    public async Task GetOrFetchToBlobKeyAsync_CacheMiss_ReusesComputedShaAndStreamsFromBlob()
    {
        // The Cargo proxy path uses this method so it can serve straight from the blob store
        // instead of buffering the crate and recomputing its digest. The returned fact set must
        // carry the SHA-256 the streamed stage already produced (matching the content) and the
        // size, and the artifact must be retrievable under the caller-supplied key.
        byte[] data = RandomBytes(4096);
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        var result = await client.GetOrFetchToBlobKeyAsync(
            "cargo/org1/foo/1.0.0.crate", "http://upstream.test/foo-1.0.0.crate", spec, "cargo");

        Assert.Equal(Sha256Hex(data), result.Sha256Hex);
        Assert.Equal(data.Length, result.SizeBytes);
        Assert.Equal("cargo/org1/foo/1.0.0.crate", result.BlobKey);
        Assert.Equal(1, handler.CallCount);

        var stored = await store.GetAsync("cargo/org1/foo/1.0.0.crate");
        Assert.NotNull(stored);
        Assert.Equal(data, await DrainAsync(stored!));
    }

    [Fact]
    public async Task GetOrFetchToBlobKeyAsync_CacheHit_RecoversShaWithoutUpstreamCall()
    {
        // On a concurrent cache hit the digest is recovered by stream-hashing the stored blob —
        // no upstream call, no full buffer.
        byte[] data = RandomBytes(4096);
        var store = new InMemoryBlobStore();
        await store.PutAsync("cargo/org1/bar/2.0.0.crate", new MemoryStream(data));
        var (client, handler) = BuildClient(new AllowAllValidator(), store);

        var result = await client.GetOrFetchToBlobKeyAsync(
            "cargo/org1/bar/2.0.0.crate", "http://upstream.invalid/bar", null, "cargo");

        Assert.Equal(Sha256Hex(data), result.Sha256Hex);
        Assert.Equal(data.Length, result.SizeBytes);
        Assert.Equal(0, handler.CallCount);
    }

    // ── Audit detail JSON escaping on a hostile upstream checksum value ───────────

    [Fact]
    public async Task VerifyChecksum_HostileExpectedValue_WritesValidJsonAuditDetail()
    {
        // A compromised/misbehaving upstream can return an integrity string containing a double
        // quote or backslash. The checksum_failure audit row's detail column is contractually
        // JSON; string-interpolating the raw value produced an unparseable blob. Serializing
        // through JsonSerializer escapes it, so the security event the row exists to record stays
        // machine-readable.
        byte[] data = RandomBytes();
        const string hostileExpected = "abc\"def\\ghi\"injected";
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, hostileExpected);
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildAuditingClient(store);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        await Assert.ThrowsAsync<ChecksumException>(() =>
            client.GetOrFetchToBlobKeyAsync(
                "cargo/org1/evil/1.0.0.crate", "http://upstream.test/evil-1.0.0.crate\"q", spec, "cargo",
                orgId: "org1", purl: "pkg:cargo/evil@1.0.0"));

        await using var conn = await _db.OpenAsync();
        string? detail = await conn.QuerySingleOrDefaultAsync<string?>(
            "SELECT detail FROM audit_log WHERE action = 'checksum_failure' ORDER BY created_at DESC LIMIT 1");
        Assert.NotNull(detail);

        // Fails on the old interpolated code: the unescaped quote yields invalid JSON here.
        using var doc = JsonDocument.Parse(detail!);
        Assert.Equal(hostileExpected, doc.RootElement.GetProperty("expected").GetString());
    }
}

// ── Retry + UpstreamFetchFailedException tests ────────────────────────────────

/// <summary>
/// Pins the retry contract for upstream errors: on a transient non-success (429/5xx, or an
/// ANONYMOUS 403 — public CDN bot mitigation emits genuinely transient 403s) the client retries
/// up to MaxUpstreamFetchAttempts times; if a later attempt succeeds the artifact is served
/// normally; if retries are exhausted the client throws
/// <see cref="UpstreamFetchFailedException"/> (<c>Transient=true</c>) so the middleware can map
/// it to a retryable status code instead of absence (404). A 401/403 from an upstream the fetch
/// AUTHENTICATED to is a deterministic auth/policy refusal of the presented credential, not a
/// transient condition — it is never retried and fails after exactly one attempt with
/// <c>Transient=false, Refused=true</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamFetchRetryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static byte[] RandomBytes(int length = 64)
    {
        byte[] b = new byte[length];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static async Task<byte[]> DrainAsync(Stream stream)
    {
        await using (stream.ConfigureAwait(false))
        {
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms);
            return ms.ToArray();
        }
    }

    private static (UpstreamClient Client, SequencedHttpHandler Handler) BuildRetryClient(
        IUpstreamUrlValidator? validator = null,
        IBlobStore? blobs = null)
    {
        var handler = new SequencedHttpHandler();
        var factory = new FakeSequencedHttpClientFactory(handler);
        var store = blobs ?? new InMemoryBlobStore();
        var audit = new AuditRepository(new NullMetadataStore());
        var tiered = new TieredBlobStorage(store, store);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-retry-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var v = validator ?? new AllowAllRetryValidator();
        var client = new UpstreamClient(
            factory, tiered, audit, v,
            new StubRetryAirGapMode(), new DriveInfoStagingDiskInfo(stagingDir),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        return (client, handler);
    }

    // ── GetOrFetchStreamAsync: transient 503, then 200 → succeeds ────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_Transient503ThenSuccess_RetriesAndServes()
    {
        byte[] data = RandomBytes();
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var (client, handler) = BuildRetryClient();

        // First attempt → 503 (transient). Second attempt → 200.
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new ByteArrayContent(data) });

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/retry-key", "http://upstream.test/pkg-retry.tgz", spec, "npm");

        Assert.False(isHit);
        Assert.Equal(data, await DrainAsync(stream));
        Assert.Equal(2, handler.CallCount);
    }

    // ── GetOrFetchStreamAsync: persistent 503 → UpstreamFetchFailedException ─

    [Fact]
    public async Task GetOrFetchStreamAsync_Persistent503_ThrowsUpstreamFetchFailed()
    {
        var (client, handler) = BuildRetryClient();

        // All three attempts return 503 — retries exhausted.
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/exhaust-key", "http://upstream.test/blocked.tgz", null, "pypi"));

        Assert.True(ex.Transient);
        Assert.False(ex.Refused);
        Assert.Equal(503, ex.StatusCode);
        Assert.Equal("http://upstream.test/blocked.tgz", ex.Url);
        Assert.Equal(3, handler.CallCount);
    }

    // ── GetOrFetchStreamAsync: authenticated 403/401 refusal → single attempt ─

    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task GetOrFetchStreamAsync_AuthenticatedRefusal_SingleAttempt_ThrowsUpstreamFetchFailedRefused(
        HttpStatusCode refusalStatus)
    {
        var (client, handler) = BuildRetryClient();

        // A deterministic auth/policy refusal of the presented credential must never be
        // retried — enqueuing a second, successful response proves the client never reaches it.
        handler.Enqueue(new HttpResponseMessage(refusalStatus));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new ByteArrayContent(RandomBytes()) });

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/refused-key", "http://upstream.test/refused.tgz", null, "npm",
                authorizationHeader: "Bearer edge-master-token"));

        Assert.False(ex.Transient);
        Assert.True(ex.Refused);
        Assert.Equal((int)refusalStatus, ex.StatusCode);
        Assert.Equal("http://upstream.test/refused.tgz", ex.Url);
        Assert.Equal(1, handler.CallCount);
    }

    // ── GetOrFetchStreamAsync: ANONYMOUS 403 stays transient (CDN bot mitigation) ─

    [Fact]
    public async Task GetOrFetchStreamAsync_Anonymous403ThenSuccess_RetriesAndServes()
    {
        // With no credential attached there is nothing for the upstream to "refuse" — public
        // registry CDNs emit transient 403s (bot mitigation), so an anonymous 403 that heals
        // within the retry window must be retried in-request and served normally.
        byte[] data = RandomBytes();
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var (client, handler) = BuildRetryClient();

        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new ByteArrayContent(data) });

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/anon403-key", "http://upstream.test/anon403.tgz", spec, "npm");

        Assert.False(isHit);
        Assert.Equal(data, await DrainAsync(stream));
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_AnonymousPersistent403_TransientExhausted_NotRefused()
    {
        var (client, handler) = BuildRetryClient();

        // All three attempts return 403 anonymously — retries exhausted, still transient
        // (mapped to a retryable 503 by the middleware), never marked as a refusal.
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/anon403-exhaust-key", "http://upstream.test/anon403-blocked.tgz", null, "npm"));

        Assert.True(ex.Transient);
        Assert.False(ex.Refused);
        Assert.Equal(403, ex.StatusCode);
        Assert.Equal(3, handler.CallCount);
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_Anonymous401_ThrowsHttpRequestException_MultiBaseFallthrough()
    {
        // An anonymous 401 means "this upstream requires credentials we don't have" — neither a
        // transient error to retry nor a refusal of a presented credential. It surfaces as
        // HttpRequestException so the controller's multi-base loop can try the next upstream.
        var (client, handler) = BuildRetryClient();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Unauthorized));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/anon401-key", "http://upstream.test/anon401.tgz", null, "npm"));

        Assert.Equal(1, handler.CallCount);
    }

    // ── GetOrFetchStreamAsync: persistent 429 with Retry-After ──────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_Persistent429_PropagatesRetryAfter()
    {
        var (client, handler) = BuildRetryClient();

        for (int i = 0; i < 3; i++)
        {
            var tooMany = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            tooMany.Headers.Add("Retry-After", "30");
            handler.Enqueue(tooMany);
        }

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/throttle-key", "http://upstream.test/throttled.tgz", null, "nuget"));

        Assert.True(ex.Transient);
        Assert.Equal(429, ex.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(30), ex.RetryAfter);
    }

    // ── GetOrFetchStreamAsync: genuine 404 → HttpRequestException (unchanged) ─

    [Fact]
    public async Task GetOrFetchStreamAsync_Genuine404_ThrowsHttpRequestException_NotUpstreamFetchFailed()
    {
        // 404 is non-transient — it must NOT be wrapped in UpstreamFetchFailedException.
        // The controller's multi-base loop relies on HttpRequestException to fall through to
        // the next upstream registry. Returning 404 to the client is correct.
        var (client, handler) = BuildRetryClient();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.NotFound));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/not-found-key", "http://upstream.test/missing.tgz", null, "npm"));

        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_NonTransient404_DisposesResponseToReleaseConnection()
    {
        // The response is obtained with HttpCompletionOption.ResponseHeadersRead; on a
        // non-transient status the client surfaces HttpRequestException so the multi-base loop
        // advances. It must dispose the undrained response first — EnsureSuccessStatusCode does
        // NOT dispose it, and an un-disposed ResponseHeadersRead body pins the pooled connection
        // (per-host pool caps at 10) until GC finalization. Upstream 404s are the hot path.
        bool[] disposed = new bool[1];
        var (client, handler) = BuildRetryClient();
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new DisposeTrackingContent(disposed),
        });

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/leak-key", "http://upstream.test/missing.tgz", null, "npm"));

        Assert.True(disposed[0],
            "the non-transient (404) response must be disposed so its ResponseHeadersRead connection returns to the pool");
    }

    // ── FetchAndCacheByUrlAsync: authenticated 403 refusal → single attempt ─

    [Fact]
    public async Task FetchAndCacheByUrlAsync_AuthenticatedRefused403_SingleAttempt_ThrowsUpstreamFetchFailedRefused()
    {
        var (client, handler) = BuildRetryClient();
        // Only one response enqueued — a second dequeue attempt (i.e. a retry) would throw
        // from an empty queue and fail the test outright.
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.FetchAndCacheByUrlAsync("http://upstream.test/blocked.nupkg", null, "nuget",
                authorizationHeader: "Bearer edge-master-token"));

        Assert.False(ex.Transient);
        Assert.True(ex.Refused);
        Assert.Equal(403, ex.StatusCode);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task FetchAndCacheByUrlAsync_AnonymousPersistent403_TransientExhausted_NotRefused()
    {
        // The no-pre-known-SHA path (npm tarballs, NuGet flatcontainer) applies the same
        // anonymous-403-is-transient contract as the blob-key path.
        var (client, handler) = BuildRetryClient();
        for (int i = 0; i < 3; i++)
        {
            handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        }

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.FetchAndCacheByUrlAsync("http://upstream.test/anon-blocked.nupkg", null, "nuget"));

        Assert.True(ex.Transient);
        Assert.False(ex.Refused);
        Assert.Equal(403, ex.StatusCode);
        Assert.Equal(3, handler.CallCount);
    }

    // ── Mixed partial-failure: first upstream refuses (403, single attempt), second succeeds ─

    [Fact]
    public async Task FetchAndCacheByUrlAsync_MixedPartialFailure_FirstUpstreamRefused_SecondSucceeds()
    {
        // Simulates the real multi-base controller loop: first upstream returns a deterministic
        // 403 refusal (UpstreamFetchFailedException, single attempt), second upstream returns
        // 200. The exception from the first must propagate out of FetchAndCacheByUrlAsync; the
        // controller loop propagates it to the middleware (which maps a refusal to 502). To test
        // the mixed scenario at the UpstreamClient level, we assert that the first call throws
        // after exactly one attempt and that a second independent call (simulating the next
        // upstream) succeeds.
        byte[] data = RandomBytes();
        var store = new InMemoryBlobStore();

        // First client: returns a single authenticated 403 — never retried.
        var (client1, handler1) = BuildRetryClient(blobs: store);
        handler1.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client1.FetchAndCacheByUrlAsync("http://upstream-a.test/pkg.nupkg", null, "nuget",
                authorizationHeader: "Basic dXBzdHJlYW06c2VjcmV0"));
        Assert.False(ex.Transient);
        Assert.True(ex.Refused);
        Assert.Equal(1, handler1.CallCount);

        // Second client (different upstream base): returns 200 — succeeds.
        var (client2, handler2) = BuildRetryClient(blobs: store);
        handler2.Enqueue(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data) });

        var result2 = await client2.FetchAndCacheByUrlAsync("http://upstream-b.test/pkg.nupkg", null, "nuget");
        Assert.NotNull(result2);
        Assert.Equal(1, handler2.CallCount);
    }
}

/// <summary>
/// Unit tests for <see cref="UpstreamFetchFailedExceptionMiddleware"/> mapping:
/// transient exhaustion → 503 with Retry-After; non-transient → 502.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamFetchFailedExceptionMiddlewareTests
{
    private static DefaultHttpContext BuildContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    [Fact]
    public async Task Transient_MapsTo503_WithRetryAfterHeader()
    {
        var middleware = new UpstreamFetchFailedExceptionMiddleware(
            _ => throw new UpstreamFetchFailedException
            { Url = "http://cdn.example.com/pkg.tgz", StatusCode = 403, Transient = true, RetryAfter = TimeSpan.FromSeconds(10) },
            NullLogger<UpstreamFetchFailedExceptionMiddleware>.Instance);

        var ctx = BuildContext();
        await middleware.InvokeAsync(ctx);

        Assert.Equal(503, ctx.Response.StatusCode);
        Assert.Equal("10", ctx.Response.Headers.RetryAfter.ToString());

        ctx.Response.Body.Seek(0, SeekOrigin.Begin);
        string body = await new StreamReader(ctx.Response.Body).ReadToEndAsync();
        Assert.Contains("Upstream temporarily unavailable", body);
        Assert.DoesNotContain("cdn.example.com", body);
    }

    [Fact]
    public async Task Transient_NoRetryAfterOnException_UsesDefaultFallback()
    {
        var middleware = new UpstreamFetchFailedExceptionMiddleware(
            _ => throw new UpstreamFetchFailedException
            { Url = "http://upstream.test/pkg.tgz", StatusCode = 503, Transient = true },
            NullLogger<UpstreamFetchFailedExceptionMiddleware>.Instance);

        var ctx = BuildContext();
        await middleware.InvokeAsync(ctx);

        Assert.Equal(503, ctx.Response.StatusCode);
        // Default fallback Retry-After must be a non-empty positive hint.
        Assert.True(int.TryParse(ctx.Response.Headers.RetryAfter.ToString(), out int retryAfterSecs)
                    && retryAfterSecs > 0);
    }

    [Fact]
    public async Task NonTransient_MapsTo502_NoRetryAfter()
    {
        var middleware = new UpstreamFetchFailedExceptionMiddleware(
            _ => throw new UpstreamFetchFailedException
            { Url = "http://upstream.test/pkg.tgz", StatusCode = 400, Transient = false },
            NullLogger<UpstreamFetchFailedExceptionMiddleware>.Instance);

        var ctx = BuildContext();
        await middleware.InvokeAsync(ctx);

        Assert.Equal(502, ctx.Response.StatusCode);
        Assert.True(string.IsNullOrEmpty(ctx.Response.Headers.RetryAfter.ToString()));

        ctx.Response.Body.Seek(0, SeekOrigin.Begin);
        string body = await new StreamReader(ctx.Response.Body).ReadToEndAsync();
        Assert.Contains("Upstream fetch failed", body);
    }

    [Fact]
    public async Task Refused_MapsTo502_WithDistinctRefusalBody_NotGenericUnreachable()
    {
        var middleware = new UpstreamFetchFailedExceptionMiddleware(
            _ => throw new UpstreamFetchFailedException
            { Url = "http://upstream.test/pkg.tgz", StatusCode = 403, Transient = false, Refused = true },
            NullLogger<UpstreamFetchFailedExceptionMiddleware>.Instance);

        var ctx = BuildContext();
        await middleware.InvokeAsync(ctx);

        Assert.Equal(502, ctx.Response.StatusCode);
        Assert.True(string.IsNullOrEmpty(ctx.Response.Headers.RetryAfter.ToString()));

        ctx.Response.Body.Seek(0, SeekOrigin.Begin);
        string body = await new StreamReader(ctx.Response.Body).ReadToEndAsync();
        Assert.Contains("refused", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Upstream fetch failed", body);
    }

    [Fact]
    public async Task NoException_PassesThrough()
    {
        bool nextCalled = false;
        var middleware = new UpstreamFetchFailedExceptionMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            NullLogger<UpstreamFetchFailedExceptionMiddleware>.Instance);

        var ctx = BuildContext();
        await middleware.InvokeAsync(ctx);

        Assert.True(nextCalled);
        Assert.Equal(200, ctx.Response.StatusCode);
    }
}

// ── Test doubles ──────────────────────────────────────────────────────────────

/// <summary>Allows all URLs — used to test non-SSRF paths.</summary>
file sealed class AllowAllValidator : IUpstreamUrlValidator
{
    public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(UpstreamUrlBlock.None);
}

/// <summary>Blocks all URLs — used to test SSRF rejection paths.</summary>
file sealed class BlockAllValidator : IUpstreamUrlValidator
{
    public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(UpstreamUrlBlock.BlockedRange);
}

/// <summary>Controllable HttpMessageHandler for unit tests.</summary>
internal sealed class FakeHttpHandler : HttpMessageHandler
{
    public HttpResponseMessage NextResponse { get; set; } =
        new HttpResponseMessage(HttpStatusCode.OK);

    /// <summary>When set, SendAsync throws this exception instead of returning NextResponse.</summary>
    public Exception? NextException { get; set; }

    public int CallCount { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CallCount++;
        return NextException is not null ? throw NextException : Task.FromResult(NextResponse);
    }
}

/// <summary>
/// ILogger&lt;T&gt; that records each log call's level, message, exception, and
/// structured key/value state. Used to assert on Serilog-bound properties without
/// pulling in Microsoft.Extensions.Logging.Testing (not on the test project).
/// </summary>
file sealed class CapturingLogger<T> : ILogger<T>
{
    public List<LogRecord> Records { get; } = new();

    IDisposable? ILogger.BeginScope<TState>(TState state) => null;
    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
        Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var props = new Dictionary<string, object?>();
        if (state is IEnumerable<KeyValuePair<string, object?>> kvs)
        {
            foreach (var kv in kvs)
            {
                props[kv.Key] = kv.Value;
            }
        }
        Records.Add(new LogRecord(logLevel, formatter(state, exception), exception, props));
    }

    public sealed record LogRecord(
        LogLevel Level,
        string Message,
        Exception? Exception,
        IReadOnlyDictionary<string, object?> Properties);
}

/// <summary>Controllable IStagingDiskInfo for unit tests.</summary>
file sealed class FakeDiskInfo(long available, long total) : IStagingDiskInfo
{
    public long GetAvailableBytes() => available;
    public long GetTotalBytes() => total;
    public long GetStagingDirectoryUsedBytes() => 0;
}

/// <summary>IStagingDiskInfo that always throws — simulates a broken staging volume probe.</summary>
file sealed class FaultyDiskInfo : IStagingDiskInfo
{
    public long GetAvailableBytes() => throw new IOException("disk probe failed");
    public long GetTotalBytes() => throw new IOException("disk probe failed");
    public long GetStagingDirectoryUsedBytes() => throw new IOException("disk probe failed");
}

/// <summary>IHttpClientFactory that always returns a client backed by FakeHttpHandler.</summary>
file sealed class FakeHttpClientFactory : IHttpClientFactory
{
    private readonly HttpClient _client;

    public FakeHttpClientFactory(HttpMessageHandler handler)
        => _client = new HttpClient(handler);

    public HttpClient CreateClient(string name) => _client;
}

/// <summary>AuditRepository that discards all writes — avoids needing a schema for pure unit tests.</summary>
file sealed class NullMetadataStore : IMetadataStore
{
    public DbProvider Provider => DbProvider.Sqlite;

    public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
    {
        // Return an in-memory SQLite connection with just the tables AuditRepository needs.
        var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL DEFAULT 'tenant',
                org_id TEXT, actor_id TEXT, actor_kind TEXT, action TEXT NOT NULL,
                ecosystem TEXT, purl TEXT, detail TEXT, source_ip TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            CREATE TABLE IF NOT EXISTS activity (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL, ecosystem TEXT NOT NULL, purl TEXT NOT NULL,
                event_type TEXT NOT NULL, actor_id TEXT, actor_kind TEXT,
                detail TEXT, source_ip TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            """;
        cmd.ExecuteNonQuery();
        return Task.FromResult<System.Data.Common.DbConnection>(conn);
    }
}

/// <summary>
/// HttpMessageHandler that dequeues pre-loaded responses in order, one per call.
/// Used for retry tests where the first attempt fails and a later attempt succeeds.
/// </summary>
internal sealed class SequencedHttpHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _responses = new();
    public int CallCount { get; private set; }

    public void Enqueue(HttpResponseMessage response) => _responses.Enqueue(response);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CallCount++;
        return _responses.Count > 0
            ? Task.FromResult(_responses.Dequeue())
            : Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
    }
}

/// <summary>IHttpClientFactory that always returns a client backed by SequencedHttpHandler.</summary>
internal sealed class FakeSequencedHttpClientFactory : IHttpClientFactory
{
    private readonly HttpClient _client;

    public FakeSequencedHttpClientFactory(SequencedHttpHandler handler)
        => _client = new HttpClient(handler);

    public HttpClient CreateClient(string name) => _client;
}

/// <summary>
/// HttpContent that flips a flag when disposed — lets a test assert the client disposes a
/// non-transient (404/410) response instead of stranding its pooled connection.
/// </summary>
file sealed class DisposeTrackingContent : ByteArrayContent
{
    private readonly bool[] _disposed;
    public DisposeTrackingContent(bool[] disposed) : base(Array.Empty<byte>()) => _disposed = disposed;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _disposed[0] = true;
        }
        base.Dispose(disposing);
    }
}

/// <summary>Allows all URLs — used by retry test helpers.</summary>
file sealed class AllowAllRetryValidator : IUpstreamUrlValidator
{
    public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(UpstreamUrlBlock.None);
}

/// <summary>Not air-gapped — used by retry test helpers.</summary>
file sealed class StubRetryAirGapMode : IAirGapMode
{
    public bool IsEnabled => false;
    public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
    public bool IsJobDisabled(string jobName) => false;
}
