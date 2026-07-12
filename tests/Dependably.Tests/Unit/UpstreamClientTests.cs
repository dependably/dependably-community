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

[Trait("Category", "Unit")]
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
        ILogger<UpstreamClient>? logger = null)
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
        var client = new UpstreamClient(factory, tiered, audit, validator, airGap, new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir), Dependably.Infrastructure.StagingOptions.Resolve(config), log);
        return (client, handler);
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
