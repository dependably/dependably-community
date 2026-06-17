using System.Net;
using System.Security.Cryptography;
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
}

// ── Retry + UpstreamFetchFailedException tests ────────────────────────────────

/// <summary>
/// Pins the retry contract for transient upstream errors: on a transient non-success
/// (403/429/5xx) the client retries up to MaxUpstreamFetchAttempts times; if a later
/// attempt succeeds the artifact is served normally; if retries are exhausted the client
/// throws <see cref="UpstreamFetchFailedException"/> so the middleware can map it to a
/// retryable status code instead of a fatal policy block (403) or absence (404).
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

    // ── GetOrFetchStreamAsync: transient 403, then 200 → succeeds ────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_Transient403ThenSuccess_RetriesAndServes()
    {
        byte[] data = RandomBytes();
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var (client, handler) = BuildRetryClient();

        // First attempt → 403 (transient). Second attempt → 200.
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new ByteArrayContent(data) });

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/retry-key", "http://upstream.test/pkg-retry.tgz", spec, "npm");

        Assert.False(isHit);
        Assert.Equal(data, await DrainAsync(stream));
        Assert.Equal(2, handler.CallCount);
    }

    // ── GetOrFetchStreamAsync: persistent 403 → UpstreamFetchFailedException ─

    [Fact]
    public async Task GetOrFetchStreamAsync_Persistent403_ThrowsUpstreamFetchFailed()
    {
        var (client, handler) = BuildRetryClient();

        // All three attempts return 403 — retries exhausted.
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/exhaust-key", "http://upstream.test/blocked.tgz", null, "pypi"));

        Assert.True(ex.Transient);
        Assert.Equal(403, ex.StatusCode);
        Assert.Equal("http://upstream.test/blocked.tgz", ex.Url);
        Assert.Equal(3, handler.CallCount);
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

    // ── FetchAndCacheByUrlAsync: persistent 403 → UpstreamFetchFailedException ─

    [Fact]
    public async Task FetchAndCacheByUrlAsync_Persistent403_ThrowsUpstreamFetchFailed()
    {
        var (client, handler) = BuildRetryClient();
        for (int i = 0; i < 3; i++)
        {
            handler.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        }

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client.FetchAndCacheByUrlAsync("http://upstream.test/blocked.nupkg", null, "nuget"));

        Assert.True(ex.Transient);
        Assert.Equal(403, ex.StatusCode);
        Assert.Equal(3, handler.CallCount);
    }

    // ── Mixed partial-failure: first upstream 403 (transient exhausted), second succeeds ─

    [Fact]
    public async Task FetchAndCacheByUrlAsync_MixedPartialFailure_FirstUpstreamExhausted_SecondSucceeds()
    {
        // Simulates the real multi-base controller loop: first upstream returns persistent 403
        // (UpstreamFetchFailedException), second upstream returns 200. The exception from the
        // first must propagate out of FetchAndCacheByUrlAsync; the controller loop catches it
        // and the controller propagates it to the middleware (which returns 503). To test the
        // mixed scenario at the UpstreamClient level, we assert that the first call throws and
        // that a second independent call (simulating the next upstream) succeeds.
        byte[] data = RandomBytes();
        var store = new InMemoryBlobStore();

        // First client: returns 3× 403
        var (client1, handler1) = BuildRetryClient(blobs: store);
        for (int i = 0; i < 3; i++)
        {
            handler1.Enqueue(new HttpResponseMessage(HttpStatusCode.Forbidden));
        }

        var ex = await Assert.ThrowsAsync<UpstreamFetchFailedException>(() =>
            client1.FetchAndCacheByUrlAsync("http://upstream-a.test/pkg.nupkg", null, "nuget"));
        Assert.True(ex.Transient);

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
    public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(true);
}

/// <summary>Blocks all URLs — used to test SSRF rejection paths.</summary>
file sealed class BlockAllValidator : IUpstreamUrlValidator
{
    public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(false);
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

/// <summary>Allows all URLs — used by retry test helpers.</summary>
file sealed class AllowAllRetryValidator : IUpstreamUrlValidator
{
    public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
        => Task.FromResult(true);
}

/// <summary>Not air-gapped — used by retry test helpers.</summary>
file sealed class StubRetryAirGapMode : IAirGapMode
{
    public bool IsEnabled => false;
    public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
    public bool IsJobDisabled(string jobName) => false;
}
