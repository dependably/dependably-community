using System.Net;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

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
        var stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(factory, tiered, audit, validator, airGap, config, log);
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
        var b = new byte[length];
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
        var data = RandomBytes();
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
        var data = RandomBytes();
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
        var data = RandomBytes();
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
        var body = """{"version":"3.0.0"}"""u8.ToArray();
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
        var data = RandomBytes();
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
        if (NextException is not null) throw NextException;
        return Task.FromResult(NextResponse);
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
            foreach (var kv in kvs) props[kv.Key] = kv.Value;
        }
        Records.Add(new LogRecord(logLevel, formatter(state, exception), exception, props));
    }

    public sealed record LogRecord(
        LogLevel Level,
        string Message,
        Exception? Exception,
        IReadOnlyDictionary<string, object?> Properties);
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
