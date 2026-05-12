using System.Net;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit;

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
        bool airGapped = false)
    {
        var handler = new FakeHttpHandler();
        var factory = new FakeHttpClientFactory(handler);
        var store = blobs ?? new InMemoryBlobStore();
        var audit = new AuditRepository(new NullMetadataStore());
        var logger = NullLogger<UpstreamClient>.Instance;
        var airGap = new StubAirGapMode(airGapped);
        // Tier-shared bootstrap: cache and registry point at the same store. UpstreamClient
        // only ever touches the Cache tier.
        var tiered = new TieredBlobStorage(store, store);
        var client = new UpstreamClient(factory, tiered, audit, validator, airGap, logger);
        return (client, handler);
    }

    private sealed class StubAirGapMode : Dependably.Infrastructure.IAirGapMode
    {
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
    }

    private static byte[] RandomBytes(int length = 64)
    {
        var b = new byte[length];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ── Cache hit ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchAsync_CacheHit_ReturnsBytesWithoutUpstreamCall()
    {
        var data = RandomBytes();
        var store = new InMemoryBlobStore();
        await store.PutAsync("blobs/test-key", new MemoryStream(data));

        var (client, handler) = BuildClient(new AllowAllValidator(), store);

        var (bytes, isHit) = await client.GetOrFetchAsync(
            "blobs/test-key", "http://upstream.invalid/pkg", null, "pypi");

        Assert.True(isHit);
        Assert.Equal(data, bytes);
        Assert.Equal(0, handler.CallCount); // upstream never contacted
    }

    // ── Cache miss: valid checksum ─────────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchAsync_CacheMiss_FetchesAndCachesBlob()
    {
        var data = RandomBytes();
        var spec = new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex(data));
        var store = new InMemoryBlobStore();
        var (client, handler) = BuildClient(new AllowAllValidator(), store);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(data)
        };

        var (bytes, isHit) = await client.GetOrFetchAsync(
            "blobs/new-key", "http://upstream.test/pkg", spec, "npm");

        Assert.False(isHit);
        Assert.Equal(data, bytes);
        Assert.Equal(1, handler.CallCount);

        // Verify blob was cached
        var stored = await store.GetAsync("blobs/new-key");
        Assert.NotNull(stored);
    }

    // ── Cache miss: checksum mismatch ──────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchAsync_ChecksumMismatch_ThrowsChecksumException()
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
            client.GetOrFetchAsync("blobs/bad-hash", "http://upstream.test/pkg", wrongSpec, "pypi"));

        // Nothing should be cached after a checksum failure
        var stored = await store.GetAsync("blobs/bad-hash");
        Assert.Null(stored);
    }

    // ── SSRF blocking in GetOrFetchAsync ──────────────────────────────────────

    [Fact]
    public async Task GetOrFetchAsync_SsrfBlocked_ThrowsSsrfBlockedException()
    {
        var (client, _) = BuildClient(new BlockAllValidator());

        await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            client.GetOrFetchAsync(
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
    public async Task GetOrFetchAsync_ContentLengthExceedsLimit_ThrowsUpstreamResponseTooLargeException()
    {
        var (client, handler) = BuildClient(new AllowAllValidator());
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>())
        };
        response.Content.Headers.ContentLength = 601L * 1024 * 1024; // 601 MB
        handler.NextResponse = response;

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            client.GetOrFetchAsync("blobs/too-large", "http://upstream.test/huge", null, "nuget"));
    }

    // ── AIR_GAPPED enforcement (#48) ──────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchAsync_AirGapped_CacheHitStillServes()
    {
        // Air-gap must not block reads of artefacts already imported into the cache —
        // that would break running deployments. Only the upstream-fetch path is gated.
        var data = RandomBytes();
        var store = new InMemoryBlobStore();
        await store.PutAsync("blobs/cached-key", new MemoryStream(data));
        var (client, handler) = BuildClient(new AllowAllValidator(), store, airGapped: true);

        var (bytes, isHit) = await client.GetOrFetchAsync(
            "blobs/cached-key", "http://upstream.invalid/pkg", null, "npm");

        Assert.True(isHit);
        Assert.Equal(data, bytes);
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task GetOrFetchAsync_AirGapped_CacheMissThrowsAirGappedException()
    {
        var (client, handler) = BuildClient(new AllowAllValidator(), airGapped: true);
        // Even if upstream were reachable, the air-gap gate must fire before any HTTP call.
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(RandomBytes())
        };

        var ex = await Assert.ThrowsAsync<AirGappedException>(() =>
            client.GetOrFetchAsync("blobs/missing-key", "http://upstream.test/pkg", null, "pypi"));
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

    public int CallCount { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CallCount++;
        return Task.FromResult(NextResponse);
    }
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
                org_id TEXT, actor_id TEXT, action TEXT NOT NULL,
                ecosystem TEXT, purl TEXT, detail TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            CREATE TABLE IF NOT EXISTS activity (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL, ecosystem TEXT NOT NULL, purl TEXT NOT NULL,
                event_type TEXT NOT NULL, actor_id TEXT, detail TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );
            """;
        cmd.ExecuteNonQuery();
        return Task.FromResult<System.Data.Common.DbConnection>(conn);
    }
}
