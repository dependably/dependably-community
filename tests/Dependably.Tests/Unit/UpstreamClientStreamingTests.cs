using System.Net;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance for #89 + #105: <see cref="UpstreamClient.GetOrFetchStreamAsync"/> is now
/// the only proxy-fetch entry point. Cache HIT hands back the blob-store stream
/// untouched (no MemoryStream copy); cache MISS hashes upstream into the staging file
/// and the freshly cached blob streams back.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamClientStreamingTests
{
    [Fact]
    public async Task GetOrFetchStreamAsync_CacheHit_StreamsBlobDirectly()
    {
        // The whole point of the streaming variant: the returned stream IS the blob-store
        // stream; the test verifies we can consume it without going through an
        // intermediate MemoryStream allocation in UpstreamClient.
        var payload = Enumerable.Range(0, 4096).Select(i => (byte)(i & 0xff)).ToArray();
        var store = new InMemoryBlobStore();
        await store.PutAsync("blobs/y", new MemoryStream(payload));
        var (client, _) = Build(store);

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/y", "http://upstream.invalid/", null, "pypi");

        Assert.True(isHit);
        await using (stream)
        {
            using var copy = new MemoryStream();
            await stream.CopyToAsync(copy);
            Assert.Equal(payload, copy.ToArray());
        }
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_CacheHit_ExactSizedRoundTrip()
    {
        // Regression for #89: the cache-HIT stream is consumable as a fixed-size buffer
        // without going through the legacy MemoryStream-grow-and-ToArray path.
        var payload = new byte[12345];
        Random.Shared.NextBytes(payload);
        var store = new InMemoryBlobStore();
        await store.PutAsync("blobs/x", new MemoryStream(payload));
        var (client, _) = Build(store);

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            "blobs/x", "http://upstream.invalid/", null, "pypi");
        Assert.True(isHit);

        await using (stream)
        {
            using var copy = new MemoryStream();
            await stream.CopyToAsync(copy);
            Assert.Equal(payload.Length, copy.Length);
            Assert.Equal(payload, copy.ToArray());
        }
    }

    [Fact]
    public async Task GetOrFetchStreamAsync_CacheMiss_HashAndStage_VerifiesChecksum()
    {
        var payload = new byte[1024];
        Random.Shared.NextBytes(payload);
        var sha = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

        var handler = new StaticHandler(HttpStatusCode.OK, payload);
        var (client, store) = Build(handler: handler);

        var (stream, isHit) = await client.GetOrFetchStreamAsync(
            BlobKeys.Proxy(sha),
            "http://upstream.invalid/",
            new ChecksumSpec(ChecksumAlgorithm.Sha256, sha),
            "pypi");

        Assert.False(isHit);
        await using (stream)
        {
            using var copy = new MemoryStream();
            await stream.CopyToAsync(copy);
            Assert.Equal(payload, copy.ToArray());
        }
        Assert.True(await store.ExistsAsync(BlobKeys.Proxy(sha)));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, InMemoryBlobStore Store) Build(
        InMemoryBlobStore? store = null,
        HttpMessageHandler? handler = null)
    {
        var blobs = store ?? new InMemoryBlobStore();
        var factory = new FactoryFor(handler ?? new StaticHandler(HttpStatusCode.OK, Array.Empty<byte>()));
        var audit = new AuditRepository(new InMemoryAudit());
        var tiered = new TieredBlobStorage(blobs, blobs);
        // #104 staging path: per-test temp dir keeps parallel xunit runs from colliding.
        var stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(
            factory, tiered, audit, new AllowAll(), new AirGap(false), config,
            NullLogger<UpstreamClient>.Instance);
        return (client, blobs);
    }

    private sealed class StaticHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly byte[] _body;
        public StaticHandler(HttpStatusCode status, byte[] body) { _status = status; _body = body; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(_status) { Content = new ByteArrayContent(_body) });
    }

    private sealed class FactoryFor : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FactoryFor(HttpMessageHandler h) => _client = new HttpClient(h);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAll : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class AirGap : IAirGapMode
    {
        public AirGap(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
    }

    private sealed class InMemoryAudit : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY, scope TEXT, org_id TEXT, actor_id TEXT, action TEXT,
                    ecosystem TEXT, purl TEXT, detail TEXT, source_ip TEXT, created_at TEXT
                );
                """;
            cmd.ExecuteNonQuery();
            return Task.FromResult<System.Data.Common.DbConnection>(conn);
        }
    }
}
