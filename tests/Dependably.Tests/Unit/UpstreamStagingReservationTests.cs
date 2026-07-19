using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the staging-disk floor's in-flight reservation ledger: concurrent fetches must
/// account for each OTHER's declared-but-not-yet-written bytes, not just a static disk-space
/// snapshot. Without the reservation ledger, two concurrent large fetches can each pass their
/// own floor check against the same free-space reading and together overrun the volume.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamStagingReservationTests
{
    [Fact]
    public async Task ConcurrentLargeFetch_ReservesDeclaredBytes_SecondFetchSeesReducedAvailability()
    {
        // available = 5,000,000 bytes; floor = 4,900,000 bytes. Fetch A declares 500,000 bytes —
        // on its own, both floor phases pass (5,000,000 >= 4,900,000). Fetch A's HTTP response
        // headers (and therefore its Content-Length) arrive immediately, but its BODY read is
        // gated, so we can deterministically observe the moment after A has reserved its bytes
        // but before it has written any of them to disk. A concurrent Fetch B (distinct blobKey,
        // same client instance so the reservation ledger is shared) must then fail Phase 1
        // because 5,000,000 - 500,000 (A's reservation) = 4,500,000 < 4,900,000 — even though
        // the disk itself still reports the same static 5,000,000 snapshot the whole time.
        const long available = 5_000_000;
        const long floor = 4_900_000;
        const long contentLengthA = 500_000;

        byte[] payloadA = new byte[contentLengthA];
        Random.Shared.NextBytes(payloadA);
        string shaA = Convert.ToHexString(SHA256.HashData(payloadA)).ToLowerInvariant();

        var bodyGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var bodyReadStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var routing = new RoutingHandler();
        routing.AddRoute("http://upstream.invalid/a.whl", new BodyGatedHandler(payloadA, bodyGate.Task, bodyReadStarted));
        routing.AddRoute("http://upstream.invalid/b.whl", new CountingHandler(HttpStatusCode.OK, []));

        var diskInfo = new FakeDiskInfo(available);
        var (client, _) = BuildClient(routing, diskInfo, floor);

        var fetchA = Task.Run(() => client.GetOrFetchStreamAsync(
            "blobs/reserve-a", "http://upstream.invalid/a.whl",
            new ChecksumSpec(ChecksumAlgorithm.Sha256, shaA), "pypi"));

        // Deterministically wait until A's response body read has actually started — production
        // code (UpstreamClient.GetOrFetchStreamAsync) reserves the declared bytes strictly before
        // it begins reading the response body, so this signal only fires after phase 1, headers,
        // phase 2, and the reservation have all already happened. A fixed delay only guesses at
        // how long that synchronous prefix takes and flakes under load.
        await bodyReadStarted.Task;

        // B must fail Phase 1 because A's reservation is still outstanding.
        var ex = await Assert.ThrowsAsync<StagingDiskFullException>(() =>
            client.GetOrFetchStreamAsync(
                "blobs/reserve-b", "http://upstream.invalid/b.whl", null, "pypi"));
        Assert.Equal(available - contentLengthA, ex.AvailableBytes);

        // B's own HTTP GET must never fire — Phase 1 rejects before the network call.
        var bHandler = Assert.IsType<CountingHandler>(routing.HandlerFor("http://upstream.invalid/b.whl"));
        Assert.Equal(0, bHandler.CallCount);

        // Release A so it completes and the reservation is released; the client (and its ledger)
        // stay well-behaved afterward.
        bodyGate.SetResult();
        var (streamA, _) = await fetchA;
        await streamA.DisposeAsync();

        // With A's reservation released, a THIRD fetch for the same coordinate B now succeeds.
        var (streamB, _) = await client.GetOrFetchStreamAsync(
            "blobs/reserve-b", "http://upstream.invalid/b.whl", null, "pypi");
        await streamB.DisposeAsync();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, InMemoryBlobStore Blobs) BuildClient(
        HttpMessageHandler handler, IStagingDiskInfo diskInfo, long stagingFloorBytes)
    {
        var factory = new FactoryFor(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-reservation-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = stagingDir,
                ["STAGING_DISK_FLOOR_BYTES"] = stagingFloorBytes.ToString(),
            })
            .Build();
        var client = new UpstreamClient(
            factory,
            tiered,
            new AuditRepository(new NullMetadataStore()),
            new AllowAllValidator(),
            new DisabledAirGap(),
            diskInfo,
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        return (client, blobs);
    }

    // ── Test doubles ─────────────────────────────────────────────────────────

    /// <summary>
    /// Returns response headers (including Content-Length) immediately, but blocks the actual
    /// body read until <paramref name="bodyReady"/> completes — lets a test observe the window
    /// between "headers arrived / bytes reserved" and "bytes actually written".
    /// </summary>
    private sealed class BodyGatedHandler : IRoutedHandler
    {
        private readonly byte[] _body;
        private readonly Task _bodyReady;
        private readonly TaskCompletionSource? _bodyReadStarted;
        public int CallCount { get; private set; }

        public BodyGatedHandler(byte[] body, Task bodyReady, TaskCompletionSource? bodyReadStarted = null)
        {
            _body = body;
            _bodyReady = bodyReady;
            _bodyReadStarted = bodyReadStarted;
        }

        public Task<HttpResponseMessage> InvokeAsync(HttpRequestMessage request, CancellationToken ct)
        {
            CallCount++;
            var content = new BodyGatedContent(_body, _bodyReady, _bodyReadStarted);
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
            return Task.FromResult(response);
        }
    }

    private sealed class BodyGatedContent : HttpContent
    {
        private readonly byte[] _body;
        private readonly Task _bodyReady;
        private readonly TaskCompletionSource? _bodyReadStarted;

        public BodyGatedContent(byte[] body, Task bodyReady, TaskCompletionSource? bodyReadStarted = null)
        {
            _body = body;
            _bodyReady = bodyReady;
            _bodyReadStarted = bodyReadStarted;
            Headers.ContentLength = body.Length;
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            // Signals that the caller has reached the body-read step — production code reserves
            // the declared bytes strictly before this point, so this is a valid, deterministic
            // proxy for "the reservation has already happened."
            _bodyReadStarted?.TrySetResult();
            await _bodyReady;
            await stream.WriteAsync(_body);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _body.Length;
            return true;
        }
    }

    /// <summary>Public forwarder so RoutingHandler can dispatch without subclassing HttpMessageHandler.</summary>
    private interface IRoutedHandler
    {
        Task<HttpResponseMessage> InvokeAsync(HttpRequestMessage request, CancellationToken ct);
    }

    private sealed class CountingHandler : IRoutedHandler
    {
        private readonly HttpStatusCode _status;
        private readonly byte[] _body;
        public int CallCount { get; private set; }

        public CountingHandler(HttpStatusCode status, byte[] body)
        {
            _status = status;
            _body = body;
        }

        public Task<HttpResponseMessage> InvokeAsync(HttpRequestMessage request, CancellationToken ct)
        {
            CallCount++;
            return Task.FromResult(new HttpResponseMessage(_status) { Content = new ByteArrayContent(_body) });
        }
    }

    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly List<(string Prefix, IRoutedHandler Handler)> _routes = new();

        public void AddRoute(string prefix, IRoutedHandler handler) => _routes.Add((prefix, handler));

        public IRoutedHandler HandlerFor(string url) =>
            _routes.First(r => url.StartsWith(r.Prefix, StringComparison.Ordinal)).Handler;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri?.ToString() ?? string.Empty;
            foreach (var (prefix, handler) in _routes)
            {
                if (url.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return handler.InvokeAsync(request, cancellationToken);
                }
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class FactoryFor : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FactoryFor(HttpMessageHandler handler) => _client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class DisabledAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class FakeDiskInfo : IStagingDiskInfo
    {
        private readonly long _available;
        public FakeDiskInfo(long available) => _available = available;
        public long GetAvailableBytes() => _available;
        public long GetTotalBytes() => 10L * 1024 * 1024 * 1024;
        public long GetStagingDirectoryUsedBytes() => 0;
    }

    private sealed class NullMetadataStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, action TEXT, target TEXT,
                    detail TEXT, actor_email TEXT, created_at TEXT, source_ip TEXT);
                CREATE TABLE IF NOT EXISTS activity (
                    id TEXT PRIMARY KEY, org_id TEXT, package_version_id TEXT, action TEXT,
                    user_id TEXT, purl TEXT, detail TEXT, source_ip TEXT, created_at TEXT);
                """;
            cmd.ExecuteNonQuery();
            return Task.FromResult<System.Data.Common.DbConnection>(conn);
        }
    }
}
