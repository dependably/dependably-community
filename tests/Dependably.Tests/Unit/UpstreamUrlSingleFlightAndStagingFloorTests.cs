using System.Net;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the URL-keyed single-flight path (<see cref="UpstreamClient.FetchAndCacheByUrlAsync"/>,
/// npm/NuGet miss path): cancellation must not collapse the in-flight entry while the shared
/// fetch is still running, single-flight keys must vary with credentials, and the staging-disk
/// floor must be enforced on this path exactly like the blob-key path.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamUrlSingleFlightAndStagingFloorTests
{
    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ── Cancelled waiter must not collapse the in-flight entry (#298) ──────────

    [Fact]
    public async Task FetchAndCacheByUrlAsync_FirstWaiterCancels_SecondJoinerDoesNotTriggerSecondFetch()
    {
        var gate = new GateHandler(HttpStatusCode.OK, RandomBytes(64));
        var (client, _) = BuildClient(gate);
        const string url = "http://upstream.invalid/pkg-cancel.tgz";

        using var cts = new CancellationTokenSource();
        var firstTask = client.FetchAndCacheByUrlAsync(url, null, "npm", ct: cts.Token);

        await Task.Delay(80);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstTask);

        var secondTask = Task.Run(() => client.FetchAndCacheByUrlAsync(url, null, "npm"));
        await Task.Delay(80);
        gate.Release();
        var result = await secondTask;

        Assert.Equal(1, gate.CallCount);
        Assert.Equal(Sha256Hex(gate.ResponseBody), result.Sha256Hex);
    }

    // ── Single-flight key must vary with credentials (#299) ─────────────────────

    [Fact]
    public async Task FetchAndCacheByUrlAsync_DifferentAuthorizationHeaders_SameUrl_DoNotShareFetch()
    {
        var gate = new GateHandler(HttpStatusCode.OK, RandomBytes(32));
        var (client, _) = BuildClient(gate);
        const string url = "http://upstream.invalid/pkg-creds.tgz";

        var taskA = Task.Run(() => client.FetchAndCacheByUrlAsync(url, null, "npm", authorizationHeader: "Bearer token-a"));
        var taskB = Task.Run(() => client.FetchAndCacheByUrlAsync(url, null, "npm", authorizationHeader: "Bearer token-b"));

        await Task.Delay(80);
        gate.Release();
        await Task.WhenAll(taskA, taskB);

        Assert.Equal(2, gate.CallCount);
    }

    // ── Staging-disk floor must be enforced on the URL-keyed (npm/NuGet) miss path (#297) ──

    [Fact]
    public async Task FetchAndCacheByUrlAsync_SubFloorDisk_ThrowsStagingDiskFullExceptionBeforeGet()
    {
        // Disk reports 0 bytes available — well below the configured floor. Phase 1 must reject
        // the fetch before any upstream HTTP call, exactly like the blob-key path.
        var diskInfo = new FakeDiskInfo(available: 0, total: 10L * 1024 * 1024 * 1024);
        var handler = new FakeHttpHandler();
        var (client, _) = BuildClientWithDisk(diskInfo, handler);
        handler.NextResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(RandomBytes(16))
        };

        var ex = await Assert.ThrowsAsync<StagingDiskFullException>(() =>
            client.FetchAndCacheByUrlAsync("http://upstream.test/pkg-disk-full.tgz", null, "npm"));

        Assert.Equal(0L, ex.AvailableBytes);
        Assert.True(ex.FloorBytes > 0);
        Assert.Equal(0, handler.CallCount); // upstream never contacted
    }

    [Fact]
    public async Task FetchAndCacheByUrlAsync_ContentLengthTripsDynamicFloor_ThrowsStagingDiskFullException()
    {
        // Available disk passes the absolute floor but not the dynamic (2x content-length)
        // floor once headers arrive — Phase 2 must reject after the GET, before any bytes are
        // staged to disk.
        const long floor = 10L * 1024 * 1024; // 10 MiB
        const long available = 15L * 1024 * 1024; // 15 MiB: passes phase 1, fails phase 2 for a
                                                  // declared content-length whose 2x exceeds it.
        const long declaredContentLength = 10L * 1024 * 1024; // dynamicFloor = max(10MiB, 20MiB) = 20MiB > 15MiB

        var diskInfo = new FakeDiskInfo(available, total: 10L * 1024 * 1024 * 1024);
        var handler = new FakeHttpHandler();
        var (client, _) = BuildClientWithDisk(diskInfo, handler, floor);
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Array.Empty<byte>())
        };
        response.Content.Headers.ContentLength = declaredContentLength;
        handler.NextResponse = response;

        var ex = await Assert.ThrowsAsync<StagingDiskFullException>(() =>
            client.FetchAndCacheByUrlAsync("http://upstream.test/pkg-dynamic-floor.tgz", null, "npm"));

        Assert.True(ex.FloorBytes >= declaredContentLength * 2);
        // The GET happened (headers were needed to learn Content-Length) but staging never began.
        Assert.Equal(1, handler.CallCount);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, InMemoryBlobStore Blobs) BuildClient(HttpMessageHandler handler)
    {
        var factory = new FactoryFor(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-urlsingleflight-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(
            factory,
            tiered,
            new AuditRepository(new NullMetadataStore()),
            new AllowAllValidator(),
            new DisabledAirGap(),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir),
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        return (client, blobs);
    }

    private static (UpstreamClient Client, InMemoryBlobStore Blobs) BuildClientWithDisk(
        IStagingDiskInfo diskInfo, HttpMessageHandler handler, long stagingFloorBytes = 512L * 1024 * 1024)
    {
        var factory = new FactoryFor(handler);
        var blobs = new InMemoryBlobStore();
        var tiered = new TieredBlobStorage(blobs, blobs);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-urlsingleflight-disk-{Guid.NewGuid():N}");
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

    private sealed class GateHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly HttpStatusCode _status;
        private int _callCount;

        public GateHandler(HttpStatusCode status, byte[] body)
        {
            _status = status;
            ResponseBody = body;
        }

        public byte[] ResponseBody { get; }
        public int CallCount => _callCount;

        public void Release() => _gate.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _callCount);
            await _gate.Task.WaitAsync(cancellationToken);
            return new HttpResponseMessage(_status)
            {
                Content = new ByteArrayContent(ResponseBody)
            };
        }
    }

    private sealed class FakeHttpHandler : HttpMessageHandler
    {
        public HttpResponseMessage NextResponse { get; set; } = new(HttpStatusCode.OK);
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(NextResponse);
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
        private readonly long _total;
        public FakeDiskInfo(long available, long total) { _available = available; _total = total; }
        public long GetAvailableBytes() => _available;
        public long GetTotalBytes() => _total;
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
