using System.Net;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Single-flight acceptance: <see cref="UpstreamClient.GetOrFetchMetadataAsync"/>
/// must coalesce N concurrent calls for the same URL into one upstream HTTP request.
/// The previous controllers called <see cref="UpstreamClient.GetMetadataAsync"/> directly
/// from the first-fetch path, which had no dedup map and let cold-start CI fan-out hit
/// upstream N times for one coordinate.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamMetadataSingleFlightTests
{
    [Fact]
    public async Task ConcurrentMetadataFetches_ProduceOneUpstreamRequest()
    {
        // GateHandler holds every incoming request open until ReleaseAsync is signalled.
        // That window lets us line up multiple concurrent callers on the same URL before
        // letting the underlying HTTP call resolve — exactly the race the dedup map exists
        // to collapse.
        var handler = new GateHandler(HttpStatusCode.OK, "metadata-body");
        var (client, _) = BuildClient(handler);

        const string url = "http://upstream.invalid/pkg/index.json";
        var tasks = Enumerable.Range(0, 8)
            .Select(_ => Task.Run(() => client.GetOrFetchMetadataAsync(url)))
            .ToArray();

        // Give the scheduler a tick to let all callers reach GetOrFetchMetadataAsync and
        // register in the in-flight map before we release the upstream response.
        await Task.Delay(50);
        handler.Release();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, handler.CallCount);
        foreach (var r in results)
        {
            Assert.True(r.IsSuccessStatusCode);
            Assert.Equal("metadata-body", r.BodyAsString());
        }
    }

    [Fact]
    public async Task SubsequentMetadataFetch_AfterFirstReleases_RunsFresh()
    {
        // After the first batch resolves, the in-flight entry is removed; a follow-up
        // call should trigger a fresh upstream request (the helper has no caching layer
        // — single-flight only collapses *concurrent* callers).
        var handler = new GateHandler(HttpStatusCode.OK, "first-body");
        var (client, _) = BuildClient(handler);

        const string url = "http://upstream.invalid/pkg/index.json";
        var first = client.GetOrFetchMetadataAsync(url);
        await Task.Delay(50);
        handler.Release();
        _ = await first;

        // Swap the response — proves the second call genuinely re-hit upstream.
        handler.Reset(HttpStatusCode.OK, "second-body");
        var secondTask = client.GetOrFetchMetadataAsync(url);
        await Task.Delay(50);
        handler.Release();
        var second = await secondTask;

        Assert.Equal(2, handler.CallCount);
        Assert.Equal("second-body", second.BodyAsString());
    }

    [Fact]
    public async Task GetOrFetchMetadataAsync_AirGapped_Throws()
    {
        var handler = new GateHandler(HttpStatusCode.OK, "");
        var (client, _) = BuildClient(handler, airGapped: true);

        await Assert.ThrowsAsync<AirGappedException>(
            () => client.GetOrFetchMetadataAsync("http://upstream.invalid/x"));
    }

    [Fact]
    public async Task GetOrFetchMetadataAsync_BlockedByValidator_Throws()
    {
        var handler = new GateHandler(HttpStatusCode.OK, "");
        var (client, _) = BuildClient(handler, validator: new BlockAllValidator());

        await Assert.ThrowsAsync<SsrfBlockedException>(
            () => client.GetOrFetchMetadataAsync("http://forbidden/"));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, GateHandler Handler) BuildClient(
        GateHandler handler,
        IUpstreamUrlValidator? validator = null,
        bool airGapped = false)
    {
        var factory = new FactoryFor(handler);
        var blobs = new InMemoryBlobStore();
        var audit = new AuditRepository(new InMemoryMetadataStore());
        var airGap = new AirGap(airGapped);
        var tiered = new TieredBlobStorage(blobs, blobs);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(
            factory,
            tiered,
            audit,
            validator ?? new AllowEverythingValidator(),
            airGap,
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir),
            config,
            NullLogger<UpstreamClient>.Instance);
        return (client, handler);
    }

    private sealed class GateHandler : HttpMessageHandler
    {
        private TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private HttpStatusCode _status;
        private string _body;
        public int CallCount;

        public GateHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }

        public void Release() => _gate.TrySetResult();

        public void Reset(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
            _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            await _gate.Task.WaitAsync(cancellationToken);
            return new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, System.Text.Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class FactoryFor : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FactoryFor(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class AirGap : IAirGapMode
    {
        public AirGap(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }

    private sealed class AllowEverythingValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class BlockAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(false);
    }

    /// <summary>Discard-only metadata store for unit tests that only need AuditRepository to no-op.</summary>
    private sealed class InMemoryMetadataStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    org_id TEXT, user_id TEXT, action TEXT, target TEXT, detail TEXT,
                    actor_email TEXT, created_at TEXT,
                    source_ip TEXT
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id TEXT PRIMARY KEY,
                    org_id TEXT, package_version_id TEXT, action TEXT, user_id TEXT,
                    purl TEXT, detail TEXT, source_ip TEXT, created_at TEXT
                );
                """;
            cmd.ExecuteNonQuery();
            return Task.FromResult<System.Data.Common.DbConnection>(conn);
        }
    }
}
