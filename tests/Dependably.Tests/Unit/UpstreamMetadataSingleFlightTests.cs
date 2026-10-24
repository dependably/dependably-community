using System.Net;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
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
// BlockAllValidator drives the real IUpstreamUrlValidator.IsAllowedAsync extension, which emits
// to the process-wide static dependably.security.upstream_url_blocks counter that
// UpstreamUrlBlocksEmissionTests asserts exact counts against. See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
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
        // Invoke all 8 callers directly (not via Task.Run), one after another, without awaiting
        // in between. GetOrFetchMetadataAsync's synchronous prologue — including the in-flight
        // map registration — runs to completion on THIS thread before its first real suspension
        // point (no cache configured here, and the fake validator's CheckAsync completes
        // synchronously), so each call has already registered by the time it returns a pending
        // Task. Deterministic by construction: no thread pool scheduling, no signal, no margin.
        var tasks = new Task<UpstreamMetadataResponse>[8];
        for (int i = 0; i < tasks.Length; i++)
        {
            tasks[i] = client.GetOrFetchMetadataAsync(url);
        }

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
        await handler.WaitForCallCountAsync(1);
        handler.Release();
        _ = await first;

        // Swap the response — proves the second call genuinely re-hit upstream.
        handler.Reset(HttpStatusCode.OK, "second-body");
        var secondTask = client.GetOrFetchMetadataAsync(url);
        await handler.WaitForCallCountAsync(2);
        handler.Release();
        var second = await secondTask;

        Assert.Equal(2, handler.CallCount);
        Assert.Equal("second-body", second.BodyAsString());
    }

    [Fact]
    public async Task FirstWaiterCancels_SecondJoinerDoesNotTriggerSecondFetch()
    {
        // The first caller's WaitAsync(ct) detaches early (its own token cancels) while the
        // shared upstream fetch is still running. A second, uncancelled caller for the SAME
        // (url, maxBytes, authorizationHeader) coordinate must join the SAME shared fetch rather
        // than triggering a brand-new upstream call.
        var handler = new GateHandler(HttpStatusCode.OK, "metadata-body");
        var (client, _) = BuildClient(handler);
        const string url = "http://upstream.invalid/pkg/cancel-index.json";

        using var cts = new CancellationTokenSource();
        var firstTask = client.GetOrFetchMetadataAsync(url, authorizationHeader: null, ct: cts.Token);

        await handler.WaitForCallCountAsync(1);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstTask);

        // Calling it directly (not via Task.Run) is deterministic, not just best-effort:
        // GetOrFetchMetadataAsync's synchronous prologue — including the in-flight map
        // registration — runs to completion on THIS thread before the method's first real
        // suspension point, and that happens-before relationship holds regardless of scheduler
        // contention (unlike a cross-thread "has it started yet" signal, which a sufficiently
        // loaded box can still lose the race against). Only after that registration has
        // definitely landed do we release the gate.
        var secondTask = client.GetOrFetchMetadataAsync(url);
        handler.Release();
        var second = await secondTask;

        Assert.Equal(1, handler.CallCount);
        Assert.Equal("metadata-body", second.BodyAsString());
    }

    [Fact]
    public async Task DifferentAuthorizationHeaders_SameUrl_DoNotShareFetch()
    {
        // Single-flight keys must include a hash of the Authorization header: two callers
        // presenting different credentials for the identical URL must never ride the same
        // fetch — otherwise the second caller would silently inherit the first caller's
        // upstream credentials (and any resulting audit/attribution).
        var handler = new GateHandler(HttpStatusCode.OK, "shared-body");
        var (client, _) = BuildClient(handler);
        const string url = "http://upstream.invalid/pkg/creds-index.json";

        var taskA = Task.Run(() => client.GetOrFetchMetadataAsync(url, authorizationHeader: "Bearer token-a"));
        var taskB = Task.Run(() => client.GetOrFetchMetadataAsync(url, authorizationHeader: "Bearer token-b"));

        // Different credentials never collapse, so both callers independently reach the gate —
        // wait for both real arrivals rather than guessing at scheduling latency.
        await handler.WaitForCallCountAsync(2);
        handler.Release();
        await Task.WhenAll(taskA, taskB);

        // Two distinct credentials on the identical URL must not collapse into one fetch.
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task DifferentMaxBytes_SameUrl_DoNotShareFetch()
    {
        // A metadata caller (32 MB cap) and an artifact-buffering caller (600 MB cap) hitting the
        // identical URL must never share a fetch — the winner's cap would otherwise silently
        // apply to the other caller too.
        var handler = new GateHandler(HttpStatusCode.OK, "shared-body");
        var (client, _) = BuildClient(handler);
        const string url = "http://upstream.invalid/pkg/cap-index.json";

        var taskA = Task.Run(() => client.GetOrFetchMetadataAsync(url, UpstreamClient.MaxMetadataResponseBytes, null));
        var taskB = Task.Run(() => client.GetOrFetchMetadataAsync(url, UpstreamClient.MaxUpstreamResponseBytes, null));

        // Different caps never collapse, so both callers independently reach the gate — wait
        // for both real arrivals rather than guessing at scheduling latency.
        await handler.WaitForCallCountAsync(2);
        handler.Release();
        await Task.WhenAll(taskA, taskB);

        Assert.Equal(2, handler.CallCount);
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

    [Fact]
    public async Task StalledBody_FailsAtDeadline_AndNextFetchRunsFresh()
    {
        // HttpClient.Timeout stops applying once headers arrive, so an upstream that sends
        // headers and then never sends another body byte must still fail the shared fetch at
        // its own deadline — otherwise the in-flight entry is never removed and every later
        // caller for the URL joins a fetch that never completes, until the process restarts.
        var time = TestTime.Frozen();
        var handler = new StalledBodyHandler();
        var (client, _) = BuildClient(handler, time: time);
        const string url = "http://upstream.invalid/simple/ruff/";

        var stalled = client.GetOrFetchMetadataAsync(url);
        await handler.BodyReadStarted.WaitAsync(TimeSpan.FromSeconds(10));

        time.Advance(UpstreamClient.MetadataFetchDeadline);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(() => stalled.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.IsType<TimeoutException>(ex.InnerException);

        // The failed fetch left the in-flight map, so the next caller reaches upstream again.
        handler.StallBody = false;
        var fresh = await client.GetOrFetchMetadataAsync(url).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(2, handler.CallCount);
        Assert.Equal("fresh-body", fresh.BodyAsString());
    }

    [Fact]
    public async Task StalledBody_BeforeDeadline_StillPending()
    {
        // Twin of the deadline test: the shared fetch is not failed early, so a slow but live
        // upstream inside the budget is not cut off.
        var time = TestTime.Frozen();
        var handler = new StalledBodyHandler();
        var (client, _) = BuildClient(handler, time: time);

        var stalled = client.GetOrFetchMetadataAsync("http://upstream.invalid/simple/slow/");
        await handler.BodyReadStarted.WaitAsync(TimeSpan.FromSeconds(10));

        time.Advance(UpstreamClient.MetadataFetchDeadline - TimeSpan.FromSeconds(1));

        Assert.False(stalled.IsCompleted);
        Assert.Equal(1, handler.CallCount);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, THandler Handler) BuildClient<THandler>(
        THandler handler,
        IUpstreamUrlValidator? validator = null,
        bool airGapped = false,
        TimeProvider? time = null)
        where THandler : HttpMessageHandler
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
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance,
            time: time);
        return (client, handler);
    }

    // Answers with 200 headers immediately; while StallBody is set, the body stream then never
    // yields a byte until its read is cancelled — a half-open upstream connection.
    private sealed class StalledBodyHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _bodyReadStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int CallCount;
        public volatile bool StallBody = true;

        public Task BodyReadStarted => _bodyReadStarted.Task;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref CallCount);
            HttpContent content = StallBody
                ? new StreamContent(new StalledStream(_bodyReadStarted))
                : new StringContent("fresh-body", System.Text.Encoding.UTF8, "application/json");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        }
    }

    private sealed class StalledStream : Stream
    {
        private readonly TaskCompletionSource _readStarted;
        public StalledStream(TaskCompletionSource readStarted) => _readStarted = readStarted;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _readStarted.TrySetResult();
            await new TaskCompletionSource().Task.WaitAsync(cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class GateHandler : HttpMessageHandler
    {
        private readonly object _arrivalLock = new();
        private TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource? _arrival;
        private int _arrivalTarget;
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

        /// <summary>
        /// Completes once the gate has been hit by at least <paramref name="count"/> requests —
        /// a deterministic replacement for guessing how long a caller takes to reach the HTTP
        /// layer with a fixed <see cref="Task.Delay(int)"/>, which flakes under load. CallCount
        /// is cumulative across <see cref="Reset"/>.
        /// </summary>
        public Task WaitForCallCountAsync(int count, CancellationToken ct = default)
        {
            lock (_arrivalLock)
            {
                if (CallCount >= count)
                {
                    return Task.CompletedTask;
                }

                _arrivalTarget = count;
                _arrival = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                return _arrival.Task.WaitAsync(ct);
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int count = Interlocked.Increment(ref CallCount);
            lock (_arrivalLock)
            {
                if (_arrival is not null && count >= _arrivalTarget)
                {
                    _arrival.TrySetResult();
                }
            }

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
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class BlockAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.BlockedRange);
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
