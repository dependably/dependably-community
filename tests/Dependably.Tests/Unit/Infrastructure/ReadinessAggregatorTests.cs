using System.Data.Common;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Health;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for the hard/soft readiness split.
///
/// <para>The shape under test: <c>/ready</c> is the load-balancer health check, and every
/// dependency it probes is shared by the whole replica fleet. Failing the probe on a shared
/// dependency deregisters every replica simultaneously for a condition none of them can route
/// around, so only <em>required</em> dependencies (the metadata store by default; also the blob
/// store on an edge node) may answer 503. Everything else is reported as degradation.</para>
///
/// <para>Probe cost is covered too: the blob-store probe result is cached for a short TTL on the
/// injected <see cref="FakeTimeProvider"/> so a poll burst across load-balancer nodes does not
/// become one object-store metadata call per poll. All time reads are exact instants.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ReadinessAggregatorTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static IConfiguration Config(params (string Key, string? Value)[] pairs) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(pairs.ToDictionary(p => p.Key, p => p.Value))
            .Build();

    private static IServiceProvider EmptyServices() => new ServiceCollection().BuildServiceProvider();

    private ReadinessAggregator Build(
        IBlobStore blobs,
        ReadinessOptions options,
        TimeProvider time,
        IMetadataStore? db = null)
        => new(db ?? _db, blobs, EmptyServices(), logger: null, time: time, options: options);

    private static ReadinessOptions FullPlaneDefaults() => ReadinessOptions.Resolve(Config());

    // ── Classification ────────────────────────────────────────────────────────

    [Fact]
    public void Resolve_FullPlane_MarksOnlyMetadataStoreRequired()
    {
        var options = ReadinessOptions.Resolve(Config());

        Assert.True(options.IsRequired(ReadinessOptions.DbCheck));
        Assert.False(options.IsRequired(ReadinessOptions.BlobStoreCheck));
        Assert.False(options.IsRequired(ReadinessOptions.RedisCheck));
    }

    [Fact]
    public void Resolve_EdgePlane_AlsoMarksBlobStoreRequired()
    {
        // An edge node exists to serve artefact bytes out of its own (node-local) blob store,
        // so blob storage is load-bearing there — and a node-local failure is exactly the
        // uncorrelated condition a load balancer can genuinely route around.
        var options = ReadinessOptions.Resolve(Config(("DEPLOYMENT_MODE", "edge")));

        Assert.True(options.IsRequired(ReadinessOptions.DbCheck));
        Assert.True(options.IsRequired(ReadinessOptions.BlobStoreCheck));
        Assert.False(options.IsRequired(ReadinessOptions.RedisCheck));
    }

    [Fact]
    public void Resolve_HardDependencyOverride_ReplacesPlaneDefaults()
    {
        var options = ReadinessOptions.Resolve(
            Config(("READINESS_HARD_DEPENDENCIES", "db, blob_store , redis")));

        Assert.True(options.IsRequired(ReadinessOptions.DbCheck));
        Assert.True(options.IsRequired(ReadinessOptions.BlobStoreCheck));
        Assert.True(options.IsRequired(ReadinessOptions.RedisCheck));
    }

    [Fact]
    public void Resolve_BlobProbeTtl_DefaultsAndHonoursExplicitZero()
    {
        Assert.Equal(ReadinessOptions.DefaultBlobProbeTtl, ReadinessOptions.Resolve(Config()).BlobProbeTtl);
        Assert.Equal(
            TimeSpan.Zero,
            ReadinessOptions.Resolve(Config(("READINESS_BLOB_PROBE_TTL_SECONDS", "0"))).BlobProbeTtl);
        Assert.Equal(
            TimeSpan.FromSeconds(45),
            ReadinessOptions.Resolve(Config(("READINESS_BLOB_PROBE_TTL_SECONDS", "45"))).BlobProbeTtl);
    }

    // ── Report semantics ──────────────────────────────────────────────────────

    [Fact]
    public async Task CheckAsync_FailingSoftDependency_KeepsRequiredChecksGreen()
    {
        var clock = TestTime.Frozen();
        var aggregator = Build(new FailingBlobStore(), FullPlaneDefaults(), clock);

        var report = await aggregator.CheckAsync(CancellationToken.None);

        Assert.False(report.AllOk);
        Assert.True(report.RequiredOk);
        Assert.Equal([ReadinessOptions.BlobStoreCheck], report.FailingChecks);
        Assert.Equal([ReadinessOptions.DbCheck], report.RequiredChecks);
        Assert.Equal("error", report.ToStatusMap()[ReadinessOptions.BlobStoreCheck]);
        Assert.Equal("ok", report.ToStatusMap()[ReadinessOptions.DbCheck]);
    }

    [Fact]
    public async Task CheckAsync_FailingRequiredDependency_FailsRequiredChecks()
    {
        var clock = TestTime.Frozen();
        var aggregator = Build(
            new CountingBlobStore(clock), FullPlaneDefaults(), clock, db: new FailingMetadataStore());

        var report = await aggregator.CheckAsync(CancellationToken.None);

        Assert.False(report.AllOk);
        Assert.False(report.RequiredOk);
        Assert.Equal([ReadinessOptions.DbCheck], report.FailingChecks);
    }

    [Fact]
    public async Task CheckAsync_BlobStoreRequiredByConfiguration_FailsRequiredChecks()
    {
        // The operator override is the escape hatch back to the strict-on-every-probe posture.
        var clock = TestTime.Frozen();
        var options = ReadinessOptions.Resolve(Config(("READINESS_HARD_DEPENDENCIES", "db,blob_store")));
        var aggregator = Build(new FailingBlobStore(), options, clock);

        var report = await aggregator.CheckAsync(CancellationToken.None);

        Assert.False(report.RequiredOk);
        Assert.Contains(ReadinessOptions.BlobStoreCheck, report.RequiredChecks);
    }

    [Fact]
    public async Task CheckAsync_NeverLeaksRawErrorTextIntoTheStatusMap()
    {
        var clock = TestTime.Frozen();
        var aggregator = Build(new FailingBlobStore(), FullPlaneDefaults(), clock);

        var report = await aggregator.CheckAsync(CancellationToken.None);

        Assert.Contains(FailingBlobStore.SecretDetail, report.Checks
            .Single(c => c.Name == ReadinessOptions.BlobStoreCheck).Error);
        Assert.DoesNotContain(FailingBlobStore.SecretDetail, string.Join(",", report.ToStatusMap().Values));
    }

    // ── Blob-probe cache (exact instants on FakeTimeProvider) ──────────────────

    [Fact]
    public async Task BlobProbe_IsReusedWithinTtlAndReprobedExactlyAtIt()
    {
        var clock = TestTime.Frozen();
        var blobs = new CountingBlobStore(clock);
        var ttl = TimeSpan.FromSeconds(15);
        var aggregator = Build(blobs, new ReadinessOptions([ReadinessOptions.DbCheck], ttl), clock);

        await aggregator.CheckAsync(CancellationToken.None);
        Assert.Equal(1, blobs.ExistsCalls);

        // Repeated polls at the same instant — a load-balancer burst across nodes — reuse it.
        await aggregator.CheckAsync(CancellationToken.None);
        await aggregator.CheckAsync(CancellationToken.None);
        Assert.Equal(1, blobs.ExistsCalls);

        // One tick short of the TTL is still a cache hit.
        clock.SetUtcNow(TestTime.KnownNow + ttl - TimeSpan.FromSeconds(1));
        await aggregator.CheckAsync(CancellationToken.None);
        Assert.Equal(1, blobs.ExistsCalls);

        // Exactly at the TTL the entry has expired and the store is probed again.
        clock.SetUtcNow(TestTime.KnownNow + ttl);
        await aggregator.CheckAsync(CancellationToken.None);
        Assert.Equal(2, blobs.ExistsCalls);
        Assert.Equal(TestTime.KnownNow + ttl, blobs.LastProbedAt);

        // …and the fresh entry is then reused for a further full TTL.
        clock.SetUtcNow(TestTime.KnownNow + ttl + ttl - TimeSpan.FromSeconds(1));
        await aggregator.CheckAsync(CancellationToken.None);
        Assert.Equal(2, blobs.ExistsCalls);
    }

    [Fact]
    public async Task BlobProbe_CachesFailureToo_SoADownStoreIsNotHammered()
    {
        var clock = TestTime.Frozen();
        var blobs = new FailingBlobStore();
        var aggregator = Build(
            blobs, new ReadinessOptions([ReadinessOptions.DbCheck], TimeSpan.FromSeconds(15)), clock);

        await aggregator.CheckAsync(CancellationToken.None);
        var second = await aggregator.CheckAsync(CancellationToken.None);

        Assert.Equal(1, blobs.ExistsCalls);
        Assert.Contains(ReadinessOptions.BlobStoreCheck, second.FailingChecks);
    }

    [Fact]
    public async Task BlobProbe_ZeroTtl_ProbesEveryCall()
    {
        var clock = TestTime.Frozen();
        var blobs = new CountingBlobStore(clock);
        var aggregator = Build(blobs, new ReadinessOptions([ReadinessOptions.DbCheck], TimeSpan.Zero), clock);

        await aggregator.CheckAsync(CancellationToken.None);
        await aggregator.CheckAsync(CancellationToken.None);
        await aggregator.CheckAsync(CancellationToken.None);

        Assert.Equal(3, blobs.ExistsCalls);
    }

    // ── /ready decision ───────────────────────────────────────────────────────

    [Fact]
    public void Ready_SoftDependencyDown_StaysHealthyForTheLoadBalancer()
    {
        var report = new ReadinessReport([
            new ReadinessCheck(ReadinessOptions.DbCheck, Required: true, Error: null),
            new ReadinessCheck(ReadinessOptions.BlobStoreCheck, Required: false, Error: "S3 503"),
            new ReadinessCheck(ReadinessOptions.RedisCheck, Required: false, Error: null),
        ]);

        var (body, status) = HealthEndpoints.EvaluateReadiness(report, strictView: false);

        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.Equal("degraded", body.Status);
        Assert.False(body.Strict);
        Assert.Equal("error", body.Checks[ReadinessOptions.BlobStoreCheck]);
        Assert.Equal([ReadinessOptions.BlobStoreCheck], body.Degraded);
        Assert.Equal([ReadinessOptions.DbCheck], body.Required);
        // The degradation is legible as non-load-bearing: it is not in the required set.
        Assert.DoesNotContain(ReadinessOptions.BlobStoreCheck, body.Required);
    }

    [Fact]
    public void Ready_RequiredDependencyDown_Is503()
    {
        var report = new ReadinessReport([
            new ReadinessCheck(ReadinessOptions.DbCheck, Required: true, Error: "connection refused"),
            new ReadinessCheck(ReadinessOptions.BlobStoreCheck, Required: false, Error: null),
        ]);

        var (body, status) = HealthEndpoints.EvaluateReadiness(report, strictView: false);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, status);
        Assert.Equal("unready", body.Status);
        Assert.Equal([ReadinessOptions.DbCheck], body.Degraded);
        Assert.Contains(ReadinessOptions.DbCheck, body.Required);
    }

    [Fact]
    public void Ready_StrictView_Is503WhenAnySoftDependencyIsDown()
    {
        var report = new ReadinessReport([
            new ReadinessCheck(ReadinessOptions.DbCheck, Required: true, Error: null),
            new ReadinessCheck(ReadinessOptions.RedisCheck, Required: false, Error: "failover"),
        ]);

        var (body, status) = HealthEndpoints.EvaluateReadiness(report, strictView: true);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, status);
        Assert.Equal("degraded", body.Status);
        Assert.True(body.Strict);
        Assert.Equal([ReadinessOptions.RedisCheck], body.Degraded);
    }

    [Fact]
    public void Ready_AllGreen_Is200InBothViews()
    {
        var report = new ReadinessReport([
            new ReadinessCheck(ReadinessOptions.DbCheck, Required: true, Error: null),
            new ReadinessCheck(ReadinessOptions.BlobStoreCheck, Required: false, Error: null),
        ]);

        var (lenientBody, lenientStatus) = HealthEndpoints.EvaluateReadiness(report, strictView: false);
        var (strictBody, strictStatus) = HealthEndpoints.EvaluateReadiness(report, strictView: true);

        Assert.Equal(StatusCodes.Status200OK, lenientStatus);
        Assert.Equal(StatusCodes.Status200OK, strictStatus);
        Assert.Equal("ready", lenientBody.Status);
        Assert.Equal("ready", strictBody.Status);
        Assert.Empty(lenientBody.Degraded);
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class CountingBlobStore : IBlobStore
    {
        private readonly TimeProvider _time;

        public CountingBlobStore(TimeProvider time) => _time = time;

        public int ExistsCalls { get; private set; }
        public DateTimeOffset? LastProbedAt { get; private set; }

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            ExistsCalls++;
            LastProbedAt = _time.GetUtcNow();
            return Task.FromResult(false);
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => Task.FromResult<Stream?>(null);
        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(0L);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => Task.FromResult<RangedStream?>(null);
        public async IAsyncEnumerable<BlobInfo> ListAsync(
            string prefix,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }

    private sealed class FailingBlobStore : IBlobStore
    {
        internal const string SecretDetail = "/var/lib/dependably/blobs is unreachable";

        public int ExistsCalls { get; private set; }

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            ExistsCalls++;
            throw new IOException(SecretDetail);
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => Task.FromResult<Stream?>(null);
        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(0L);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => Task.FromResult<RangedStream?>(null);
        public async IAsyncEnumerable<BlobInfo> ListAsync(
            string prefix,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }

    private sealed class FailingMetadataStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("metadata store connection refused");
    }
}
