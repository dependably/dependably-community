using System.Diagnostics.Metrics;
using System.Threading.RateLimiting;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Microsoft.Extensions.Logging;
using NSubstitute;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure.Redis;

/// <summary>
/// Behavioral tests for the Redis fixed-window rate limiter.
///
/// Backend-unavailable contract: when Redis cannot answer, the limiter resolves the request by
/// the configured posture — grant under fail-open (the default, pinned by
/// <see cref="Acquire_RedisThrows_FailsOpen_AcquiresLease"/>), deny under fail-closed (pinned by
/// <see cref="Acquire_RedisThrows_FailClosed_RejectsWithWindowRetryAfter"/>) — and in BOTH cases
/// logs at Warning and increments <c>dependably.rate_limit.backend_unavailable</c> with the
/// policy name. A limiter that silently stops limiting is indistinguishable from one that works.
///
/// Attaches a MeterListener filtered only by DependablyMeter.MeterName + instrument name and
/// asserts exact counts — must run alone against the process-wide static meter.
/// See MeterSensitiveCollection.
/// </summary>
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class RedisFixedWindowRateLimiterTests
{
    private const string BackendUnavailableInstrument = "dependably.rate_limit.backend_unavailable";

    private readonly IDatabase _db = Substitute.For<IDatabase>();
    private readonly CapturingLogger _logger = new();

    private RedisFixedWindowRateLimiter NewSut(
        int permitLimit = 5, int windowSeconds = 60, bool failOpen = true)
        => new(
            _db,
            new RedisFixedWindowRateLimiter.Settings(
                KeyPrefix: "p:", Scope: "login", Bucket: "ip-1.2.3.4",
                PermitLimit: permitLimit, WindowSeconds: windowSeconds, FailOpen: failOpen),
            TimeProvider.System,
            _logger);

    private static RedisResult Pair(long count, long ttl) =>
        RedisResult.Create(new[] { RedisResult.Create(count), RedisResult.Create(ttl) });

    private static RedisConnectionException Down() =>
        new(ConnectionFailureType.SocketFailure, "down");

    [Fact]
    public async Task UnderLimit_AcquiresLease()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 1, ttl: 60));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync(permitCount: 1);
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task AtLimit_StillAcquires()
    {
        // count == permitLimit is "the Nth permitted call", not the rejection boundary.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 5, ttl: 60));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync();
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task OverLimit_RejectsWithRetryAfterFromTtl()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 6, ttl: 42));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync();
        Assert.False(lease.IsAcquired);
        Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter.Name, out object? meta));
        Assert.Equal(TimeSpan.FromSeconds(42), Assert.IsType<TimeSpan>(meta));
    }

    [Fact]
    public async Task OverLimit_TtlMissing_FallsBackToWindowLength()
    {
        // If TTL is -1 / 0 (key persisted somehow), the retry-after defaults to a full window.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 7, ttl: 0));

        using var lease = await NewSut(permitLimit: 5, windowSeconds: 90).AcquireAsync();
        Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter.Name, out object? meta));
        Assert.Equal(TimeSpan.FromSeconds(90), Assert.IsType<TimeSpan>(meta));
    }

    [Fact]
    public async Task Acquire_RedisThrows_FailsOpen_AcquiresLease()
    {
        // Fail-open contract — a Redis outage must not deny legitimate traffic.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns<Task<RedisResult>>(_ => throw Down());

        using var lease = await NewSut().AcquireAsync();
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task Acquire_RedisThrows_FailOpen_LogsWarningAndCountsTheGrant()
    {
        // The grant itself is defensible; making it silently is not. Every fail-open grant must
        // leave a Warning naming the policy and a counter increment tagged decision=allowed —
        // that counter is the only signal that login rate limiting is currently switched off.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns<Task<RedisResult>>(_ => throw Down());

        var measurements = new List<(long Value, string? Policy, string? Decision, string? Cause)>();
        using (var listener = BackendUnavailableListener(measurements))
        {
            using var lease = await NewSut().AcquireAsync();
            Assert.True(lease.IsAcquired);
        }

        var (value, policy, decision, cause) = Assert.Single(measurements);
        Assert.Equal(1, value);
        Assert.Equal("login", policy);
        Assert.Equal("allowed", decision);
        Assert.Equal("connection", cause);

        string warning = Assert.Single(_logger.Warnings);
        Assert.Contains("login", warning, StringComparison.Ordinal);
        Assert.Contains("allowed", warning, StringComparison.Ordinal);
        Assert.Contains(nameof(RedisConnectionException), warning, StringComparison.Ordinal);
        Assert.Single(_logger.Exceptions);
    }

    [Fact]
    public async Task Acquire_RedisThrows_FailClosed_RejectsWithWindowRetryAfter()
    {
        // The operator switch: with the posture set to closed, an unreachable backend denies
        // rather than grants, and advertises the window length as Retry-After.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns<Task<RedisResult>>(_ => throw Down());

        var measurements = new List<(long Value, string? Policy, string? Decision, string? Cause)>();
        using (var listener = BackendUnavailableListener(measurements))
        {
            using var lease = await NewSut(windowSeconds: 90, failOpen: false).AcquireAsync();
            Assert.False(lease.IsAcquired);
            Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter.Name, out object? meta));
            Assert.Equal(TimeSpan.FromSeconds(90), Assert.IsType<TimeSpan>(meta));
        }

        var (value, policy, decision, cause) = Assert.Single(measurements);
        Assert.Equal(1, value);
        Assert.Equal("login", policy);
        Assert.Equal("denied", decision);
        Assert.Equal("connection", cause);

        string warning = Assert.Single(_logger.Warnings);
        Assert.Contains("login", warning, StringComparison.Ordinal);
        Assert.Contains("denied", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Acquire_MixedHealthyAndFailedCalls_CountsOnlyTheBackendFailures()
    {
        // Partial failure inside one limiter's lifetime: a healthy call, an outage, then a
        // recovered call. Only the outage may emit — a counter that also ticks on healthy
        // decisions is unalertable, and one that misses the outage is worse than none.
        var responses = new Queue<Func<RedisResult>>(new Func<RedisResult>[]
        {
            () => Pair(count: 1, ttl: 60),
            () => throw Down(),
            () => Pair(count: 2, ttl: 59),
        });
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns<Task<RedisResult>>(_ => Task.FromResult(responses.Dequeue()()));

        var measurements = new List<(long Value, string? Policy, string? Decision, string? Cause)>();
        var sut = NewSut();
        using (var listener = BackendUnavailableListener(measurements))
        {
            for (int i = 0; i < 3; i++)
            {
                using var lease = await sut.AcquireAsync();
                Assert.True(lease.IsAcquired);
            }
        }

        var (_, _, decision, _) = Assert.Single(measurements);
        Assert.Equal("allowed", decision);
        Assert.Single(_logger.Warnings);
    }

    [Fact]
    public async Task Acquire_ScriptReturnsNull_FailsOpenByPostureRatherThanThrowing()
    {
        // A null script reply (e.g. a stale/incompatible Lua script, or a mocked/misbehaving
        // server) casts to a null RedisResult[] rather than throwing at the cast site; the
        // NullReferenceException that follows on element access must be caught by the same guard
        // as a connection failure, not bubble out of the limiter as an unhandled exception.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns((RedisResult)null!);

        var measurements = new List<(long Value, string? Policy, string? Decision, string? Cause)>();
        using (var listener = BackendUnavailableListener(measurements))
        {
            using var lease = await NewSut().AcquireAsync();
            Assert.True(lease.IsAcquired); // fail-open posture, same as a connection failure
        }

        var (value, policy, decision, cause) = Assert.Single(measurements);
        Assert.Equal(1, value);
        Assert.Equal("login", policy);
        Assert.Equal("allowed", decision);
        Assert.Equal("malformed_reply", cause);

        string warning = Assert.Single(_logger.Warnings);
        Assert.Contains("login", warning, StringComparison.Ordinal);
        Assert.Contains("malformed_reply", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Acquire_ScriptReturnsWrongShapedReply_FailsClosedByPostureRatherThanThrowing()
    {
        // A reply that isn't the two-element {count, ttl} array the script always returns (here,
        // a bare integer) must take the configured posture — fail-closed in this case — rather
        // than the InvalidCastException surfacing as an unhandled exception / bare HTTP 500.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(RedisResult.Create(42L));

        var measurements = new List<(long Value, string? Policy, string? Decision, string? Cause)>();
        using (var listener = BackendUnavailableListener(measurements))
        {
            using var lease = await NewSut(windowSeconds: 90, failOpen: false).AcquireAsync();
            Assert.False(lease.IsAcquired);
            Assert.True(lease.TryGetMetadata(MetadataName.RetryAfter.Name, out object? meta));
            Assert.Equal(TimeSpan.FromSeconds(90), Assert.IsType<TimeSpan>(meta));
        }

        var (value, policy, decision, cause) = Assert.Single(measurements);
        Assert.Equal(1, value);
        Assert.Equal("login", policy);
        Assert.Equal("denied", decision);
        Assert.Equal("malformed_reply", cause);

        string warning = Assert.Single(_logger.Warnings);
        Assert.Contains(nameof(InvalidCastException), warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Acquire_ScriptReturnsShortArray_FailsOpenByPostureRatherThanThrowing()
    {
        // A one-element array (missing the ttl slot) throws IndexOutOfRangeException on access —
        // the third malformed-reply shape, distinct from null and from a non-array reply.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(RedisResult.Create(new[] { RedisResult.Create(5L) }));

        var measurements = new List<(long Value, string? Policy, string? Decision, string? Cause)>();
        using (var listener = BackendUnavailableListener(measurements))
        {
            using var lease = await NewSut().AcquireAsync();
            Assert.True(lease.IsAcquired);
        }

        var (_, _, _, cause) = Assert.Single(measurements);
        Assert.Equal("malformed_reply", cause);

        string warning = Assert.Single(_logger.Warnings);
        Assert.Contains(nameof(IndexOutOfRangeException), warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Acquire_ScriptReturnsNonNumericCount_FailsOpenByPostureRatherThanThrowing()
    {
        // The count slot is present but not integer-shaped (e.g. a script/client incompatibility
        // that returns a bulk string instead of an integer reply). StackExchange.Redis's (long)
        // conversion wraps the underlying format/range failure as InvalidCastException, which
        // this guard already catches — pinning that a non-numeric reply is diagnosed the same as
        // every other malformed shape rather than falling through to cause=connection.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(RedisResult.Create(new[]
            {
                RedisResult.Create((RedisValue)"not-a-number"),
                RedisResult.Create(60L),
            }));

        var measurements = new List<(long Value, string? Policy, string? Decision, string? Cause)>();
        using (var listener = BackendUnavailableListener(measurements))
        {
            using var lease = await NewSut().AcquireAsync();
            Assert.True(lease.IsAcquired);
        }

        var (_, _, decision, cause) = Assert.Single(measurements);
        Assert.Equal("allowed", decision);
        Assert.Equal("malformed_reply", cause);
    }

    [Fact]
    public async Task KeyIncludesScope_Bucket_AndWindowId()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(1, 60));

        await NewSut(windowSeconds: 60).AcquireAsync();

        await _db.Received(1).ScriptEvaluateAsync(
            Arg.Any<string>(),
            Arg.Is<RedisKey[]>(keys =>
                keys.Length == 1 &&
                keys[0].ToString().StartsWith("p:ratelimit:login:ip-1.2.3.4:", StringComparison.Ordinal)),
            Arg.Any<RedisValue[]>());
    }

    [Fact]
    public async Task SynchronousAttemptAcquire_DefersToAsync()
    {
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(1, 60));
        using var lease = NewSut().AttemptAcquire();   // covers the AttemptAcquireCore branch
        await Task.Yield();
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public void GetStatistics_ReturnsNull_UntilBacklogIsModeled()
    {
        Assert.Null(NewSut().GetStatistics());
    }

    [Fact]
    public async Task AcquireAsync_WithPermitCountGreaterThanOne_AcquiresLease()
    {
        // permitCount > 1 still routes through the same AcquireAsync() path — count stays under limit.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 3, ttl: 55));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync(permitCount: 3);
        Assert.True(lease.IsAcquired);
    }

    [Fact]
    public async Task SuccessLease_Dispose_DoesNotThrow()
    {
        // Exercises the SuccessLease.Dispose(bool) path — stateless, nothing to release.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 1, ttl: 60));

        var lease = await NewSut().AcquireAsync();
        Assert.True(lease.IsAcquired);
        var ex = Record.Exception(() => lease.Dispose());
        Assert.Null(ex);
    }

    [Fact]
    public async Task RejectedLease_TryGetMetadata_UnknownKey_ReturnsFalse()
    {
        // Drive the limiter over limit to obtain a RejectedLease, then probe an unknown key.
        _db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>())
            .Returns(Pair(count: 10, ttl: 30));

        using var lease = await NewSut(permitLimit: 5).AcquireAsync();
        Assert.False(lease.IsAcquired);
        bool found = lease.TryGetMetadata("unknown_key", out object? meta);
        Assert.False(found);
        Assert.Null(meta);
    }

    [Fact]
    public void Dispose_Limiter_DoesNotThrow()
    {
        // Exercises the protected Dispose(bool) override — no unmanaged resources to release.
        var sut = NewSut();
        var ex = Record.Exception(() => sut.Dispose());
        Assert.Null(ex);
    }

    // ── Harness ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Listens for <c>dependably.rate_limit.backend_unavailable</c> emissions and records each
    /// measurement together with its policy/decision/cause tags.
    /// </summary>
    private static MeterListener BackendUnavailableListener(
        List<(long Value, string? Policy, string? Decision, string? Cause)> sink)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName &&
                    instrument.Name == BackendUnavailableInstrument)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            string? policy = null;
            string? decision = null;
            string? cause = null;
            foreach (var tag in tags)
            {
                if (tag.Key == "policy")
                {
                    policy = tag.Value as string;
                }
                else if (tag.Key == "decision")
                {
                    decision = tag.Value as string;
                }
                else if (tag.Key == "cause")
                {
                    cause = tag.Value as string;
                }
            }

            sink.Add((measurement, policy, decision, cause));
        });
        listener.Start();
        return listener;
    }

    private sealed class CapturingLogger : ILogger<RedisFixedWindowRateLimiter>
    {
        public List<string> Warnings { get; } = [];

        public List<Exception> Exceptions { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel != LogLevel.Warning)
            {
                return;
            }

            Warnings.Add(formatter(state, exception));
            if (exception is not null)
            {
                Exceptions.Add(exception);
            }
        }
    }
}
