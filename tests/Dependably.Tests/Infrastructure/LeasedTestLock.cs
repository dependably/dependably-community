using Dependably.Infrastructure.Redis;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Outcome the next <see cref="ILockHandle.ExtendAsync"/> call should produce.
/// </summary>
public enum ExtendOutcome
{
    /// <summary>The lease is extended (the holder still owns the key).</summary>
    Renew,

    /// <summary>The backend answers "you no longer hold this lock" — the definitive lost signal.</summary>
    Refuse,

    /// <summary>The backend is unreachable — a connection blip, not a lease decision.</summary>
    Throw,
}

/// <summary>
/// An <see cref="IDistributedLock"/> that models real Redis lease semantics on an injected clock:
/// a key holds an owner token and an expiry instant, a second acquirer is refused only while the
/// key is unexpired, and an extend succeeds only for the current owner of an unexpired key.
///
/// <para><see cref="InProcessDistributedLock"/> is deliberately not used for lease assertions —
/// it grants the first acquirer unconditionally within a process, so a test built on it can pass
/// without any lease ever being renewed. This fake makes expiry the thing under test, and counts
/// renewal attempts so a test can wait for the heartbeat instead of guessing at timing.</para>
/// </summary>
public sealed class LeasedTestLock : IDistributedLock
{
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _keys = new(StringComparer.Ordinal);
    private int _extendAttempts;
    private int _extendSuccesses;

    public LeasedTestLock(TimeProvider time) => _time = time;

    /// <summary>Outcome selector, keyed by 1-based extend-attempt number. Renews by default.</summary>
    public Func<int, ExtendOutcome> ExtendBehavior { get; set; } = _ => ExtendOutcome.Renew;

    /// <summary>Total <see cref="ILockHandle.ExtendAsync"/> calls, including refused and throwing ones.</summary>
    public int ExtendAttempts => Volatile.Read(ref _extendAttempts);

    /// <summary>Extend calls that actually pushed the expiry out.</summary>
    public int ExtendSuccesses => Volatile.Read(ref _extendSuccesses);

    /// <summary>True while <paramref name="name"/> is held by an unexpired owner.</summary>
    public bool IsHeld(string name)
    {
        lock (_gate)
        {
            return _keys.TryGetValue(name, out var entry) && entry.ExpiresAt > _time.GetUtcNow();
        }
    }

    public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_keys.TryGetValue(name, out var held) && held.ExpiresAt > _time.GetUtcNow())
            {
                return Task.FromResult<ILockHandle?>(null);
            }

            string token = Guid.NewGuid().ToString("N");
            _keys[name] = new Entry(token, _time.GetUtcNow() + ttl);
            return Task.FromResult<ILockHandle?>(new Handle(this, name, token, _time.GetUtcNow()));
        }
    }

    public async Task<ILockHandle> AcquireAsync(
        string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
        await TryAcquireAsync(name, ttl, ct)
            ?? throw new TimeoutException($"Could not acquire test lock '{name}' within {wait}.");

    private bool Extend(string name, string token, TimeSpan additional)
    {
        int attempt = Interlocked.Increment(ref _extendAttempts);
        var outcome = ExtendBehavior(attempt);
        if (outcome == ExtendOutcome.Throw)
        {
            throw new InvalidOperationException("simulated lock-backend failure (e.g. Redis connection blip)");
        }

        lock (_gate)
        {
            if (outcome == ExtendOutcome.Refuse
                || !_keys.TryGetValue(name, out var held)
                || !string.Equals(held.Token, token, StringComparison.Ordinal)
                || held.ExpiresAt <= _time.GetUtcNow())
            {
                return false;
            }

            _keys[name] = held with { ExpiresAt = _time.GetUtcNow() + additional };
        }

        Interlocked.Increment(ref _extendSuccesses);
        return true;
    }

    private void Release(string name, string token)
    {
        lock (_gate)
        {
            // Compare-and-delete: a lapsed holder must not evict the instance that took over.
            if (_keys.TryGetValue(name, out var held)
                && string.Equals(held.Token, token, StringComparison.Ordinal))
            {
                _keys.Remove(name);
            }
        }
    }

    private sealed record Entry(string Token, DateTimeOffset ExpiresAt);

    private sealed class Handle : ILockHandle
    {
        private readonly LeasedTestLock _owner;
        private readonly string _token;
        private bool _released;

        public string Name { get; }
        public DateTimeOffset AcquiredAt { get; }

        public Handle(LeasedTestLock owner, string name, string token, DateTimeOffset acquiredAt)
        {
            _owner = owner;
            Name = name;
            _token = token;
            AcquiredAt = acquiredAt;
        }

        public Task<bool> ExtendAsync(TimeSpan additional, CancellationToken ct = default) =>
            _released ? Task.FromResult(false) : Task.FromResult(_owner.Extend(Name, _token, additional));

        public ValueTask DisposeAsync()
        {
            if (!_released)
            {
                _released = true;
                _owner.Release(Name, _token);
            }

            return ValueTask.CompletedTask;
        }
    }
}
