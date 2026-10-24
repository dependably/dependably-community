using System.Data.Common;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Hands out each connection wrapped in a <see cref="CountingConnection"/>, and disposes the real
/// connection the wrapper does not own.
/// </summary>
internal sealed class CountingStore(IMetadataStore inner) : IMetadataStore, IAsyncDisposable
{
    private readonly List<DbConnection> _inner = [];
    private readonly List<CountingConnection> _connections = [];

    public DbProvider Provider => inner.Provider;

    public IReadOnlyList<CountingConnection> Connections => _connections;

    public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        var connection = await inner.OpenAsync(ct);
        _inner.Add(connection);
        var counting = new CountingConnection(connection);
        _connections.Add(counting);
        return counting;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var connection in _inner)
        {
            await connection.DisposeAsync();
        }
    }
}

/// <summary>The system clock, counting the waits the code under test starts on it.</summary>
internal sealed class PauseCountingTimeProvider : TimeProvider
{
    private int _pauses;

    public int Pauses => Volatile.Read(ref _pauses);

    public override DateTimeOffset GetUtcNow() => System.GetUtcNow();
    public override long GetTimestamp() => System.GetTimestamp();
    public override long TimestampFrequency => System.TimestampFrequency;
    public override TimeZoneInfo LocalTimeZone => System.LocalTimeZone;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        Interlocked.Increment(ref _pauses);
        return System.CreateTimer(callback, state, dueTime, period);
    }
}
