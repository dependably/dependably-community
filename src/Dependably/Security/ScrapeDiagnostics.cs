using System.Net;

namespace Dependably.Security;

/// <summary>
/// Lock-free ring buffer of recent <c>/metrics</c> scrape attempts, plus
/// process-lifetime allow/deny counts. Surfaced on the sysadmin
/// observability page so operators can see who's hitting the endpoint
/// and which requests are being rejected.
///
/// <para>Capacity is fixed at 500 entries; the writer wraps the index
/// modulo capacity. Memory cost is trivial (~30 KB).</para>
///
/// <para>Recorded values are non-PII: only the request timestamp,
/// remote IP (post-forwarded-headers rewrite), and outcome enum.</para>
/// </summary>
public sealed class ScrapeDiagnostics
{
    public const int Capacity = 500;

    public enum Outcome
    {
        Allowed,
        DeniedIp,
        DeniedDisabled,
    }

    public sealed record Entry(DateTimeOffset Timestamp, string? RemoteIp, Outcome Outcome);

    private readonly Entry?[] _buffer = new Entry?[Capacity];
    private long _writeIndex;

    private long _allowedTotal;
    private long _deniedIpTotal;
    private long _deniedDisabledTotal;

    public void Record(IPAddress? remoteIp, Outcome outcome)
    {
        var entry = new Entry(DateTimeOffset.UtcNow, remoteIp?.ToString(), outcome);
        var index = Interlocked.Increment(ref _writeIndex) - 1;
        _buffer[index % Capacity] = entry;

        switch (outcome)
        {
            case Outcome.Allowed: Interlocked.Increment(ref _allowedTotal); break;
            case Outcome.DeniedIp: Interlocked.Increment(ref _deniedIpTotal); break;
            case Outcome.DeniedDisabled: Interlocked.Increment(ref _deniedDisabledTotal); break;
        }
    }

    /// <summary>
    /// Returns up to <paramref name="n"/> most-recent entries, newest
    /// first. Defaults to 50, the size the sysadmin page displays.
    /// </summary>
    public IReadOnlyList<Entry> Recent(int n = 50)
    {
        var write = Interlocked.Read(ref _writeIndex);
        var count = (int)Math.Min(write, n);
        if (count == 0) return Array.Empty<Entry>();

        var start = write - count;
        var result = new List<Entry>(count);
        for (var i = start; i < write; i++)
        {
            var entry = _buffer[i % Capacity];
            if (entry is not null) result.Add(entry);
        }
        result.Reverse();
        return result;
    }

    /// <summary>
    /// Lifetime totals since process start. Honest about windowing —
    /// the sysadmin UI labels these "since startup".
    /// </summary>
    public (long Allowed, long DeniedIp, long DeniedDisabled) LifetimeCounts() => (
        Interlocked.Read(ref _allowedTotal),
        Interlocked.Read(ref _deniedIpTotal),
        Interlocked.Read(ref _deniedDisabledTotal));
}
