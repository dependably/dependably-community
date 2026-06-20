using System.Collections.Concurrent;
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
///
/// <para>Audit coalescing: <see cref="ShouldAudit"/> suppresses duplicate
/// audit writes for the same (scope, orgId, ip, endpoint) tuple within a
/// 10-minute window, capped at 1024 tracked keys, to prevent write-amplification
/// from high-frequency unauthenticated requests.</para>
/// </summary>
public sealed class ScrapeDiagnostics
{
    public const int Capacity = 500;

    /// <summary>Maximum cooldown map entries before the oldest is evicted.</summary>
    private const int AuditMapCap = 1024;

    private static readonly TimeSpan AuditCooldown = TimeSpan.FromMinutes(10);

    public enum Outcome
    {
        Allowed,
        DeniedIp,
        DeniedDisabled,
    }

    public sealed record Entry(DateTimeOffset Timestamp, string? RemoteIp, Outcome Outcome);

    /// <summary>Shape returned by <see cref="RecentDeniedIps"/>.</summary>
    public sealed record DeniedIpEntry(string Ip, DateTimeOffset LastSeen);

    private readonly Entry?[] _buffer = new Entry?[Capacity];
    private long _writeIndex;

    private long _allowedTotal;
    private long _deniedIpTotal;
    private long _deniedDisabledTotal;

    private readonly TimeProvider _time;

    // Cooldown map for audit coalescing: key → last-audited timestamp.
    // ConcurrentDictionary for thread safety; eviction is best-effort (trimmed when cap is exceeded).
    private readonly ConcurrentDictionary<string, DateTimeOffset> _auditMap = new(StringComparer.Ordinal);

    public ScrapeDiagnostics(TimeProvider time)
    {
        _time = time;
    }

    public void Record(IPAddress? remoteIp, Outcome outcome)
    {
        var entry = new Entry(_time.GetUtcNow(), IpAddressExtensions.Normalize(remoteIp), outcome);
        long index = Interlocked.Increment(ref _writeIndex) - 1;
        _buffer[index % Capacity] = entry;

        switch (outcome)
        {
            case Outcome.Allowed: Interlocked.Increment(ref _allowedTotal); break;
            case Outcome.DeniedIp: Interlocked.Increment(ref _deniedIpTotal); break;
            case Outcome.DeniedDisabled: Interlocked.Increment(ref _deniedDisabledTotal); break;
        }
    }

    /// <summary>
    /// Returns true (and records the timestamp) if this (scope, orgId, ip, endpoint)
    /// combination has not been audited within the 10-minute cooldown window. Returns
    /// false if the cooldown has not elapsed — the caller should suppress the audit write.
    ///
    /// <para>The map is capped at 1024 entries; when the cap is reached the entire map
    /// is cleared before adding the new key, which resets all cooldowns. This is
    /// intentionally conservative — a cleared map means the next denial from each IP
    /// writes exactly one audit row, which is the safe direction.</para>
    /// </summary>
    public bool ShouldAudit(string scope, string? orgId, string ip, string endpoint)
    {
        var now = _time.GetUtcNow();
        string key = $"{scope}\x1f{orgId ?? ""}\x1f{ip}\x1f{endpoint}";

        if (_auditMap.TryGetValue(key, out var last) && now - last < AuditCooldown)
        {
            return false;
        }

        // Evict entire map when cap is reached to bound memory.
        if (_auditMap.Count >= AuditMapCap)
        {
            _auditMap.Clear();
        }

        _auditMap[key] = now;
        return true;
    }

    /// <summary>
    /// Returns up to <paramref name="n"/> most-recent entries, newest
    /// first. Defaults to 50, the size the sysadmin page displays.
    /// </summary>
    public IReadOnlyList<Entry> Recent(int n = 50)
    {
        long write = Interlocked.Read(ref _writeIndex);
        int count = (int)Math.Min(write, n);
        if (count == 0)
        {
            return Array.Empty<Entry>();
        }

        long start = write - count;
        var result = new List<Entry>(count);
        for (long i = start; i < write; i++)
        {
            var entry = _buffer[i % Capacity];
            if (entry is not null)
            {
                result.Add(entry);
            }
        }
        result.Reverse();
        return result;
    }

    /// <summary>
    /// Returns up to <paramref name="max"/> distinct IPs that were denied by IP
    /// (outcome <see cref="Outcome.DeniedIp"/>), deduped, newest-first, from the
    /// ring buffer. Intended for the allowlist editor so the operator can see
    /// which source IPs are being rejected and add them with one click.
    /// </summary>
    public IReadOnlyList<DeniedIpEntry> RecentDeniedIps(int max = 10)
    {
        long write = Interlocked.Read(ref _writeIndex);
        int scan = (int)Math.Min(write, Capacity);
        if (scan == 0)
        {
            return Array.Empty<DeniedIpEntry>();
        }

        // Collect newest-first from the ring buffer. The HashSet tracks which IPs have already
        // appeared; the List accumulates results in the order they are encountered (newest-first),
        // making the output order deterministic regardless of platform map internals.
        var seenIps = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<DeniedIpEntry>(max);
        for (long i = write - 1; i >= write - scan; i--)
        {
            var entry = _buffer[i % Capacity];
            if (entry is null || entry.Outcome != Outcome.DeniedIp || entry.RemoteIp is null)
            {
                continue;
            }

            if (seenIps.Add(entry.RemoteIp))
            {
                result.Add(new DeniedIpEntry(entry.RemoteIp, entry.Timestamp));
                if (result.Count >= max)
                {
                    break;
                }
            }
        }

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
