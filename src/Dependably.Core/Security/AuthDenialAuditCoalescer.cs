using System.Collections.Concurrent;

namespace Dependably.Security;

/// <summary>
/// Coalesces audit writes for repeated authorization denials so a client looping against a gate
/// records the fact once rather than once per request.
///
/// <para>
/// Protocol clients retry structurally, not exceptionally: a single <c>docker push</c> of a
/// multi-layer image issues three write requests per layer and runs several layers concurrently,
/// so one wrong credential produces dozens of identical denials in under a second. Auditing each
/// of them buries the one fact an operator needs — that this credential was refused, and what it
/// carried — under write amplification, and does it in a table a tenant can therefore grow at the
/// rate its rate-limit ceiling allows.
/// </para>
///
/// <para>
/// Same shape as the metrics-scrape denial coalescer: a per-key cooldown, a hard cap on tracked
/// keys, and whole-map eviction at the cap. Eviction is deliberately not LRU — the map exists to
/// suppress a burst, and dropping it wholesale costs at most one extra audit row per live key
/// while keeping the bound unconditional. State is process-local and in-memory: a duplicate row
/// from a second replica is a far cheaper failure than a lock, and none of this is a security
/// control — the 403 is sent regardless of what this returns.
/// </para>
/// </summary>
public sealed class AuthDenialAuditCoalescer
{
    private const int KeyCap = 1024;

    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastAudited = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    public AuthDenialAuditCoalescer(TimeProvider time) => _time = time;

    /// <summary>
    /// True when this denial should be written to the audit log — i.e. the first occurrence of
    /// <paramref name="orgId"/>/<paramref name="actorId"/>/<paramref name="route"/> in the
    /// current cooldown window.
    /// </summary>
    public bool ShouldAudit(string orgId, string actorId, string route)
    {
        var now = _time.GetUtcNow();
        string key = $"{orgId}\x1f{actorId}\x1f{route}";

        if (_lastAudited.TryGetValue(key, out var last) && now - last < Cooldown)
        {
            return false;
        }

        if (_lastAudited.Count >= KeyCap)
        {
            _lastAudited.Clear();
        }

        _lastAudited[key] = now;
        return true;
    }
}
