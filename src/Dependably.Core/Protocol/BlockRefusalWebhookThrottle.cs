using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;

namespace Dependably.Protocol;

/// <summary>
/// Per-process burst throttle in front of the <c>package.blocked</c> webhook dispatch, keyed on
/// (org, purl, arm). A blocked artefact hammered by a CI retry loop refuses the same coordinate
/// dozens of times a minute; <see cref="BlockGateService"/> still writes the full audit/activity/
/// quarantine trail for every one of those refusals — this throttle sits only in front of the
/// webhook dispatch call, so only the first refusal inside the coalescing window reaches
/// subscribers rather than flooding the org's dispatch queue lane with one envelope per request.
/// A transient failure resolving the org or dispatching the envelope (see
/// <c>BlockGateService.EmitBlockWebhookEventAsync</c>) still burns the window — the throttle only
/// tracks that a dispatch was <em>attempted</em> for the coordinate, not that it was delivered —
/// so a coordinate whose org lookup fails once goes quiet for the rest of that window; this is a
/// deliberate best-effort trade, the same one the dispatch call itself makes.
///
/// <para>
/// <b>State is process-local and in-memory, deliberately not persisted</b> — the same posture
/// <c>EmailTransportBreaker</c> documents for the shared SMTP transport's health. A file-backed
/// SQLite deployment already runs exactly one live process (<c>InstanceLock</c> refuses a second
/// writer on the same database), so a process-local throttle there is instance-wide by
/// construction. A Postgres deployment can run multiple replicas, each holding its own view of
/// recent refusals — a bounded, self-correcting trade: at worst each replica independently lets
/// through its own first-refusal-per-window for a coordinate, which multiplies the dispatched
/// event count by at most the replica count, never by the request volume a CI retry loop
/// generates.
/// </para>
///
/// <para>
/// <b>Bounded key space.</b> The key space grows with the number of distinct (org, purl, arm)
/// coordinates blocked, not with request volume — but unlike the quarantine review table (whose
/// distinct-purl set stops growing once a coordinate is fixed or allowlisted), several arms mint
/// a fresh coordinate that never repeats: the release-age arm keys on every newly published
/// upstream version, and the licence and unbacked-provenance-enforcement postures key on every
/// distinct artefact denied under a blanket policy. Left unbounded, that is an eventual memory
/// leak. Same shape as <c>AuthDenialAuditCoalescer</c> / the metrics-scrape denial coalescer: a
/// hard cap on tracked keys (<see cref="KeyCap"/>) and whole-map eviction at the cap, checked
/// before the write. The check-then-write is not itself atomic with the write, so the map can
/// transiently exceed <see cref="KeyCap"/> by at most the number of threads racing between the
/// count check and the write — bounded by request concurrency, not by request volume, which is
/// the property this cap exists to hold. Eviction is deliberately not LRU — the map exists to
/// suppress a burst, not to remember history, so dropping it wholesale costs at most one extra
/// dispatch per live coordinate (a coordinate cleared mid-window re-dispatches on its very next
/// refusal, exactly as if it were seeing that coordinate for the first time) while keeping the
/// bound unconditional rather than dependent on tracking recency. None of this is a security
/// control — the block itself (and its audit/activity/quarantine rows) happens regardless of
/// what this returns.
/// </para>
///
/// <para>
/// <b>Single dispatch under concurrency.</b> Two refusals for the same coordinate arriving at
/// once — parallel <c>npm ci</c>/<c>docker pull</c> retries hitting the same blocked artefact
/// from different connections — race on the same map entry. The window check and the write below
/// are a compare-and-swap loop (<see cref="ConcurrentDictionary{TKey,TValue}.TryAdd"/> /
/// <see cref="ConcurrentDictionary{TKey,TValue}.TryUpdate"/>), not a bare check-then-write: the
/// loser of the race re-reads the entry the winner just wrote and returns <see langword="false"/>
/// against it, so at most one of any number of concurrent refusals for the same coordinate ever
/// dispatches — the "one dispatch per window" guarantee holds under concurrency, not just when
/// called from a single thread.
/// </para>
/// </summary>
public sealed class BlockRefusalWebhookThrottle
{
    /// <summary>Default coalescing window (<c>BLOCK_WEBHOOK_THROTTLE_WINDOW_MINUTES</c>).</summary>
    internal const int DefaultWindowMinutes = 15;

    /// <summary>
    /// Hard cap on tracked (org, purl, arm) coordinates before the whole map is cleared. Same
    /// value as <c>AuthDenialAuditCoalescer.KeyCap</c> — both exist to bound a per-process
    /// coalescing map against an unbounded key space, not to size a production workload.
    /// </summary>
    internal const int KeyCap = 1024;

    private readonly TimeProvider _time;
    private readonly TimeSpan _window;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastDispatchedAt = new(StringComparer.Ordinal);

    /// <summary>Test seam: the live tracked-coordinate count, so a cap test can assert on the
    /// map's actual size rather than only on ShouldDispatch's return values (which cannot, by
    /// themselves, distinguish a bounded map from an unbounded one).</summary>
    internal int TrackedCoordinateCount => _lastDispatchedAt.Count;

    public BlockRefusalWebhookThrottle(TimeProvider time, IConfiguration config)
    {
        _time = time;
        int minutes = int.TryParse(config["BLOCK_WEBHOOK_THROTTLE_WINDOW_MINUTES"], out int m) && m > 0
            ? m
            : DefaultWindowMinutes;
        _window = TimeSpan.FromMinutes(minutes);
    }

    /// <summary>
    /// Test seam: builds a throttle with an explicit window rather than reading configuration.
    /// </summary>
    internal BlockRefusalWebhookThrottle(TimeProvider time, TimeSpan window)
    {
        _time = time;
        _window = window;
    }

    /// <summary>
    /// True when a refusal for the given (org, purl, arm) coordinate should dispatch a webhook
    /// event now — either the first refusal ever observed for that coordinate, or the first
    /// refusal since the previous dispatch aged out of the window (or since the map was last
    /// cleared at <see cref="KeyCap"/> — see the class doc). A <see langword="true"/> result
    /// stamps the coordinate's last-dispatch time, so the window resets from the most recent
    /// dispatch rather than the first — a coordinate that refuses steadily every few minutes for
    /// hours dispatches once per window throughout, not once total.
    /// </summary>
    public bool ShouldDispatch(string orgId, string purl, string arm)
    {
        string key = string.Join('\x1f', orgId, purl, arm);
        var now = _time.GetUtcNow();

        while (true)
        {
            if (_lastDispatchedAt.TryGetValue(key, out var last))
            {
                if (now - last < _window)
                {
                    return false;
                }

                if (_lastDispatchedAt.TryUpdate(key, now, last))
                {
                    return true;
                }

                // Lost a race with a concurrent refusal on the same coordinate — the winner
                // already stamped a newer value; re-read and evaluate against that instead.
                continue;
            }

            if (_lastDispatchedAt.Count >= KeyCap)
            {
                _lastDispatchedAt.Clear();
            }

            if (_lastDispatchedAt.TryAdd(key, now))
            {
                return true;
            }

            // Lost a race with a concurrent first-refusal on the same coordinate — retry, which
            // now finds the winner's entry via TryGetValue above.
        }
    }
}
