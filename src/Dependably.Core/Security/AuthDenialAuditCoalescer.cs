using System.Collections.Concurrent;
using Dependably.Infrastructure.Audit;

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
/// <b>Two modes, deliberately different.</b> <see cref="ShouldAudit"/> is a suppress-only
/// throttle: it answers "write this row or not", and the caller writes its own fully detailed row
/// on the first denial of each cooldown window. <see cref="Record"/> is a counting accumulator:
/// the caller writes nothing, the denial is folded into a per-window tally, and
/// <c>AuthDenialAuditFlushService</c> writes one row per key per window carrying the
/// <c>count</c>. The second mode exists for the seams an unauthenticated caller can trigger at
/// will (a rejected credential, a rate-limit 429), where suppression alone would destroy the
/// signal — repetition <em>is</em> the signal there, so the count has to survive the coalescing.
/// </para>
///
/// <para>
/// <b>Why the two caps behave differently.</b> Both modes bound their key space, but they are
/// allowed to reach the bound differently. The suppress map (<see cref="KeyCap"/>) is dropped
/// wholesale at the cap: it exists to suppress a burst, not to remember history, so dropping it
/// costs at most one extra audit row per live key. The counting maps must never do that. Their
/// key space carries an attacker-controlled dimension (the partition — an IP, and an IPv6
/// <c>/64</c> is free to mint), so clearing at the cap would let an attacker spray keys to the
/// bound and zero every count in the map at exactly the moment repetition is worth recording.
/// Flush-on-evict is not the alternative either: that hands the same attacker the audit write
/// rate back, which is what the coalescing exists to take away. At the cap new keys are folded
/// into a coarser bucket that is still counted — see <see cref="Record"/>.
/// </para>
///
/// <para>
/// State is process-local and in-memory, and this is not a security control — the 401/403/429 is
/// sent regardless of what this returns or accumulates. Per-replica accumulation is the only
/// option inside the Core closure: the distributed primitive available here is a lock, not a
/// counter, and the edge composition root can never reach a shared cache at all. A multi-replica
/// deployment therefore emits one row per replica per window, and the true count for a key is the
/// SUM of the rows sharing <c>(org, partition, reason, window_start)</c> — the same posture
/// <c>BlockRefusalWebhookThrottle</c> documents for its own process-local map.
/// </para>
///
/// <para>
/// <b>That SUM is only computable because the window is wall-clock aligned.</b> A tally is bucketed
/// by <see cref="FloorToWindow"/> of the instant it was <em>recorded</em> — not by when this
/// instance happened to start or when its flush timer happened to fire. Derived from either of
/// those, <c>window_start</c> would be per-process: two replicas started eleven seconds apart
/// would label the same denial with two different windows, the documented grouping would join
/// nothing, and a collector following it would read one replica's share of the traffic as the
/// whole. Bucketing on the event instant makes the label a pure function of when the denial
/// happened, so every replica independently produces the same one. Two consequences follow and
/// are intended: a drain can return tallies from more than one window (a burst spanning a minute
/// boundary is two buckets, each correctly labelled), and a flush period shorter than the
/// alignment yields several rows per window — which the SUM already handles, since it is the same
/// shape multiple replicas produce.
/// </para>
/// </summary>
public sealed class AuthDenialAuditCoalescer
{
    /// <summary>
    /// Hard bound on keys tracked by the suppress-only <see cref="ShouldAudit"/> map.
    /// </summary>
    internal const int KeyCap = 1024;

    /// <summary>
    /// Hard bound on exactly-keyed counting entries held for the current window. Past it, a key
    /// not already tracked folds into the overflow bucket rather than displacing anything.
    /// </summary>
    internal const int CountKeyCap = 1024;

    /// <summary>
    /// Hard bound on overflow buckets. The overflow key drops the two dimensions a caller does
    /// not control — partition, route and the granted set — leaving
    /// <c>(action, org, ecosystem, policy, reason, required)</c>,
    /// which is drawn from the tenant list and from compile-time vocabularies, so this bound is
    /// reached only by a deployment with a very large tenant count, never by request volume. Past
    /// it, counts fold once more into the saturation bucket, which is keyed on the action alone.
    /// </summary>
    internal const int OverflowKeyCap = 256;

    /// <summary>
    /// Partition and route value on a folded bucket. A reader can tell a folded row from an
    /// exactly-keyed one by this value alone, which matters because the folded row's count is
    /// real while its partition attribution is not.
    /// </summary>
    public const string OverflowPartition = "overflow";

    /// <summary>Reason recorded on a saturation-bucket row.</summary>
    public const string OverflowReason = "overflow";

    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Wall-clock grid the accumulation windows are aligned to. Every tally is bucketed into
    /// <c>[floor(t), floor(t) + WindowAlignment)</c> for the instant <c>t</c> it was recorded, so
    /// the bucket is a property of the event rather than of the process observing it — which is
    /// what lets a reader add one key's rows across replicas. One minute is also the flush
    /// service's default period (<c>AuthDenialAuditFlushService.DefaultWindow</c>), so in the
    /// default configuration one window closes to exactly one row per key per replica.
    /// </summary>
    public static readonly TimeSpan WindowAlignment = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastAudited = new(StringComparer.Ordinal);

    // One lock over all three counting maps rather than a concurrent dictionary. The count is the
    // product here, so a drain that races an increment must not be able to lose one: the lock
    // makes "every recorded denial appears in exactly one flushed window" hold by construction
    // instead of by argument. The critical section is a dictionary lookup and an integer add on a
    // path that is already behind a rate limiter.
    private readonly Lock _countGate = new();
    private readonly Dictionary<BucketedKey, Tally> _counts = [];
    private readonly Dictionary<BucketedKey, Tally> _overflow = [];
    private readonly Dictionary<BucketedKey, Tally> _saturated = [];

    private readonly TimeProvider _time;

    public AuthDenialAuditCoalescer(TimeProvider time) => _time = time;

    /// <summary>
    /// Start of the <see cref="WindowAlignment"/>-sized wall-clock window containing
    /// <paramref name="instant"/>. Truncating toward the Unix epoch rather than toward zero so the
    /// grid is the same on both sides of it — every deployment's clock is well past 1970, but a
    /// test's frozen clock need not be, and a boundary that flips sign at the epoch is a bug that
    /// only ever shows up in one.
    /// </summary>
    public static DateTimeOffset FloorToWindow(DateTimeOffset instant)
    {
        long ticks = instant.UtcDateTime.Ticks;
        long alignment = WindowAlignment.Ticks;
        return new DateTimeOffset(ticks - (ticks % alignment), TimeSpan.Zero);
    }

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

    /// <summary>
    /// Folds one denial into the current window's tally for <paramref name="key"/>. Writes
    /// nothing — <c>AuthDenialAuditFlushService</c> turns the window into audit rows when it
    /// closes.
    ///
    /// <para>
    /// <paramref name="sourceIp"/> is the full remote address (never the rate-limit partition
    /// form) of the <em>first</em> denial folded into a key in this window; later denials on the
    /// same key do not overwrite it, so the flushed row names an address that genuinely produced
    /// a denial rather than whichever one happened to arrive last.
    /// </para>
    ///
    /// <para>
    /// Three tiers, none of which discards a count. An already-tracked key increments. A new key
    /// is tracked while the map is under <see cref="CountKeyCap"/>. Past that it folds into the
    /// overflow bucket for its <c>(action, org, ecosystem, policy, reason, required)</c> — still counted,
    /// with partition and route reading <see cref="OverflowPartition"/> so nobody mistakes the
    /// bucket for a real partition. Past <see cref="OverflowKeyCap"/> buckets it folds once more
    /// into a saturation bucket keyed on the action alone, which carries no org and so flushes as
    /// a system-scope row. Resolution degrades under a key spray; the total does not.
    /// </para>
    /// </summary>
    public void Record(AuthDenialKey key, string? sourceIp = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        // An undeclared action name is one the SIEM action catalogue never lists, so no collector
        // can subscribe to it and none can discover it is missing. Every call site passes a
        // compile-time constant, so failing loudly here surfaces the mistake in the wiring
        // change's own tests rather than as an event family nobody knows to ask for.
        if (!AuditActions.IsDeclared(key.Action))
        {
            throw new ArgumentException(
                $"Audit action '{key.Action}' is not in the declared vocabulary (AuditActions.All), " +
                "so it cannot be discovered or subscribed to on the SIEM feed.",
                nameof(key));
        }

        // The bucket is a function of when the denial happened, never of when this process started
        // or when its flush timer fires — that is what makes one key's rows addable across
        // replicas, and it is why the drain does not choose the label.
        var bucket = FloorToWindow(_time.GetUtcNow());

        lock (_countGate)
        {
            if (TryIncrement(_counts, new BucketedKey(bucket, key)))
            {
                return;
            }

            if (_counts.Count < CountKeyCap)
            {
                _counts[new BucketedKey(bucket, key)] = NewTally(sourceIp);
                return;
            }

            var overflowKey = key with
            {
                Partition = OverflowPartition,
                Route = OverflowPartition,
                // The granted set rides with the token the partition names. Once the partition is
                // folded away the set no longer describes a single credential, and keeping it
                // would multiply the overflow buckets by the number of distinct capability sets
                // in flight — the one dimension of a bucket whose whole job is to stay bounded.
                Granted = null,
            };

            if (TryIncrement(_overflow, new BucketedKey(bucket, overflowKey)))
            {
                return;
            }

            if (_overflow.Count < OverflowKeyCap)
            {
                _overflow[new BucketedKey(bucket, overflowKey)] = NewTally(sourceIp);
                return;
            }

            var saturationKey = new AuthDenialKey
            {
                Action = key.Action,
                Partition = OverflowPartition,
                Reason = OverflowReason,
                Route = OverflowPartition,
            };

            if (!TryIncrement(_saturated, new BucketedKey(bucket, saturationKey)))
            {
                _saturated[new BucketedKey(bucket, saturationKey)] = NewTally(sourceIp);
            }
        }
    }

    /// <summary>
    /// Hands every tally accumulated so far to the caller, which owns writing them. The maps are
    /// emptied here, but nothing is discarded — the counts leave in the returned window, which is
    /// what separates this from the suppress map's whole-map drop.
    ///
    /// <para>
    /// Each tally carries its own wall-clock window, so a drain that spans a minute boundary
    /// returns two correctly-labelled buckets rather than one averaged over both. The returned
    /// <c>DrainedAt</c> is the drain instant itself and labels nothing — it exists for the
    /// flush-path log line, because the window a row belongs to is the row's own.
    /// </para>
    /// </summary>
    public AuthDenialWindow DrainWindow()
    {
        var now = _time.GetUtcNow();

        lock (_countGate)
        {
            var entries = new List<AuthDenialTally>(_counts.Count + _overflow.Count + _saturated.Count);
            Collect(_counts, entries);
            Collect(_overflow, entries);
            Collect(_saturated, entries);

            _counts.Clear();
            _overflow.Clear();
            _saturated.Clear();

            return new AuthDenialWindow(DrainedAt: now, Entries: entries);
        }
    }

    /// <summary>Tallies pending in the open window. Diagnostics and tests only.</summary>
    internal int PendingKeyCount
    {
        get
        {
            lock (_countGate)
            {
                return _counts.Count + _overflow.Count + _saturated.Count;
            }
        }
    }

    /// <summary>
    /// Increments an already-tracked tally and reports whether it found one. Never adds — the
    /// caller decides that against its tier's cap, which is what keeps "increment an existing
    /// key" free of the cap check and "add a new key" subject to it.
    /// </summary>
    private static bool TryIncrement(Dictionary<BucketedKey, Tally> map, BucketedKey key)
    {
        if (!map.TryGetValue(key, out var tally))
        {
            return false;
        }

        tally.Count++;
        return true;
    }

    private static Tally NewTally(string? sourceIp) => new() { Count = 1, SourceIp = sourceIp };

    private static void Collect(Dictionary<BucketedKey, Tally> map, List<AuthDenialTally> into)
    {
        foreach (var (bucketed, tally) in map)
        {
            into.Add(new AuthDenialTally(
                bucketed.Key,
                tally.Count,
                tally.SourceIp,
                bucketed.WindowStart,
                bucketed.WindowStart + WindowAlignment));
        }
    }

    private sealed class Tally
    {
        public long Count { get; set; }
        public string? SourceIp { get; init; }
    }

    /// <summary>
    /// A coalescing key within one wall-clock window. The window is part of the map key rather
    /// than a field on the tally so a key still live across a boundary starts a fresh count in the
    /// new window instead of carrying the previous one's total into it.
    /// </summary>
    private readonly record struct BucketedKey(DateTimeOffset WindowStart, AuthDenialKey Key);
}

/// <summary>
/// Coalescing key for a counted denial. Every property is set by name — <c>required</c> init
/// properties rather than a positional record, because five of the six are strings and a
/// positional form would let two of them swap at a call site without a compile error.
///
/// <para>
/// <b>The org is part of the key, not part of the payload.</b> Under
/// <c>DEPLOYMENT_MODE=multi</c> one <c>/64</c> reaches two tenants inside a single window; with
/// the org outside the key the flushed row is attributed to whichever tenant happened to arrive
/// first, and every tenant-scoped audit write needs an org regardless. A denial with no
/// resolvable tenant (an apex or system-scope request) leaves <see cref="OrgId"/> null and
/// flushes as a system-scope row.
/// </para>
///
/// <para>
/// <b><see cref="Route"/> is the endpoint route template, never the request path.</b> A raw path
/// embeds a package name — tenant data inside an attacker-controlled audit write — and gives the
/// key one value per package, which is precisely the explosion the cap exists to survive.
/// </para>
/// </summary>
public sealed record AuthDenialKey
{
    /// <summary>Dotted audit action, e.g. the credential-rejection or rate-limit family.</summary>
    public required string Action { get; init; }

    /// <summary>Resolved tenant id, or null for an apex/system-scope denial.</summary>
    public string? OrgId { get; init; }

    /// <summary>
    /// The actor dimension the denial is grouped by: a rate-limit partition key, a token id
    /// prefix, or an IP. Attacker-controlled, which is why the cap exists.
    /// </summary>
    public required string Partition { get; init; }

    /// <summary>
    /// Ecosystem the denial happened on, or null where the plane has none. Written to the audit
    /// row's <c>ecosystem</c> column, which outlives the detail payload — the personal-data sweep
    /// nulls <c>detail</c> and <c>source_ip</c> at the configured horizon, so anything only in the
    /// payload stops being readable there.
    /// </summary>
    public string? Ecosystem { get; init; }

    /// <summary>
    /// Limiter or gate policy the denial came from, where the plane has one. Kept distinct from
    /// <see cref="Ecosystem"/> so a policy name is never written into the ecosystem column; it
    /// still discriminates the key, so two policies never fold into one row.
    /// </summary>
    public string? Policy { get; init; }

    /// <summary>Why the request was denied, from the emitting seam's closed vocabulary.</summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Capability the endpoint demanded, on a capability denial; null on every other family. It
    /// discriminates the key because two different gates on one route are two different facts —
    /// and it is drawn from the compile-time capability vocabulary, so it adds no cardinality a
    /// caller can choose.
    /// </summary>
    public string? Required { get; init; }

    /// <summary>
    /// Capability set the presented credential actually carried, rendered the way
    /// <c>oci.scope_denied</c> renders it. Required-versus-granted is the whole diagnostic value
    /// of a capability denial: "refused" alone cannot tell an operator whether to re-mint the
    /// token or to stop the caller.
    ///
    /// <para>
    /// Its key cost depends on what <see cref="Partition"/> holds. Where the partition names the
    /// credential itself, the granted set is functionally determined by it — one token has one
    /// capability set — and costs no keys at all. Where the partition is an address, an address
    /// can present arbitrarily many credentials in a window and the granted set does multiply
    /// keys; <see cref="AuthDenialAuditCoalescer.CountKeyCap"/> is what bounds that, not this
    /// field's own shape. It is dropped entirely when a key folds into the overflow bucket,
    /// because there the partition is gone and the set no longer describes anything.
    /// </para>
    /// </summary>
    public string? Granted { get; init; }

    /// <summary>Endpoint route template. Never <c>Request.Path</c>.</summary>
    public required string Route { get; init; }
}

/// <summary>
/// One key's denial count within one wall-clock window.
/// <see cref="WindowStart"/>/<see cref="WindowEnd"/> are the
/// <see cref="AuthDenialAuditCoalescer.WindowAlignment"/>-aligned bounds of the window the counted
/// denials fell in — identical on every replica for the same denials, which is what makes the
/// documented <c>(org, partition, reason, window_start)</c> grouping join across them.
/// </summary>
public sealed record AuthDenialTally(
    AuthDenialKey Key,
    long Count,
    string? SourceIp,
    DateTimeOffset WindowStart,
    DateTimeOffset WindowEnd);

/// <summary>
/// One drain's worth of tallies. <see cref="DrainedAt"/> is when the drain ran and labels nothing;
/// the window a tally belongs to is carried per tally, because a drain can span a window boundary
/// and the two buckets it returns are genuinely different windows.
/// </summary>
public sealed record AuthDenialWindow(
    DateTimeOffset DrainedAt,
    IReadOnlyList<AuthDenialTally> Entries);
