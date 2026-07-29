namespace Dependably.Infrastructure;

/// <summary>
/// Per-org ledger of bytes this process has admitted through the tenant storage-quota gate but
/// that the committed <c>org_storage_bytes</c> sum cannot see yet.
///
/// The gate derives usage from the live view rather than an accumulated counter, so a write is
/// invisible to it until its row is committed — a blob is put, a <c>cache_artifact</c> or
/// <c>package_versions</c> row lands afterwards. Without this ledger every concurrent write of a
/// distinct artefact reads the same pre-write sum and admits itself, bounded only by how many
/// requests the tenant opens. Charging admitted-but-uncommitted bytes against the ceiling makes
/// concurrent writes see each other.
///
/// The ledger is per-process, so a multi-replica deployment bounds each replica independently and
/// can overshoot by (replicas x in-flight bytes); community deployments are single-node. A narrow
/// window also remains between releasing a reservation and the row becoming visible to the sum.
/// Both are bounded overshoots the next read corrects, not unbounded attacker-paced growth.
/// </summary>
public sealed class StorageQuotaLedger
{
    private readonly Dictionary<string, long> _inFlight = [];
    private readonly object _gate = new();

    /// <summary>
    /// Admits <paramref name="delta"/> bytes for <paramref name="orgId"/> when
    /// <paramref name="committedBytes"/> (the live sum) plus the org's in-flight total plus
    /// <paramref name="delta"/> stays inside <paramref name="quota"/>. Returns the reservation to
    /// dispose once the write is committed (or has failed), or <c>null</c> when the write would
    /// exceed the ceiling — the caller's 413.
    ///
    /// Test-and-charge run under one lock so two writes cannot both read the same in-flight total
    /// and both admit themselves. The caller's live-sum read stays outside it: no await ever holds
    /// the lock, and a sum gone stale by a just-committed row only admits one write that could
    /// have been refused, which the next read corrects.
    ///
    /// A negative delta (an overwrite whose replacement is smaller than what it replaces) is
    /// tested as-is but charged as zero — releasing bytes is only real once the row commits, and
    /// a negative charge would understate the footprint concurrent writers see.
    /// </summary>
    public StorageReservation? TryReserve(string orgId, long committedBytes, long delta, long quota)
    {
        long charge = Math.Max(0, delta);
        lock (_gate)
        {
            _inFlight.TryGetValue(orgId, out long inFlight);
            if (committedBytes + inFlight + delta > quota)
            {
                return null;
            }

            _inFlight[orgId] = inFlight + charge;
        }

        return new StorageReservation(this, orgId, charge);
    }

    /// <summary>
    /// Returns <paramref name="charge"/> to the org's in-flight total once the write it covered
    /// has completed — committed (the live sum owns those bytes now) or failed (they were never
    /// written). Drops the key at zero so an instance that has served many orgs holds no per-org
    /// residue.
    /// </summary>
    internal void Release(string orgId, long charge)
    {
        if (charge == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!_inFlight.TryGetValue(orgId, out long inFlight))
            {
                return;
            }

            long remaining = inFlight - charge;
            if (remaining > 0)
            {
                _inFlight[orgId] = remaining;
            }
            else
            {
                _inFlight.Remove(orgId);
            }
        }
    }

    /// <summary>In-flight bytes currently charged to <paramref name="orgId"/>. Diagnostics/tests.</summary>
    public long InFlightBytes(string orgId)
    {
        lock (_gate)
        {
            return _inFlight.TryGetValue(orgId, out long inFlight) ? inFlight : 0;
        }
    }
}

/// <summary>
/// A tenant's claim on quota headroom for one in-flight write. Disposing releases the claim, so
/// callers hold it in a <c>using</c> that spans the write AND the row commit that makes the bytes
/// visible to <c>org_storage_bytes</c> — releasing before the commit reopens the gap the ledger
/// exists to close. Disposal is idempotent.
/// </summary>
public sealed class StorageReservation : IDisposable
{
    /// <summary>
    /// The no-op reservation, returned when no quota applies (unlimited tenant). Callers dispose
    /// unconditionally rather than branching on whether a ceiling was enforced.
    /// </summary>
    public static StorageReservation None { get; } = new(null, string.Empty, 0);

    private readonly StorageQuotaLedger? _ledger;
    private readonly string _orgId;
    private readonly long _charge;
    private bool _released;

    internal StorageReservation(StorageQuotaLedger? ledger, string orgId, long charge)
    {
        _ledger = ledger;
        _orgId = orgId;
        _charge = charge;
    }

    public void Dispose()
    {
        if (_released || _ledger is null)
        {
            return;
        }

        _released = true;
        _ledger.Release(_orgId, _charge);
    }
}
