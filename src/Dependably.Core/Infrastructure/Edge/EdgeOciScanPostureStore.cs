using System.Collections.Concurrent;
using System.Globalization;
using Dapper;

namespace Dependably.Infrastructure.Edge;

/// <summary>
/// On an edge node, the OCI scan-enforcement posture each org's master last stated on a response.
/// An edge holds no scan results and no copy of the master's org settings: an edge reading its own
/// <c>org_settings</c> row would see the default <c>off</c> and skip a gate the master enforces. So
/// the master states the org's posture on every manifest response (<see cref="Header"/>), and the
/// edge records the latest value per org here. A response without the header says nothing about
/// the org and records nothing.
///
/// <para>While the master is reachable, only a fresh <c>off</c> lets the edge answer a manifest from
/// its own cache; any other posture, or none, sends the request to the master. While it is
/// unreachable, only a last-known <c>warn</c> or <c>block</c> refuses: an org at <c>off</c>, or one
/// whose posture the master never stated, is answered from the edge cache as it always was.</para>
///
/// <para>A recorded <c>off</c> is only trusted for <see cref="OffFreshness"/> after the master last
/// confirmed it: an org that moves to <c>warn</c>/<c>block</c> on the master would otherwise be
/// served from the edge cache with no master check for as long as the edge stays up. Once stale,
/// <c>off</c> reads as unknown and the next manifest request goes to the master, whose response
/// refreshes it. <c>warn</c> and <c>block</c> already consult the master on every request, so they
/// carry no bound.</para>
///
/// <para>Kept in memory and written through to <c>edge_oci_scan_postures</c>, whose
/// <c>recorded_at</c> is when the master last stated the posture, so a restart keeps both the
/// posture and the age of an <c>off</c> confirmation. A change is written at once; a repeated
/// <c>off</c> only once its persisted confirmation is <see cref="OffPersistInterval"/> old, so a
/// steady stream of responses costs few writes.</para>
/// </summary>
public sealed class EdgeOciScanPostureStore
{
    /// <summary>The response header the master states an org's posture in.</summary>
    public const string Header = "X-Dependably-Oci-Scan-Enforcement";

    /// <summary>How long a recorded <c>off</c> is trusted after the master last stated it.</summary>
    public static readonly TimeSpan OffFreshness = TimeSpan.FromMinutes(5);

    /// <summary>How old a persisted <c>off</c> confirmation gets before a repeated <c>off</c> rewrites it.</summary>
    public static readonly TimeSpan OffPersistInterval = TimeSpan.FromMinutes(1);

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, Entry> _known = new(StringComparer.Ordinal);

    // ConfirmedAt is the last time the master stated the posture; PersistedAt the recorded_at
    // the database holds for it. A null instant is one the edge cannot read and treats as stale.
    private sealed record Entry(string Posture, DateTimeOffset? ConfirmedAt, DateTimeOffset? PersistedAt);

    public EdgeOciScanPostureStore(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// The org's last reported posture (<c>off</c>, <c>warn</c> or <c>block</c>), or null when the
    /// master has never reported one for it or its <c>off</c> is older than
    /// <see cref="OffFreshness"/>.
    /// </summary>
    public async Task<string?> GetAsync(string orgId, CancellationToken ct = default)
    {
        var entry = await LoadAsync(orgId, ct);
        return entry is null || (entry.Posture == "off" && !IsFresh(entry.ConfirmedAt)) ? null : entry.Posture;
    }

    /// <summary>
    /// The org's last reported posture with no freshness bound, or null when the master never
    /// stated one.
    /// </summary>
    public async Task<string?> GetLastKnownAsync(string orgId, CancellationToken ct = default) =>
        (await LoadAsync(orgId, ct))?.Posture;

    /// <summary>
    /// For a request the master cannot answer: the org's last-known posture when it is
    /// <c>warn</c> or <c>block</c>, which refuses, or null when it is <c>off</c> or was never
    /// stated, which leaves the edge to answer from its own cache.
    /// </summary>
    public async Task<string?> LastKnownGatedPostureAsync(string orgId, CancellationToken ct = default)
    {
        string? posture = await GetLastKnownAsync(orgId, ct);
        return posture is "warn" or "block" ? posture : null;
    }

    /// <summary>
    /// True when the edge may answer a manifest for the org from its own cache: the master
    /// reported <c>off</c> within <see cref="OffFreshness"/>.
    /// </summary>
    public async Task<bool> MayServeFromCacheAsync(string orgId, CancellationToken ct = default) =>
        await GetAsync(orgId, ct) == "off";

    /// <summary>Records the posture a master response stated; a value outside the vocabulary is ignored.</summary>
    public async Task RecordAsync(string orgId, string posture, CancellationToken ct = default)
    {
        if (posture is not ("off" or "warn" or "block"))
        {
            return;
        }

        var now = _time.GetUtcNow();
        var current = await LoadAsync(orgId, ct);
        if (current is not null && current.Posture == posture
            && (posture != "off" || (current.PersistedAt is { } persisted && now - persisted < OffPersistInterval)))
        {
            _known[orgId] = current with { ConfirmedAt = now };
            return;
        }

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO edge_oci_scan_postures (org_id, posture, recorded_at)
            VALUES (@orgId, @posture, @now)
            ON CONFLICT (org_id) DO UPDATE SET posture = excluded.posture, recorded_at = excluded.recorded_at
            """,
            new { orgId, posture, now = now.ToUtcIsoMillis() });
        _known[orgId] = new Entry(posture, now, now);
    }

    private bool IsFresh(DateTimeOffset? confirmedAt) =>
        confirmedAt is { } confirmed && _time.GetUtcNow() - confirmed < OffFreshness;

    private async Task<Entry?> LoadAsync(string orgId, CancellationToken ct)
    {
        if (_known.TryGetValue(orgId, out var entry))
        {
            return entry;
        }

        await using var conn = await _db.OpenAsync(ct);
        var (posture, recorded) = await conn.QuerySingleOrDefaultAsync<(string? Posture, string? RecordedAt)>(
            "SELECT posture AS Posture, recorded_at AS RecordedAt FROM edge_oci_scan_postures WHERE org_id = @orgId",
            new { orgId });
        if (posture is null)
        {
            return null;
        }

        DateTimeOffset? recordedAt = DateTimeOffset.TryParse(
            recorded, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : null;
        return _known.GetOrAdd(orgId, new Entry(posture, recordedAt, recordedAt));
    }
}
