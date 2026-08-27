using Dapper;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure.VulnTracker;

/// <summary>
/// One tracker lookup, as observed by whoever made it. Carries counts and instants only — never a
/// purl, an advisory id or a tenant identifier, because every surface that reads it back renders
/// in the operator context (in multi-tenant mode, the system_admin SPA, which must never show
/// tenant business data).
/// </summary>
/// <param name="Reached">
/// True only when the tracker answered 2xx with a parseable body — the client's own
/// <see cref="VulnerabilityEnrichmentBatchResult.Reached"/>. Every refusal, including a quota
/// refusal, is false.
/// </param>
/// <param name="Reason">Normalized <see cref="EnrichmentUnreachedReason"/>; <c>none</c> when reached.</param>
/// <param name="PurlCount">How many purls the lookup asked about.</param>
/// <param name="AdvisoryCount">How many advisories a reached answer carried; 0 otherwise.</param>
/// <param name="DurationMs">Wall-clock the lookup took, measured with <see cref="TimeProvider"/>.</param>
/// <param name="StartedAt">When the lookup began.</param>
/// <param name="NvdAssertedAt">The producer's asserted NVD as-of, when it declared one.</param>
/// <param name="SsvcAssertedAt">The producer's asserted SSVC as-of, when it declared one.</param>
public sealed record VulnTrackerFetchOutcome(
    bool Reached,
    string Reason,
    int PurlCount,
    int AdvisoryCount,
    long DurationMs,
    DateTimeOffset StartedAt,
    DateTimeOffset? NvdAssertedAt = null,
    DateTimeOffset? SsvcAssertedAt = null);

/// <summary>
/// The stored health of the one tracker connection. All instants are canonical UTC ISO-8601
/// strings, re-serialized rather than parsed, because every consumer either renders them or
/// hands them to a client that formats in the viewer's locale.
///
/// <para>
/// A settable-property class rather than a positional record, matching
/// <see cref="BackgroundJobRun"/>: SQLite hands every INTEGER column back as
/// <see cref="long"/>, and Dapper's record path resolves a constructor by exact parameter type,
/// so an <c>int</c> member would fail materialization at runtime with no compile-time signal.
/// </para>
/// </summary>
public class VulnTrackerHealthRow
{
    public string? LastAttemptAt { get; set; }
    public string? LastSuccessAt { get; set; }
    public string LastStatus { get; set; } = "";
    public string LastReason { get; set; } = "";
    public long LastPurlCount { get; set; }
    public long LastAdvisoryCount { get; set; }
    public long ConsecutiveFailures { get; set; }
    public string? FailingSince { get; set; }
    public string? NvdAssertedAt { get; set; }
    public string? SsvcAssertedAt { get; set; }
}

/// <summary>One row of the bounded recent-fetch log. Class-shaped for the reason above.</summary>
public class VulnTrackerFetchLogRow
{
    public string StartedAt { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Outcome { get; set; } = "";
    public string Reason { get; set; } = "";
    public long PurlCount { get; set; }
    public long AdvisoryCount { get; set; }
    public long DurationMs { get; set; }
}

/// <summary>
/// Reads and writes the observed health of the one instance-level vulnerability-tracker
/// connection (<c>vuln_tracker_health</c>) and its bounded recent-fetch log
/// (<c>vuln_tracker_fetch_log</c>).
///
/// <para>
/// <b>This never writes configuration.</b> Not one statement here touches the <c>vuln_tracker_*</c>
/// keys in <c>instance_settings</c>: a failing tracker does not switch itself off, and a green
/// probe does not switch it on. That is the same posture <c>RecordEmailFailureAsync</c> takes with
/// the shared SMTP relay, for the same reason — configuration is what the operator asked for,
/// health is what happened, and letting an outage rewrite intent turns one infrastructure failure
/// into a configuration change nobody made and nobody can find.
/// </para>
///
/// <para>
/// <b>A probe never moves the health row.</b> <see cref="RecordProbeFetchAsync"/> writes the fetch
/// log and stops there. The health row describes the scan path — the path the block-gate arms
/// actually depend on — so letting an operator-initiated probe clear
/// <c>consecutive_failures</c> would let the one button an operator presses when worried paint
/// false-green over a scan path that is still broken.
/// </para>
/// </summary>
public sealed class VulnTrackerHealthRepository
{
    /// <summary>Fixed sentinel key of the single health row.</summary>
    private const string HealthRowId = "primary";

    /// <summary>
    /// How many fetch-log rows are kept. Bounded on write rather than by a retention sweep, so the
    /// bound holds on a deployment with background jobs disabled and cannot drift from the reader.
    /// </summary>
    public const int FetchLogRetained = 100;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public VulnTrackerHealthRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Records a lookup the enrichment pass made: one fetch-log row, plus the health row this
    /// outcome implies.
    /// </summary>
    public async Task RecordScanFetchAsync(VulnTrackerFetchOutcome outcome, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await InsertFetchAsync(conn, outcome, kind: "scan", ct);

        if (outcome.Reached)
        {
            await RecordReachedAsync(conn, outcome, ct);
        }
        else
        {
            await RecordUnreachedAsync(conn, outcome, ct);
        }

        await TrimFetchLogAsync(conn, ct);
    }

    /// <summary>
    /// Records an operator-initiated connection test. Fetch log only — see the type's remarks for
    /// why a probe deliberately leaves the health row alone.
    /// </summary>
    public async Task RecordProbeFetchAsync(VulnTrackerFetchOutcome outcome, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await InsertFetchAsync(conn, outcome, kind: "probe", ct);
        await TrimFetchLogAsync(conn, ct);
    }

    /// <summary>
    /// The stored health row, or null when no lookup has ever been attempted. Null is
    /// meaningfully different from a failing row and callers must not collapse the two: it means
    /// the scan has not run against a configured tracker yet, not that the tracker is down.
    /// </summary>
    public async Task<VulnTrackerHealthRow?> GetHealthAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: instance-global health of the one operator-owned tracker connection. The table
        // has no org_id by design — there is exactly one connection per deployment.
        return await conn.QuerySingleOrDefaultAsync<VulnTrackerHealthRow>(new CommandDefinition(
            """
            SELECT last_attempt_at      AS LastAttemptAt,
                   last_success_at      AS LastSuccessAt,
                   last_status          AS LastStatus,
                   last_reason          AS LastReason,
                   last_purl_count      AS LastPurlCount,
                   last_advisory_count  AS LastAdvisoryCount,
                   consecutive_failures AS ConsecutiveFailures,
                   failing_since        AS FailingSince,
                   nvd_asserted_at      AS NvdAssertedAt,
                   ssvc_asserted_at     AS SsvcAssertedAt
            FROM vuln_tracker_health
            WHERE id = @id
            """,
            new { id = HealthRowId }, cancellationToken: ct));
    }

    /// <summary>The most recent fetches, newest first, capped at <paramref name="limit"/>.</summary>
    public async Task<IReadOnlyList<VulnTrackerFetchLogRow>> ListRecentFetchesAsync(
        int limit, CancellationToken ct = default)
    {
        int capped = Math.Clamp(limit, 1, FetchLogRetained);
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: instance-global telemetry about one operator-owned connection; the table has
        // no org_id and the projection carries counts only, never a purl or a tenant identifier.
        var rows = await conn.QueryAsync<VulnTrackerFetchLogRow>(new CommandDefinition(
            """
            SELECT started_at     AS StartedAt,
                   kind           AS Kind,
                   outcome        AS Outcome,
                   reason         AS Reason,
                   purl_count     AS PurlCount,
                   advisory_count AS AdvisoryCount,
                   duration_ms    AS DurationMs
            FROM vuln_tracker_fetch_log
            ORDER BY started_at DESC, id DESC
            LIMIT @limit
            """,
            new { limit = capped }, cancellationToken: ct));

        return rows.ToList();
    }

    private static async Task InsertFetchAsync(
        System.Data.Common.DbConnection conn, VulnTrackerFetchOutcome outcome, string kind, CancellationToken ct)
    {
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vuln_tracker_fetch_log
                (id, started_at, kind, outcome, reason, purl_count, advisory_count, duration_ms)
            VALUES
                (@id, @startedAt, @kind, @outcome, @reason, @purlCount, @advisoryCount, @durationMs)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                // Millisecond precision, unlike the health row's second precision: several
                // lookups land inside one wall-clock second on a busy pass, and this column is
                // the log's sort key. Always three digits, so the column still collates.
                startedAt = outcome.StartedAt.ToUtcIsoMillis(),
                kind,
                outcome = outcome.Reached ? "ok" : "failed",
                reason = outcome.Reason,
                purlCount = outcome.PurlCount,
                advisoryCount = outcome.AdvisoryCount,
                durationMs = outcome.DurationMs,
            },
            cancellationToken: ct));
    }

    private async Task RecordReachedAsync(
        System.Data.Common.DbConnection conn, VulnTrackerFetchOutcome outcome, CancellationToken ct)
    {
        // The producer's asserted as-of is COALESCEd rather than overwritten. A reached response
        // that declares no freshness for a source has told us nothing new about it, and the last
        // thing it did declare is still the only upper bound we hold — and it is the OLDER value,
        // so keeping it can only make a staleness reading more conservative, never less.
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vuln_tracker_health
                (id, last_attempt_at, last_success_at, last_status, last_reason,
                 last_purl_count, last_advisory_count, consecutive_failures, failing_since,
                 nvd_asserted_at, ssvc_asserted_at)
            VALUES
                (@id, @now, @now, 'ok', 'none', @purlCount, @advisoryCount, 0, NULL, @nvd, @ssvc)
            ON CONFLICT (id) DO UPDATE SET
                last_attempt_at      = @now,
                last_success_at      = @now,
                last_status          = 'ok',
                last_reason          = 'none',
                last_purl_count      = @purlCount,
                last_advisory_count  = @advisoryCount,
                consecutive_failures = 0,
                failing_since        = NULL,
                nvd_asserted_at      = COALESCE(@nvd, vuln_tracker_health.nvd_asserted_at),
                ssvc_asserted_at     = COALESCE(@ssvc, vuln_tracker_health.ssvc_asserted_at)
            """,
            new
            {
                id = HealthRowId,
                now = _time.GetUtcNow().ToUtcIso(),
                purlCount = outcome.PurlCount,
                advisoryCount = outcome.AdvisoryCount,
                nvd = outcome.NvdAssertedAt.ToUtcIsoOrNull(),
                ssvc = outcome.SsvcAssertedAt.ToUtcIsoOrNull(),
            },
            cancellationToken: ct));
    }

    private async Task RecordUnreachedAsync(
        System.Data.Common.DbConnection conn, VulnTrackerFetchOutcome outcome, CancellationToken ct)
    {
        // last_success_at, the two counts and both asserted-at stamps are deliberately untouched:
        // they describe the last lookup that was REACHED, and a failure has learned nothing that
        // would revise them. failing_since is COALESCEd so it records where the streak began — an
        // operator needs "failing for six hours", which a last-failure stamp cannot express.
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO vuln_tracker_health
                (id, last_attempt_at, last_success_at, last_status, last_reason,
                 last_purl_count, last_advisory_count, consecutive_failures, failing_since)
            VALUES
                (@id, @now, NULL, 'failed', @reason, 0, 0, 1, @now)
            ON CONFLICT (id) DO UPDATE SET
                last_attempt_at      = @now,
                last_status          = 'failed',
                last_reason          = @reason,
                consecutive_failures = vuln_tracker_health.consecutive_failures + 1,
                failing_since        = COALESCE(vuln_tracker_health.failing_since, @now)
            """,
            new { id = HealthRowId, now = _time.GetUtcNow().ToUtcIso(), reason = outcome.Reason },
            cancellationToken: ct));
    }

    /// <summary>
    /// Keeps the newest <see cref="FetchLogRetained"/> rows. Ordered by the same key the reader
    /// uses, so the rows that survive are exactly the rows a reader would have shown.
    /// </summary>
    private static async Task TrimFetchLogAsync(System.Data.Common.DbConnection conn, CancellationToken ct)
    {
        await conn.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM vuln_tracker_fetch_log
            WHERE id NOT IN (
                SELECT id FROM vuln_tracker_fetch_log
                ORDER BY started_at DESC, id DESC
                LIMIT @keep)
            """,
            new { keep = FetchLogRetained }, cancellationToken: ct));
    }
}

/// <summary>
/// Normalizes an <see cref="EnrichmentUnreachedReason"/> to the closed token set the
/// <c>last_reason</c> / <c>reason</c> columns admit.
///
/// <para>
/// The <c>unknown</c> fallback is the point of the type. Both columns carry a CHECK, and neither
/// provider lets SQLite add one later — so writing an enum member raw would mean that the day
/// someone adds a reason to the client, every health write starts failing its constraint and the
/// panel silently stops recording anything. Mapping explicitly, with a fallback inside the
/// admitted set, makes an unmapped reason render as <c>unknown</c> instead.
/// </para>
/// </summary>
public static class VulnTrackerHealthReasons
{
    /// <summary>The reason recorded when the lookup threw instead of returning an unreached result.</summary>
    public const string Exception = "exception";

    /// <summary>The reason recorded for an <see cref="EnrichmentUnreachedReason"/> this mapping does not know.</summary>
    public const string Unknown = "unknown";

    public static string Normalize(EnrichmentUnreachedReason reason) => reason switch
    {
        EnrichmentUnreachedReason.None => "none",
        EnrichmentUnreachedReason.NotConfigured => "notConfigured",
        EnrichmentUnreachedReason.EmptyRequest => "emptyRequest",
        EnrichmentUnreachedReason.BatchTooLarge => "batchTooLarge",
        EnrichmentUnreachedReason.Transport => "transport",
        EnrichmentUnreachedReason.Timeout => "timeout",
        EnrichmentUnreachedReason.Unauthorized => "unauthorized",
        EnrichmentUnreachedReason.RateLimited => "rateLimited",
        EnrichmentUnreachedReason.ServerError => "serverError",
        EnrichmentUnreachedReason.Refused => "refused",
        EnrichmentUnreachedReason.MalformedResponse => "malformedResponse",
        _ => Unknown,
    };
}
