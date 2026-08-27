using System.Text.Json;
using Dependably.Infrastructure;

namespace Dependably.Api;

/// <summary>
/// Derives the per-tenant health verdict and stats summary the system tenant list renders, from
/// the <see cref="OrgListItem"/> row alone.
///
/// <para>Its own class rather than more of <see cref="SystemController"/>: this is a pure
/// projection with no request, no authorization and no I/O, and keeping it here is what stops the
/// controller's type coupling growing every time the health rules learn a new signal.</para>
/// </summary>
internal static class TenantHealthProjection
{
    // Storage utilisation thresholds for per-tenant health signals.
    private const double StorageWarnFraction = 0.90;

    // Snapshot age threshold for "stale" warning on tenant health: 2 hours.
    private static readonly TimeSpan SnapshotStaleThreshold = TimeSpan.FromHours(2);

    // Severity rank for health status promotion: higher rank wins.
    private const int RankOk = 0;
    private const int RankWarn = 1;
    private const int RankCritical = 2;

    private static int SeverityRank(string s) =>
        s switch { "critical" => RankCritical, "warn" => RankWarn, _ => RankOk };

    // Promotes status to the higher-severity value; "ok" < "warn" < "critical".
    private static string Promote(string current, string candidate) =>
        SeverityRank(candidate) > SeverityRank(current) ? candidate : current;

    // Derives per-tenant health status and a stats summary from OrgListItem data. Returns
    // both so the list projection can include a stats object alongside the health verdict
    // without a second query or parse pass.
    internal static (object Health, object? Stats) DeriveHealthAndStats(OrgListItem org, DateTimeOffset now)
    {
        var reasons = new List<string>();
        string status = "ok";
        object? statsSummary = null;

        // StatsRefreshService deliberately excludes a non-active org from its per-org enumeration
        // (see TenantLifecycle) — a suspended/archived/deleting tenant's snapshot stops refreshing
        // rather than going stale on its own. Surfacing that as plain "stats_stale"/"stats_missing"
        // would read as a health-pipeline problem; it is a deliberate, explained consequence of
        // suspension instead, so it gets its own reason below rather than sharing theirs.
        bool isNonActiveOrg = org.Status != "active";

        if (org.Status == "suspended")
        {
            reasons.Add("suspended");
            status = Promote(status, "warn");
        }

        string? quotaReason = QuotaReason(org);
        if (quotaReason is not null)
        {
            reasons.Add(quotaReason);
            status = Promote(status, quotaReason == "storage_quota_exceeded" ? "critical" : "warn");
        }

        string? freshnessReason = SnapshotFreshnessReason(org, now, isNonActiveOrg);
        if (freshnessReason is not null)
        {
            reasons.Add(freshnessReason);
            status = Promote(status, "warn");
        }

        if (org.StatsJson is not null)
        {
            var (statsStatus, statsReasons, statsSnapshotSummary) =
                EvaluateStatsHealth(org.StatsJson, org.StatsComputedAt);
            foreach (string reason in statsReasons)
            {
                if (!reasons.Contains(reason))
                {
                    reasons.Add(reason);
                }
            }

            status = Promote(status, statsStatus);
            statsSummary = statsSnapshotSummary;
        }

        var health = new { status, reasons };
        return (health, statsSummary);
    }

    // Where this tenant sits against its storage quota, or null when it has none or is under the
    // warning fraction. An org with no quota is not "within quota" — there is nothing to be within.
    private static string? QuotaReason(OrgListItem org)
    {
        if (!org.StorageQuotaBytes.HasValue || org.StorageQuotaBytes.Value <= 0)
        {
            return null;
        }

        double fraction = (double)org.StorageBytes / org.StorageQuotaBytes.Value;
        return fraction >= 1.0
            ? "storage_quota_exceeded"
            : fraction >= StorageWarnFraction ? "storage_quota_near" : null;
    }

    // Why this tenant's snapshot cannot be trusted as current, or null when it can. An unparseable
    // timestamp is surfaced as a stale snapshot, not silently ignored — unless the org is
    // non-active, in which case the frozen-by-suspension reason explains it more accurately than
    // "stale" or "missing" would.
    private static string? SnapshotFreshnessReason(OrgListItem org, DateTimeOffset now, bool isNonActiveOrg)
    {
        if (org.StatsComputedAt is null)
        {
            return isNonActiveOrg ? "stats_frozen_non_active" : "stats_missing";
        }

        bool stale = !DateTimeOffset.TryParse(org.StatsComputedAt, out var computedAt)
            || now - computedAt > SnapshotStaleThreshold;
        return stale
            ? isNonActiveOrg ? "stats_frozen_non_active" : "stats_stale"
            : null;
    }

    // Evaluates the per-tenant stats snapshot in isolation so the snapshot parsing and its
    // nesting stay out of DeriveHealthAndStats. Returns the health verdict plus a summary object
    // built from the same parse (so the list projection needs no second parse). A stale or
    // malformed snapshot surfaces as "stats_stale" and a null summary.
    private static (string Status, IReadOnlyList<string> Reasons, object? Summary) EvaluateStatsHealth(
        string statsJson, string? computedAt)
    {
        var reasons = new List<string>();
        string status = "ok";
        object? summary = null;

        try
        {
            var stats = JsonSerializer.Deserialize<OrgStats>(statsJson, JsonContracts.Web);
            if (stats is not null)
            {
                if (stats.QuarantinePending > 0)
                {
                    reasons.Add("quarantine_pending");
                    status = Promote(status, "warn");
                }

                // Summary for the frontend detail panel, from the already-parsed stats object.
                // trackerConfigured/enrichedAdvisoryCount/totalAdvisoryCount ride along here too —
                // the tenants-table "Enrichment %" column reads them straight off this projection
                // rather than issuing a live per-org query.
                summary = new
                {
                    packagesByEcosystem = stats.PackagesByEcosystem,
                    vulnsByEcosystemAndSeverity = stats.VulnsByEcosystemAndSeverity,
                    diskByEcosystem = stats.DiskByEcosystem,
                    totalDownloads30d = stats.TotalDownloads30d,
                    quarantinePending = stats.QuarantinePending,
                    trackerConfigured = stats.TrackerConfigured,
                    enrichedAdvisoryCount = stats.EnrichedAdvisoryCount,
                    totalAdvisoryCount = stats.TotalAdvisoryCount,
                    computedAt,
                };
            }
        }
        catch (JsonException)
        {
            // Stale or malformed snapshot: surface as stale, not a crash.
            reasons.Add("stats_stale");
            status = Promote(status, "warn");
        }

        return (status, reasons, summary);
    }
}
