using Dependably.Infrastructure;

namespace Dependably.Infrastructure.VulnTracker;

/// <summary>
/// The operator's view of the one tracker connection: whether it is configured, what the last
/// lookups did, what the producer asserts its sources are current to, and how much of the stored
/// enrichment has aged past the horizon.
///
/// <para>
/// <see cref="Configured"/> is the field every renderer must branch on first. A deployment that
/// never configured a tracker has no health row, no fetches and no stale rows — numerically
/// identical to a configured connection that has done nothing yet, and completely different in
/// meaning. Collapsing them renders an unbuilt integration as a dead one.
/// </para>
/// </summary>
/// <param name="Configured">A base URL is stored.</param>
/// <param name="Enabled">The operator has not paused it.</param>
/// <param name="MaxStalenessHours">The configured horizon, for rendering the freshness readings against.</param>
/// <param name="Health">The scan path's health row; null when no scan lookup has ever been attempted.</param>
/// <param name="RecentFetches">Newest-first recent lookups, scan and probe alike.</param>
/// <param name="EnrichedAdvisories">Advisory rows carrying tracker enrichment at all.</param>
/// <param name="StaleAdvisories">How many of those are past the horizon.</param>
public sealed record VulnTrackerHealthView(
    bool Configured,
    bool Enabled,
    int MaxStalenessHours,
    VulnTrackerHealthRow? Health,
    IReadOnlyList<VulnTrackerFetchLogRow> RecentFetches,
    long EnrichedAdvisories,
    long StaleAdvisories);

/// <summary>
/// Assembles <see cref="VulnTrackerHealthView"/> from the connection, the health store and the
/// advisory corpus, shared by the apex and single-mode read surfaces so the two cannot drift —
/// the arrangement <c>RelayHealthAggregator</c> makes for the shared SMTP relay, and for the same
/// reason: one instance-level dependency, so its health is one fact rather than one per tenant.
///
/// <para>
/// Everything it returns is a count, an instant or a status token. No purl, no advisory id, no
/// org id and no tenant slug, because in multi-tenant mode this renders in the system_admin SPA,
/// which must never show tenant business data.
/// </para>
/// </summary>
public sealed class VulnTrackerHealthAggregator
{
    /// <summary>
    /// How many recent lookups the panel shows. Well under the ring's own bound so the reader
    /// asks for a page rather than the whole retained history.
    /// </summary>
    public const int RecentFetchLimit = 20;

    private readonly InstanceVulnTrackerConfig _tracker;
    private readonly VulnTrackerHealthRepository _health;
    private readonly VulnerabilityRepository _vulns;

    public VulnTrackerHealthAggregator(
        InstanceVulnTrackerConfig tracker,
        VulnTrackerHealthRepository health,
        VulnerabilityRepository vulns)
    {
        _tracker = tracker;
        _health = health;
        _vulns = vulns;
    }

    public async Task<VulnTrackerHealthView> GetAsync(CancellationToken ct = default)
    {
        var resolved = await _tracker.ResolveAsync(ct);

        if (!resolved.Configured)
        {
            // Short-circuited rather than queried and returned as zeroes. The queries would answer
            // honestly — an unconfigured deployment really does hold no enrichment — but running
            // them would mean the "not configured" state is inferred downstream from a pile of
            // zeroes that a brand-new working connection also produces.
            return new VulnTrackerHealthView(
                Configured: false,
                Enabled: resolved.Enabled,
                MaxStalenessHours: resolved.Connection.MaxStalenessHours,
                Health: null,
                RecentFetches: [],
                EnrichedAdvisories: 0,
                StaleAdvisories: 0);
        }

        var health = await _health.GetHealthAsync(ct);
        var fetches = await _health.ListRecentFetchesAsync(RecentFetchLimit, ct);
        var (enriched, stale) = await _vulns.CountEnrichmentFreshnessAsync(ct);

        return new VulnTrackerHealthView(
            Configured: true,
            Enabled: resolved.Enabled,
            MaxStalenessHours: resolved.Connection.MaxStalenessHours,
            Health: health,
            RecentFetches: fetches,
            EnrichedAdvisories: enriched,
            StaleAdvisories: stale);
    }

    /// <summary>
    /// Projects the view for the wire. camelCase because the Svelte frontend is the only
    /// consumer — the C# default emits PascalCase, which it does not read and which surfaces as a
    /// blank panel rather than a compile error.
    /// </summary>
    public static object BuildView(VulnTrackerHealthView view)
        => new
        {
            configured = view.Configured,
            enabled = view.Enabled,
            maxStalenessHours = view.MaxStalenessHours,
            enrichedAdvisories = view.EnrichedAdvisories,
            staleAdvisories = view.StaleAdvisories,
            health = view.Health is null ? null : new
            {
                lastAttemptAt = view.Health.LastAttemptAt,
                lastSuccessAt = view.Health.LastSuccessAt,
                lastStatus = view.Health.LastStatus,
                lastReason = view.Health.LastReason,
                lastPurlCount = view.Health.LastPurlCount,
                lastAdvisoryCount = view.Health.LastAdvisoryCount,
                consecutiveFailures = view.Health.ConsecutiveFailures,
                failingSince = view.Health.FailingSince,
                nvdAssertedAt = view.Health.NvdAssertedAt,
                ssvcAssertedAt = view.Health.SsvcAssertedAt,
            },
            recentFetches = view.RecentFetches.Select(f => new
            {
                startedAt = f.StartedAt,
                kind = f.Kind,
                outcome = f.Outcome,
                reason = f.Reason,
                purlCount = f.PurlCount,
                advisoryCount = f.AdvisoryCount,
                durationMs = f.DurationMs,
            }).ToList(),
        };
}
