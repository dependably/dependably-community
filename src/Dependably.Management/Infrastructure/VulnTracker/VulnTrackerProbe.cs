using Dependably.Protocol;

namespace Dependably.Infrastructure.VulnTracker;

/// <summary>
/// Outcome of an operator-initiated connection test, as returned by both the apex and
/// single-mode surfaces.
///
/// <para>
/// <see cref="Reason"/> is a token, not a sentence: the frontend owns the wording, the same way
/// it does for every other status it renders. Returning prose here would put one of the two
/// locales in the backend's resources and the other in the SPA's.
/// </para>
/// </summary>
/// <param name="Reached">
/// True only when the tracker answered 2xx with a body the client could parse — the client's own
/// narrow claim, not "the host responded".
/// </param>
/// <param name="Reason">Normalized reason; <c>none</c> when reached.</param>
/// <param name="LatencyMs">Round trip as measured by the injected clock.</param>
/// <param name="Freshness">The producer's asserted as-of per source, exactly as it sent them.</param>
public sealed record VulnTrackerProbeResult(
    bool Reached,
    string Reason,
    long LatencyMs,
    IReadOnlyList<VulnTrackerProbeFreshness> Freshness);

/// <summary>One source's producer-asserted as-of, projected for the wire.</summary>
public sealed record VulnTrackerProbeFreshness(string Source, string? AsOf);

/// <summary>
/// The operator-initiated connection test, shared by the apex
/// (<c>POST /api/v1/system/vuln-tracker-config/test</c>) and single-mode
/// (<c>POST /api/v1/instance/vuln-tracker-config/test</c>) surfaces so the two cannot drift —
/// the same arrangement <see cref="VulnTrackerConfigEditing"/> makes for the editing routes.
///
/// <para>
/// <b>It probes the real lookup, not a health endpoint.</b> A reachability ping proves the host
/// is up, which is rarely the thing that is wrong: a tracker that answers <c>GET /health</c>
/// happily while rejecting this deployment's bearer token would report green and enrich nothing.
/// Issuing an actual <c>POST /lookup/batch</c> exercises the credential, the connect-time SSRF
/// guard, the response contract and the parse path — every leg the scan depends on.
/// </para>
///
/// <para>
/// <b>It refuses to dial a paused connection.</b> The probe requires
/// <see cref="InstanceVulnTrackerConfig.ResolvedVulnTrackerConfig.IsActive"/>, not merely a
/// stored base URL, because "paused" has to mean no outbound request at all. A test button that
/// dialed a switched-off tracker would quietly make the off switch mean something weaker than it
/// says, and an operator who wants to test can enable and save first.
/// </para>
///
/// <para>
/// <b>It never accepts a caller-supplied base URL or token.</b> Testing an unsaved form would be
/// friendlier, and it would also hand an authenticated operator an endpoint that posts an
/// arbitrary bearer credential to an arbitrary host of their choosing — an SSRF and
/// credential-exfiltration primitive wearing a convenience feature's clothes. The instance SMTP
/// transport's test send resolves saved configuration for the same reason.
/// </para>
/// </summary>
public static class VulnTrackerProbe
{
    /// <summary>
    /// The purl the probe asks about. Deliberately synthetic and deliberately not any package a
    /// tenant could hold: the request leaves this deployment, and the answer is irrelevant — only
    /// whether the tracker could be reached at all. No CVE hints are sent, so an empty result is
    /// the expected reached response.
    /// </summary>
    public const string ProbePurl = "pkg:npm/%40dependably/connection-probe@0.0.0";

    /// <summary>
    /// Runs the probe against the saved connection. Returns null when there is nothing to dial —
    /// the caller turns that into a validation error, because a connection that was never
    /// configured is a different answer from one that could not be reached, and rendering the
    /// first as the second would report an unbuilt integration as a broken one.
    /// </summary>
    public static async Task<VulnTrackerProbeResult?> TryProbeAsync(
        InstanceVulnTrackerConfig tracker,
        IVulnerabilityEnrichmentSource enrichment,
        VulnTrackerHealthRepository health,
        TimeProvider time,
        CancellationToken ct)
    {
        var resolved = await tracker.ResolveAsync(ct);
        if (!resolved.IsActive)
        {
            return null;
        }

        var timing = new ProbeTiming(time, time.GetUtcNow(), time.GetTimestamp());

        VulnerabilityEnrichmentBatchResult result;
        try
        {
            result = await enrichment.TryLookupBatchAsync([new EnrichmentLookupTarget(ProbePurl, [])], ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The client contracts never to throw for a remote failure. Recorded under its own
            // reason so a fault in the client is distinguishable from a refusal by the producer.
            return await FinishAsync(
                health, timing, reached: false, VulnTrackerHealthReasons.Exception, freshness: [], ct);
        }

        var freshness = result.Freshness
            .Select(f => new VulnTrackerProbeFreshness(f.Source, f.AsOf.ToUtcIsoOrNull()))
            .ToList();

        return await FinishAsync(
            health, timing, result.Reached,
            VulnTrackerHealthReasons.Normalize(result.Reason), freshness, ct);
    }

    /// <summary>When one probe started, and the clock that will measure how long it took.</summary>
    private readonly record struct ProbeTiming(
        TimeProvider Time, DateTimeOffset StartedAt, long StartTicks);

    private static async Task<VulnTrackerProbeResult> FinishAsync(
        VulnTrackerHealthRepository health,
        ProbeTiming timing,
        bool reached,
        string reason,
        IReadOnlyList<VulnTrackerProbeFreshness> freshness,
        CancellationToken ct)
    {
        long latencyMs = (long)timing.Time.GetElapsedTime(timing.StartTicks).TotalMilliseconds;

        // Logged as a probe, which is what keeps it out of the health row: that row describes the
        // scan path, and a green probe must not clear a failure streak the scan is still hitting.
        await health.RecordProbeFetchAsync(
            new VulnTrackerFetchOutcome(
                Reached: reached,
                Reason: reason,
                PurlCount: 1,
                AdvisoryCount: 0,
                DurationMs: latencyMs,
                StartedAt: timing.StartedAt),
            ct);

        return new VulnTrackerProbeResult(reached, reason, latencyMs, freshness);
    }
}
