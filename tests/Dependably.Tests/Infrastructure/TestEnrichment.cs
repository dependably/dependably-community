using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test doubles for the tracker enrichment overlay.
///
/// <para>
/// The defaults are the shape every pre-existing scan test needs: a tracker that is **not
/// configured**, which is what the overwhelming majority of deployments look like and what makes
/// enrichment a complete no-op. That is deliberate — a scan test that was green before the overlay
/// existed must stay green for the same reasons, not because a stub happened to answer.
/// </para>
/// </summary>
public static class TestEnrichment
{
    /// <summary>
    /// An enrichment source that fails the test if it is ever called. Paired with
    /// <see cref="NoConnection"/> it proves the unconfigured path makes no request at all, rather
    /// than making one whose result is discarded.
    /// </summary>
    public static IVulnerabilityEnrichmentSource Unused() => new ThrowingEnrichmentSource();

    /// <summary>An unconfigured connection: no base URL, so <c>IsActive</c> is false.</summary>
    public static InstanceVulnTrackerConfig NoConnection() =>
        new((_, _) => Task.FromResult<string?>(null), TimeProvider.System);

    /// <summary>
    /// A connection an operator has configured and enabled, for the tests that actually exercise
    /// enrichment. <paramref name="batchSize"/> is settable because the chunking behaviour it
    /// drives is one of the things worth pinning.
    /// </summary>
    public static InstanceVulnTrackerConfig ActiveConnection(int batchSize = 100)
    {
        var rows = new Dictionary<string, string?>
        {
            ["vuln_tracker_enabled"] = "1",
            ["vuln_tracker_base_url"] = "https://tracker.example.com",
            ["vuln_tracker_batch_size"] = batchSize.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };
        return new InstanceVulnTrackerConfig(
            (key, _) => Task.FromResult(rows.TryGetValue(key, out string? v) ? v : null),
            TimeProvider.System);
    }

    private sealed class ThrowingEnrichmentSource : IVulnerabilityEnrichmentSource
    {
        public Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
            IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default) =>
            throw new InvalidOperationException(
                "Enrichment was called with no tracker connection configured — the feature must "
                + "make no request at all in that state.");
    }
}
