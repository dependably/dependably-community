using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Scrubbers for tests that assert on the matcher's output. The production match timeout is a
/// wall-clock deadline, so a test thread descheduled mid-match under full-suite load can trip it
/// and receive the fail-closed <see cref="LogPathScrubber.RedactedValue"/> instead of the masked
/// form. Masked-form assertions use <see cref="Generous"/>; the timeout path is pinned separately
/// with <see cref="Instant"/>.
/// </summary>
internal static class TestScrubbers
{
    /// <summary>
    /// Far above any scheduling pause, yet still bounded, so a catastrophic-backtracking
    /// regression in the pattern fails a test instead of hanging the run.
    /// </summary>
    public static LogPathScrubber Generous { get; } = new(TimeSpan.FromSeconds(30));

    /// <summary>The smallest timeout the matcher accepts: one tick, which the runtime rounds to a 0 ms budget, so the first deadline check fires.</summary>
    public static LogPathScrubber Instant { get; } = new(TimeSpan.FromTicks(1));

    /// <summary>
    /// An email-bearing value the matcher needs over a hundred milliseconds to scan: four
    /// megabytes of <c>a@a.</c>, which never completes a match (no two-letter top-level label)
    /// and so is scanned end to end. Paired with <see cref="Instant"/> it times out on every run.
    /// </summary>
    public static string SlowToScan { get; } =
        "/api/v1/system/users/alice@customer.example/" + string.Concat(Enumerable.Repeat("a@a.", 1_000_000));
}
