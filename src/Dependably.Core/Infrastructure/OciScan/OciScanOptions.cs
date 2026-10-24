using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// Instance-level settings for OCI image scanning. Off by default: with
/// <see cref="Enabled"/> false nothing is enqueued, the scan API answers 404, and OCI keeps its
/// standing <c>no_feed</c> status.
/// </summary>
public sealed class OciScanOptions
{
    /// <summary><c>OCI_SCAN_ENABLED</c>: turns on enqueueing, the scan API and OCI coverage.</summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// <c>OCI_SCAN_HEARTBEAT_WINDOW</c>: how recently an org's scanner must have called the scan
    /// API for OCI to count as covered for that org.
    /// </summary>
    public TimeSpan HeartbeatWindow { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary><c>OCI_SCAN_LEASE</c>: how long a claim holds a job before another claim may take it.</summary>
    public TimeSpan Lease { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary><c>OCI_SCAN_MAX_ATTEMPTS</c>: claims a job may consume before a failure parks it.</summary>
    public int MaxAttempts { get; init; } = 5;

    /// <summary>
    /// <c>OCI_SCAN_RESCAN_AGE_HOURS</c>: how old an image's last OSV match may grow before the
    /// sweep queues a rematch (or, for a result that cannot be re-matched, a re-extraction).
    /// </summary>
    public TimeSpan RescanAge { get; init; } = TimeSpan.FromHours(24);

    /// <summary>The first retry delay after a retryable failure; each further attempt doubles it.</summary>
    public TimeSpan RetryBaseDelay { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>The longest retry delay, however many attempts have failed.</summary>
    public TimeSpan RetryMaxDelay { get; init; } = TimeSpan.FromHours(6);

    /// <summary>
    /// <c>OCI_SCAN_ADVISORY_FETCH_MAX</c>: how many advisory ids the instance does not store yet
    /// one result may have fetched from the advisory source. Ids beyond it are recorded as a
    /// coverage gap and fetched on a later match, so one request cannot spend the instance's OSV
    /// budget on thousands of lookups.
    /// </summary>
    public int AdvisoryFetchMax { get; init; } = 200;

    /// <summary>The longest wait between retries of a result refused because the advisory source was unreachable.</summary>
    public TimeSpan AdvisoryDeferMaxDelay { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The advisory source's own HTTP timeout: the <c>osv</c> client's <c>Timeout</c>.
    /// </summary>
    internal static readonly TimeSpan AdvisoryClientTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long one result may spend fetching advisories: a third of the lease, at most two
    /// minutes, so the fetch always finishes well inside the lease. It is never shorter than the
    /// source's own client timeout plus a margin while two thirds of the lease leave room for that,
    /// so a hanging source is reported by its timeout as unreached rather than cut off by the
    /// budget. Ids still unfetched when it ends are recorded as a coverage gap, unless the source
    /// answered nothing at all, which is an outage.
    /// </summary>
    public TimeSpan AdvisoryFetchBudget
    {
        get
        {
            var floor = AdvisoryClientTimeout + TimeSpan.FromSeconds(5);
            var ceiling = TimeSpan.FromMinutes(2);
            var budget = Lease / 3;
            if (budget < floor)
            {
                budget = floor < Lease * 2 / 3 ? floor : Lease * 2 / 3;
            }

            return budget < ceiling ? budget : ceiling;
        }
    }

    /// <summary>
    /// Reads the settings from configuration. A value that is set but cannot be parsed fails
    /// startup rather than silently taking the default, since a mistyped window or lease would
    /// otherwise change coverage without anyone noticing.
    /// </summary>
    public static OciScanOptions FromConfiguration(IConfiguration config)
    {
        var options = new OciScanOptions
        {
            Enabled = ReadBool(config, "OCI_SCAN_ENABLED", false),
            HeartbeatWindow = ReadSpan(config, "OCI_SCAN_HEARTBEAT_WINDOW", TimeSpan.FromMinutes(10)),
            Lease = ReadSpan(config, "OCI_SCAN_LEASE", TimeSpan.FromMinutes(15)),
            MaxAttempts = ReadInt(config, "OCI_SCAN_MAX_ATTEMPTS", 5),
            RescanAge = ReadHours(config, "OCI_SCAN_RESCAN_AGE_HOURS", 24),
            AdvisoryFetchMax = ReadInt(config, "OCI_SCAN_ADVISORY_FETCH_MAX", 200),
        };
        return options.HeartbeatWindow <= TimeSpan.Zero || options.Lease <= TimeSpan.Zero || options.MaxAttempts < 1
            || options.RescanAge < TimeSpan.FromHours(1) || options.AdvisoryFetchMax < 0
            ? throw new InvalidOperationException(
                "OCI_SCAN_HEARTBEAT_WINDOW and OCI_SCAN_LEASE must be positive, OCI_SCAN_MAX_ATTEMPTS and "
                + "OCI_SCAN_RESCAN_AGE_HOURS at least 1, and OCI_SCAN_ADVISORY_FETCH_MAX at least 0.")
            : options;
    }

    private static bool ReadBool(IConfiguration config, string key, bool fallback)
    {
        string? raw = config[key];
        return string.IsNullOrWhiteSpace(raw)
            ? fallback
            : bool.TryParse(raw, out bool value)
            ? value
            : throw new InvalidOperationException($"{key} must be true or false, got '{raw}'.");
    }

    private static TimeSpan ReadSpan(IConfiguration config, string key, TimeSpan fallback)
    {
        string? raw = config[key];
        return string.IsNullOrWhiteSpace(raw)
            ? fallback
            : TimeSpan.TryParse(raw, CultureInfo.InvariantCulture, out var value)
            ? value
            : throw new InvalidOperationException($"{key} must be a time span such as 00:10:00, got '{raw}'.");
    }

    /// <summary>
    /// The largest <c>OCI_SCAN_RESCAN_AGE_HOURS</c> accepted: 100 years. Far larger values would
    /// pass a TimeSpan bound and then overflow when the sweep subtracts the age from the clock.
    /// </summary>
    internal const int MaxRescanAgeHours = 876_000;

    // A whole number of hours. Zero and negatives come back as zero for the caller's range check;
    // a value over MaxRescanAgeHours fails here rather than overflowing the sweep's threshold.
    private static TimeSpan ReadHours(IConfiguration config, string key, int fallback)
    {
        int hours = ReadInt(config, key, fallback);
        return hours > MaxRescanAgeHours
            ? throw new InvalidOperationException($"{key} may be at most {MaxRescanAgeHours} (100 years), got '{config[key]}'.")
            : TimeSpan.FromHours(Math.Max(hours, 0));
    }

    private static int ReadInt(IConfiguration config, string key, int fallback)
    {
        string? raw = config[key];
        return string.IsNullOrWhiteSpace(raw)
            ? fallback
            : int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value)
            ? value
            : throw new InvalidOperationException($"{key} must be an integer, got '{raw}'.");
    }
}
