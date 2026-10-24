namespace Dependably.Infrastructure;

/// <summary>
/// Reports whether the deployment is configured air-gapped. When true, every upstream
/// fetch path returns a clear error rather than timing out, the proxy cache is never written,
/// and the OSV scanner runs against a local mirror only.
///
/// Configured via the <c>AIR_GAPPED</c> environment variable. Read once at startup; the
/// setting does not change at runtime.
///
/// <c>DISABLE_BACKGROUND_JOBS</c> disables background workers without full air-gap mode: either
/// every job (<c>true</c>), or a comma-separated list of job names (parsed by
/// <see cref="DisableBackgroundJobsSetting"/>, which fails startup on an unrecognised value).
/// <see cref="IsJobDisabled"/> merges four signals — a full air-gap and the whole-set switch each
/// suppress every job except the local housekeeping jobs in
/// <see cref="BackgroundJobs.HousekeepingExemptFromWholeSet"/> (and air-gap alone also spares the
/// database-only jobs in <see cref="BackgroundJobs.AirGapExempt"/>), individual names in <see cref="DisabledJobs"/> suppress
/// specific ones in any deployment mode, and edge mode (<c>DEPLOYMENT_MODE=edge</c>) force-disables
/// every job outside the cache-only allowlist (<see cref="BackgroundJobs.EdgeAllowed"/>) while
/// still honoring the operator's switch and named entries on top.
/// </summary>
public interface IAirGapMode
{
    bool IsEnabled { get; }

    /// <summary>
    /// The jobs <c>DISABLE_BACKGROUND_JOBS</c> disables. Under the whole-set switch this is
    /// <see cref="BackgroundJobs.DisabledByWholeSet"/>; <see cref="IsJobDisabled"/> is the
    /// authority, because it also covers a job name the registry does not list.
    /// </summary>
    IReadOnlySet<string> DisabledJobs { get; }

    /// <summary>
    /// True when <c>DISABLE_BACKGROUND_JOBS</c> switches off the whole job set (<c>true</c>,
    /// <c>1</c> or <c>all</c>) rather than naming jobs. A reporting signal: enforcement reads
    /// <see cref="IsJobDisabled"/>.
    /// </summary>
    bool DisablesAllJobs => false;

    bool IsJobDisabled(string jobName);
}

/// <summary>
/// Canonical registry of all background job names used across <see cref="AirGapMode"/>
/// and <see cref="Dependably.Infrastructure.Health.HealthService"/>. A job that writes
/// <c>background_job_runs</c> rows should also appear in
/// <see cref="Health.HealthService.RunRowJobs"/>.
/// </summary>
internal static class BackgroundJobs
{
    internal static readonly IReadOnlySet<string> Known =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "vuln-scan",
            "vuln-rescan",
            "sbom-scan",
            "threat-feed",
            "deprecation-refresh",
            "healthcheck-pinger",
            "cache-eviction",
            "retention",
            "orphan-reconciler",
            "oci-staging-janitor",
            "oci-reference-graph-backfill",
            "oci-blob-sweep",
            "oci-scan-sweep",
            "tenant-hard-delete",
            "blob-size-poller",
            "tenant-count-poller",
            "stats-refresh",
            "saml-cert-expiry",
            "license-backfill",
            "npm-manifest-rescan",
            "usage-rollup-hourly",
            "usage-rollup-daily",
            "usage-storage-snapshot",
            "usage-reconcile-weekly",
            "cache-size-alert",
        };

    /// <summary>
    /// The only background jobs a headless edge node runs. Edge mode is an allowlist inversion of
    /// the <c>DISABLE_BACKGROUND_JOBS</c> denylist: everything in <see cref="Known"/> that is NOT
    /// in this set is force-disabled. A cache node needs only disk-bounding, staging cleanup, the
    /// size gauge, and the healthcheck ping — all the tenant-management, scanning, and refresh
    /// jobs are inert on a node that creates nothing authoritative.
    ///
    /// <para>One deliberate exception, because a job name gates a job's <i>outbound</i> half only:
    /// <c>sbom-scan</c> disables OSV scanning, and the same pass's local SBOM policy re-evaluation
    /// keeps running. That half reads stored components, stored advisory rows and the tenant's own
    /// settings and makes no network call, so neither air-gap nor edge mode has a reason to stop
    /// it — and stopping it would freeze a security verdict rather than suppress a request. On an
    /// edge node the projects tables are dormant, so it costs one query returning no rows.</para>
    /// </summary>
    internal static readonly IReadOnlySet<string> EdgeAllowed =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cache-eviction",
            "oci-staging-janitor",
            "blob-size-poller",
            "healthcheck-pinger",
        };

    /// <summary>
    /// Local jobs that <c>AIR_GAPPED=true</c> and the whole-set switch
    /// (<c>DISABLE_BACKGROUND_JOBS=true</c>) leave running. None makes an outbound call, and
    /// stopping the disk-bounding ones would not reduce egress: it would leave the proxy cache and
    /// the staging volume growing without bound. <c>npm-manifest-rescan</c> is a one-shot pass over
    /// stored npm tarballs that reads local blobs and the database only; stopping it would leave a
    /// tarball with several top-level manifests unflagged for the install-script and licence gates.
    /// Naming one in a <c>DISABLE_BACKGROUND_JOBS</c> list still stops it, because that is an
    /// explicit operator decision about that job.
    /// </summary>
    internal static readonly IReadOnlySet<string> HousekeepingExemptFromWholeSet =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cache-eviction",
            "oci-staging-janitor",
            "npm-manifest-rescan",
        };

    /// <summary>
    /// Jobs that <c>AIR_GAPPED=true</c> leaves running because they make no outbound call at all.
    /// Unlike <see cref="HousekeepingExemptFromWholeSet"/>, the whole-set switch
    /// (<c>DISABLE_BACKGROUND_JOBS=true</c>), a named entry and edge mode still stop them.
    ///
    /// <para><c>oci-scan-sweep</c> reads and writes the database only. Its point under air-gap is
    /// the rematch: an air-gapped scanner matches against sideloaded OSV dumps, and without a
    /// periodic rematch an image would keep the verdict of the dumps it was first scanned
    /// against. A re-extraction it queues that needs an evicted proxied blob reaches
    /// <c>OciUpstreamResolver</c>, which refuses under air-gap before any fetch.</para>
    /// </summary>
    internal static readonly IReadOnlySet<string> AirGapExempt =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "oci-scan-sweep",
        };

    /// <summary>
    /// The jobs the whole-set switch disables: every <see cref="Known"/> job except
    /// <see cref="HousekeepingExemptFromWholeSet"/>.
    /// </summary>
    internal static readonly IReadOnlySet<string> DisabledByWholeSet =
        new HashSet<string>(Known.Except(HousekeepingExemptFromWholeSet, StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);
}

public sealed class AirGapMode : IAirGapMode
{
    public bool IsEnabled { get; }
    public IReadOnlySet<string> DisabledJobs { get; }
    public bool DisablesAllJobs { get; }

    // True when DEPLOYMENT_MODE=edge — flips IsJobDisabled from a pure denylist to an
    // allowlist inversion (only BackgroundJobs.EdgeAllowed run; every other Known job is off).
    private readonly bool _isEdge;

    /// <exception cref="InvalidOperationException">
    /// <c>DISABLE_BACKGROUND_JOBS</c> holds a value <see cref="DisableBackgroundJobsSetting"/> does
    /// not recognise; the host does not start.
    /// </exception>
    public AirGapMode(IConfiguration config, ILogger<AirGapMode>? logger = null)
    {
        string? raw = config["AIR_GAPPED"];
        IsEnabled = string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase);

        _isEdge = string.Equals(
            (config["DEPLOYMENT_MODE"] ?? "single").Trim(),
            "edge",
            StringComparison.OrdinalIgnoreCase);

        var disabled = DisableBackgroundJobsSetting.FromConfiguration(config);
        DisablesAllJobs = disabled.AllJobs;
        DisabledJobs = disabled.Names;

        if (DisablesAllJobs)
        {
            logger?.LogInformation(
                "DISABLE_BACKGROUND_JOBS disables every background job except the local housekeeping jobs " +
                "{HousekeepingJobs}. Request-time upstream fetches are not affected; set AIR_GAPPED=true to " +
                "stop those too.",
                string.Join(", ", BackgroundJobs.HousekeepingExemptFromWholeSet.Order(StringComparer.Ordinal)));
        }

        if (IsEnabled)
        {
            string? osvMode = config["OSV_MODE"];
            if (!string.Equals(osvMode, "local", StringComparison.OrdinalIgnoreCase))
            {
                logger?.LogWarning(
                    "AIR_GAPPED=true but OSV_MODE is not set to 'local' (current: '{OsvMode}'). " +
                    "Set OSV_MODE=local to prevent outbound OSV.dev requests.",
                    string.IsNullOrWhiteSpace(osvMode) ? "(not set)" : osvMode);
            }
        }
    }

    public bool IsJobDisabled(string jobName) =>
        // The explicit list disables named jobs in any mode. Air-gap and the whole-set switch
        // disable every job, named or not, except the local housekeeping jobs that bound disk use;
        // air-gap alone also spares the database-only jobs in AirGapExempt. Edge mode additionally
        // force-disables everything outside the cache-only allowlist; the operator's switch and
        // named entries still add on top of it.
        DisabledJobs.Contains(jobName)
        || (IsEnabled && !BackgroundJobs.HousekeepingExemptFromWholeSet.Contains(jobName)
            && !BackgroundJobs.AirGapExempt.Contains(jobName))
        || (DisablesAllJobs && !BackgroundJobs.HousekeepingExemptFromWholeSet.Contains(jobName))
        || (_isEdge && !BackgroundJobs.EdgeAllowed.Contains(jobName));
}

/// <summary>
/// The <c>disabled_reason</c> reported for a background job on the instance surface. One label
/// per cause, in precedence order, so an operator can tell which setting to change.
/// </summary>
public static class BackgroundJobDisabledReason
{
    public const string AirGapped = "AIR_GAPPED=true";
    public const string AllJobs = "DISABLE_BACKGROUND_JOBS=true";
    public const string Named = "DISABLE_BACKGROUND_JOBS";
    public const string Edge = "DEPLOYMENT_MODE=edge";

    /// <summary>Null when the job runs.</summary>
    public static string? For(IAirGapMode airGap, string jobName)
    {
        ArgumentNullException.ThrowIfNull(airGap);
        bool wholeSetApplies = !BackgroundJobs.HousekeepingExemptFromWholeSet.Contains(jobName);
        return !airGap.IsJobDisabled(jobName) ? null
            : airGap.IsEnabled && wholeSetApplies && !BackgroundJobs.AirGapExempt.Contains(jobName) ? AirGapped
            : airGap.DisablesAllJobs && wholeSetApplies ? AllJobs
            : airGap.DisabledJobs.Contains(jobName) ? Named
            : Edge;
    }
}
