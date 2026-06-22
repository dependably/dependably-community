namespace Dependably.Infrastructure;

/// <summary>
/// Reports whether the deployment is configured air-gapped. When true, every upstream
/// fetch path returns a clear error rather than timing out, the proxy cache is never written,
/// and the OSV scanner runs against a local mirror only.
///
/// Configured via the <c>AIR_GAPPED</c> environment variable. Read once at startup; the
/// setting does not change at runtime.
///
/// <c>DISABLE_BACKGROUND_JOBS</c> allows disabling individual background workers
/// (comma-separated job names) without full air-gap mode. <see cref="IsJobDisabled"/> merges
/// both signals — a full air-gap suppresses all outbound jobs, and individual names in
/// <see cref="DisabledJobs"/> suppress specific ones in any deployment mode.
/// </summary>
public interface IAirGapMode
{
    bool IsEnabled { get; }
    IReadOnlySet<string> DisabledJobs { get; }
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
            "threat-feed",
            "deprecation-refresh",
            "healthcheck-pinger",
            "cache-eviction",
            "retention",
            "orphan-reconciler",
            "oci-staging-janitor",
            "tenant-hard-delete",
            "blob-size-poller",
            "tenant-count-poller",
            "stats-refresh",
            "saml-cert-expiry",
        };
}

public sealed class AirGapMode : IAirGapMode
{
    // Delegates to the shared registry so DISABLE_BACKGROUND_JOBS validation stays in sync
    // with any new jobs registered in BackgroundJobs.Known.
    private static readonly IReadOnlySet<string> KnownJobNames = BackgroundJobs.Known;

    public bool IsEnabled { get; }
    public IReadOnlySet<string> DisabledJobs { get; }

    public AirGapMode(IConfiguration config, ILogger<AirGapMode>? logger = null)
    {
        string? raw = config["AIR_GAPPED"];
        IsEnabled = string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase);

        string disableRaw = config["DISABLE_BACKGROUND_JOBS"] ?? "";
        var parsed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string token in disableRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!KnownJobNames.Contains(token))
            {
                logger?.LogWarning("DISABLE_BACKGROUND_JOBS contains unknown job name '{JobName}'. Known names: {KnownNames}",
                    token, string.Join(", ", KnownJobNames));
            }

            parsed.Add(token);
        }
        DisabledJobs = parsed;

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
        IsEnabled || DisabledJobs.Contains(jobName);
}
