namespace Dependably.Infrastructure.Health;

/// <summary>
/// Classification and probe-cost policy for the readiness checks run by
/// <see cref="ReadinessAggregator"/>.
///
/// <para><b>Required (hard) vs reported (soft).</b> Every dependency probed by readiness is
/// shared by every replica of the deployment, so a failure is perfectly correlated across the
/// fleet: an object-store 5xx window or a cache failover makes all N replicas answer identically.
/// A load balancer that deregisters on those signals removes the entire fleet for a condition it
/// cannot route around, converting partial degradation into total outage. Only dependencies
/// whose loss leaves a replica unable to serve anything useful belong in the required set; the
/// rest are reported in the <c>/ready</c> body with their real status and left to alerting.</para>
///
/// <para><b>Defaults differ per plane.</b> On a full host the metadata store is the only required
/// dependency — without it no route resolves, while blob-store and Redis failures leave metadata
/// reads, index generation and cached-manifest serving working. A headless edge node exists to
/// serve artefact bytes out of its own (usually node-local) blob store, so blob storage is
/// load-bearing there and joins the required set; a node-local failure is also exactly the
/// uncorrelated, per-replica condition a load balancer *can* route around.</para>
///
/// <para>Operators override the classification wholesale with
/// <c>READINESS_HARD_DEPENDENCIES</c> (comma-separated check names) — for example
/// <c>db,blob_store,redis</c> restores the strict all-dependencies behaviour on every probe.
/// The strict view stays available regardless via <c>GET /ready?strict=true</c>, which demands
/// every check green and is what deployment gating and alerting should poll.</para>
/// </summary>
public sealed class ReadinessOptions
{
    /// <summary>Check name for the metadata store probe.</summary>
    public const string DbCheck = "db";

    /// <summary>Check name for the blob store probe.</summary>
    public const string BlobStoreCheck = "blob_store";

    /// <summary>Check name for the optional Redis probe.</summary>
    public const string RedisCheck = "redis";

    /// <summary>TTL applied to the blob-store probe result when unconfigured.</summary>
    public static readonly TimeSpan DefaultBlobProbeTtl = TimeSpan.FromSeconds(15);

    /// <summary>Upper bound accepted for <c>READINESS_BLOB_PROBE_TTL_SECONDS</c>.</summary>
    private static readonly TimeSpan MaxBlobProbeTtl = TimeSpan.FromMinutes(5);

    private readonly HashSet<string> _required;

    public ReadinessOptions(IEnumerable<string> requiredDependencies, TimeSpan blobProbeTtl)
    {
        _required = new HashSet<string>(requiredDependencies, StringComparer.OrdinalIgnoreCase);
        BlobProbeTtl = blobProbeTtl < TimeSpan.Zero ? TimeSpan.Zero
            : blobProbeTtl > MaxBlobProbeTtl ? MaxBlobProbeTtl
            : blobProbeTtl;
    }

    /// <summary>
    /// Check names whose failure makes the replica unready (<c>/ready</c> answers 503). Every
    /// other probed dependency is reported in the body but does not by itself fail the probe.
    /// </summary>
    public IReadOnlyCollection<string> RequiredDependencies => _required;

    /// <summary>
    /// How long a blob-store probe result (success or failure) is reused before the store is
    /// probed again. <see cref="TimeSpan.Zero"/> disables caching and probes on every call.
    /// </summary>
    public TimeSpan BlobProbeTtl { get; }

    /// <summary>True when a failure of <paramref name="check"/> must fail <c>/ready</c>.</summary>
    public bool IsRequired(string check) => _required.Contains(check);

    /// <summary>
    /// Builds the effective options from configuration. A null configuration (unit-test
    /// construction) yields the full-plane defaults.
    /// </summary>
    public static ReadinessOptions Resolve(IConfiguration? config)
    {
        bool edge = string.Equals(
            (config?["DEPLOYMENT_MODE"] ?? "single").Trim(),
            "edge",
            StringComparison.OrdinalIgnoreCase);

        string[] planeDefaults = edge ? [DbCheck, BlobStoreCheck] : [DbCheck];

        string? configured = config?["READINESS_HARD_DEPENDENCIES"];
        string[] required = string.IsNullOrWhiteSpace(configured)
            ? planeDefaults
            : configured.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var ttl = int.TryParse(config?["READINESS_BLOB_PROBE_TTL_SECONDS"], out int seconds) && seconds >= 0
            ? TimeSpan.FromSeconds(seconds)
            : DefaultBlobProbeTtl;

        return new ReadinessOptions(required, ttl);
    }
}
