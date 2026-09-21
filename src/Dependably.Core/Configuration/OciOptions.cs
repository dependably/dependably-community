using Microsoft.Extensions.Options;

namespace Dependably.Configuration;

/// <summary>
/// Strongly typed configuration for the OCI proxy layer.
/// Bound from the <c>Oci</c> section in appsettings.json / env vars.
/// Upstream registry entries are stored per-org in the <c>upstream_registry</c> DB table,
/// not in this config object. The scalars here (timeouts) remain config-driven.
/// </summary>
public sealed class OciOptions
{
    /// <summary>
    /// How long a tag → digest mapping may be served before upstream is asked again
    /// (default 1 hour). Moving tags rebuild on the order of days or weeks, so hourly
    /// revalidation is ample while cutting upstream round-trips (and Docker Hub 429
    /// exposure) roughly 12× versus a 5-minute cadence. The TTL answers only "when do we
    /// ask again" — whether a newly observed digest is *promoted* is governed separately
    /// by the org's <c>min_release_age_hours</c>, and how long a stale answer may be
    /// served through an upstream outage by <see cref="ManifestTagStaleGrace"/>. The
    /// three policies compose; they do not stack into a delay.
    /// </summary>
    public TimeSpan ManifestTagTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long past its TTL a tag's last accepted digest may still be served while the
    /// upstream is unavailable (default 24 hours). Within the grace window an upstream
    /// 429/5xx/timeout serves the previously accepted digest (audited, marked
    /// <c>X-Cache: STALE</c>) instead of failing the pull; past it the pull fails 502.
    /// The window is measured from the moment the entry became stale
    /// (<c>last_revalidated + ManifestTagTtl</c>) and is never extended by further failed
    /// revalidation attempts — otherwise a long outage would silently become
    /// serve-stale-forever.
    /// </summary>
    public TimeSpan ManifestTagStaleGrace { get; set; } = TimeSpan.FromHours(24);

    /// <summary>How long to cache upstream Bearer tokens (default 55 minutes).</summary>
    public TimeSpan TokenCacheDuration { get; set; } = TimeSpan.FromMinutes(55);

    /// <summary>Total HTTP timeout for upstream calls (default 30 minutes for large layers).</summary>
    public TimeSpan UpstreamHttpTimeout { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Largest single blob this registry will proxy from an upstream (default 10 GiB).
    ///
    /// <para>
    /// The OCI plane needs its own bound because it is the one ecosystem whose unit of transfer
    /// is an image layer: a CUDA or ML base image routinely ships a single layer several
    /// gigabytes wide, where a metadata document or an npm tarball does not. Sizing it here
    /// rather than raising <c>UpstreamClient.MaxUpstreamResponseBytes</c> keeps every other
    /// ecosystem's fetch bound tight — that constant is shared, so raising it would widen paths
    /// that have no reason to accept a gigabyte.
    /// </para>
    ///
    /// <para>
    /// This is a disk bound, not a memory one: the blob proxy streams upstream bytes straight
    /// into the cache-tier blob store through <see cref="Dependably.Protocol.OciDigestVerifyStream"/>
    /// and never buffers a whole layer. Raising it commits cache-tier storage
    /// (<c>LOCAL_STORAGE_PATH_CACHE</c> and the eviction settings that govern it), not process
    /// memory. It is deliberately still bounded rather than unlimited, so a hostile or
    /// misreporting upstream cannot stream without end into the cache volume.
    /// </para>
    /// </summary>
    public long MaxBlobProxyBytes { get; set; } = 10L * 1024 * 1024 * 1024;

}

/// <summary>
/// Runtime descriptor for one OCI upstream registry entry. Used as the DTO between
/// <see cref="Dependably.Infrastructure.UpstreamRegistryRepository.BuildOciUpstreamsForOrgAsync"/>
/// and <see cref="Dependably.Protocol.OciUpstreamAuthService"/> — not bound from config.
/// </summary>
public sealed class OciUpstreamRegistryOptions
{
    /// <summary>Human-readable label.</summary>
    public string Name { get; set; } = "";

    /// <summary>Upstream host (e.g. "registry-1.docker.io", "ghcr.io").</summary>
    public string Host { get; set; } = "";

    /// <summary>Authentication mechanism for this upstream.</summary>
    public OciAuthType AuthType { get; set; } = OciAuthType.Anonymous;

    /// <summary>Basic/token exchange username.</summary>
    public string? Username { get; set; }

    /// <summary>Basic/token exchange password or personal access token.</summary>
    public string? Password { get; set; }

    /// <summary>
    /// Operator-pinned token-exchange endpoint (AuthType=DockerHubTokenExchange). The
    /// <c>Www-Authenticate</c> realm presented by the upstream must be HTTPS and live on the
    /// upstream's own host before credentials are attached; set this to the exact realm URL
    /// (e.g. <c>https://auth.docker.io/token</c>) to allow a registry whose auth realm is
    /// hosted on an unrelated domain.
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// Repository name prefixes that route to this upstream (e.g. "library/", "ghcr.io/").
    /// An empty string "" is the catch-all fallback. First match wins.
    /// </summary>
    public List<string> Prefixes { get; set; } = [];
}

/// <summary>Authentication mechanism for an OCI upstream registry.</summary>
public enum OciAuthType
{
    /// <summary>No authentication — anonymous pulls (Docker Hub public images).</summary>
    Anonymous,

    /// <summary>HTTP Basic auth (static username+password).</summary>
    Basic,

    /// <summary>Docker Hub's token exchange flow (GET /token?service=registry.docker.io&amp;scope=...).</summary>
    DockerHubTokenExchange,

    /// <summary>
    /// AWS ECR GetAuthorizationToken-based token exchange. The enum arm is retained for
    /// future use but is rejected at the API controller layer — configure ECR via Basic
    /// with a GetAuthorizationToken-derived password in the meantime.
    /// </summary>
    AwsEcr,
}

/// <summary>
/// Startup validator for <see cref="OciOptions"/>. Validates the scalar timeouts only;
/// per-upstream-entry validation is performed at API time in the controller.
/// </summary>
public sealed class OciOptionsValidator : IValidateOptions<OciOptions>
{
    /// <summary>Smallest accepted <see cref="OciOptions.MaxBlobProxyBytes"/> (1 MiB).</summary>
    internal const long MinBlobProxyBytes = 1024L * 1024;


    public ValidateOptionsResult Validate(string? name, OciOptions options)
    {
        var errors = new List<string>();
        ValidateTimeSpans(options, errors);
        return errors.Count > 0
            ? ValidateOptionsResult.Fail(errors)
            : ValidateOptionsResult.Success;
    }

    private static void ValidateTimeSpans(OciOptions options, List<string> errors)
    {
        if (options.ManifestTagTtl <= TimeSpan.Zero)
        {
            errors.Add("Oci:ManifestTagTtl must be positive.");
        }

        if (options.ManifestTagStaleGrace <= TimeSpan.Zero)
        {
            errors.Add("Oci:ManifestTagStaleGrace must be positive.");
        }

        if (options.TokenCacheDuration <= TimeSpan.Zero)
        {
            errors.Add("Oci:TokenCacheDuration must be positive.");
        }

        if (options.UpstreamHttpTimeout <= TimeSpan.Zero)
        {
            errors.Add("Oci:UpstreamHttpTimeout must be positive.");
        }

        // A floor, not just a positivity check: a value below one layer's worth of bytes turns
        // the blob proxy into something that refuses every real image, and it fails at pull time
        // on the operator's users rather than here at startup. 1 MiB is far below any plausible
        // deliberate setting and far above the typo range (a value meant as MiB or GiB).
        if (options.MaxBlobProxyBytes < MinBlobProxyBytes)
        {
            errors.Add($"Oci:MaxBlobProxyBytes must be at least {MinBlobProxyBytes} bytes.");
        }
    }
}
