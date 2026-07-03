using Microsoft.Extensions.Options;

namespace Dependably.Configuration;

/// <summary>
/// Strongly typed configuration for the OCI proxy layer.
/// Bound from the <c>Oci</c> section in appsettings.json / env vars.
/// Upstream registry entries are stored per-org in the <c>upstream_registry</c> DB table,
/// not in this config object. The scalars here (timeouts, CatalogEnabled) remain config-driven.
/// </summary>
public sealed class OciOptions
{
    /// <summary>Short TTL for manifest lookups by tag (default 5 minutes).</summary>
    public TimeSpan ManifestTagTtl { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long to cache upstream Bearer tokens (default 55 minutes).</summary>
    public TimeSpan TokenCacheDuration { get; set; } = TimeSpan.FromMinutes(55);

    /// <summary>Total HTTP timeout for upstream calls (default 30 minutes for large layers).</summary>
    public TimeSpan UpstreamHttpTimeout { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Whether the /v2/_catalog endpoint is enabled (default false — admin only).</summary>
    public bool CatalogEnabled { get; set; }
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

        if (options.TokenCacheDuration <= TimeSpan.Zero)
        {
            errors.Add("Oci:TokenCacheDuration must be positive.");
        }

        if (options.UpstreamHttpTimeout <= TimeSpan.Zero)
        {
            errors.Add("Oci:UpstreamHttpTimeout must be positive.");
        }
    }
}
