using Microsoft.Extensions.Options;

namespace Dependably.Configuration;

/// <summary>
/// Strongly typed configuration for OCI upstream proxy.
/// Bound from <c>Oci</c> section in appsettings.json / env vars.
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

    /// <summary>Upstream registry entries in prefix-match order (first match wins).</summary>
    public List<OciUpstreamRegistryOptions> Upstreams { get; set; } = [];
}

/// <summary>
/// Per-upstream-registry configuration entry.
/// </summary>
public sealed class OciUpstreamRegistryOptions
{
    /// <summary>Human-readable label (e.g. "dockerhub", "ghcr", "ecr-prod").</summary>
    public string Name { get; set; } = "";

    /// <summary>Upstream host (e.g. "registry-1.docker.io", "ghcr.io").</summary>
    public string Host { get; set; } = "";

    /// <summary>Authentication mechanism for this upstream.</summary>
    public OciAuthType AuthType { get; set; } = OciAuthType.Anonymous;

    /// <summary>Basic/token exchange username (AuthType=Basic or DockerHubTokenExchange with rate-limit budget).</summary>
    public string? Username { get; set; }

    /// <summary>Basic/token exchange password or personal access token.</summary>
    public string? Password { get; set; }

    /// <summary>
    /// Operator-pinned token-exchange endpoint (AuthType=DockerHubTokenExchange). The
    /// <c>Www-Authenticate</c> realm presented by the upstream must be HTTPS and live on the
    /// upstream's own host or registrable domain before credentials are attached; set this to
    /// the exact realm URL (e.g. <c>https://auth.example.net/token</c>) to allow a registry
    /// whose auth realm is hosted on an unrelated domain.
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>AWS region for ECR (AuthType=AwsEcr).</summary>
    public string? AwsRegion { get; set; }

    /// <summary>AWS access key ID for ECR (AuthType=AwsEcr). Falls back to instance role credentials when null.</summary>
    public string? AwsAccessKeyId { get; set; }

    /// <summary>AWS secret access key for ECR (AuthType=AwsEcr). Falls back to instance role credentials when null.</summary>
    public string? AwsSecretAccessKey { get; set; }

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

    /// <summary>AWS ECR GetAuthorizationToken-based token exchange.</summary>
    AwsEcr,
}

/// <summary>
/// Startup validator for <see cref="OciOptions"/>. Rejects invalid configurations before
/// the first request can reach the proxy path.
/// </summary>
public sealed class OciOptionsValidator : IValidateOptions<OciOptions>
{
    public ValidateOptionsResult Validate(string? name, OciOptions options)
    {
        var errors = new List<string>();
        ValidateTimeSpans(options, errors);
        for (int i = 0; i < options.Upstreams.Count; i++)
        {
            ValidateUpstream(options.Upstreams[i], i, errors);
        }

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

    private static void ValidateUpstream(OciUpstreamRegistryOptions u, int i, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(u.Name))
        {
            errors.Add($"Oci:Upstreams[{i}].Name is required.");
        }

        if (string.IsNullOrWhiteSpace(u.Host))
        {
            errors.Add($"Oci:Upstreams[{i}].Host is required.");
        }

        if (u.AuthType == OciAuthType.Basic)
        {
            ValidateBasicAuth(u, i, errors);
        }

        if (u.AuthType == OciAuthType.AwsEcr && string.IsNullOrWhiteSpace(u.AwsRegion))
        {
            errors.Add($"Oci:Upstreams[{i}] AuthType=AwsEcr requires AwsRegion.");
        }
    }

    private static void ValidateBasicAuth(OciUpstreamRegistryOptions u, int i, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(u.Username))
        {
            errors.Add($"Oci:Upstreams[{i}] AuthType=Basic requires Username.");
        }

        if (string.IsNullOrWhiteSpace(u.Password))
        {
            errors.Add($"Oci:Upstreams[{i}] AuthType=Basic requires Password.");
        }
    }
}
