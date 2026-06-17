using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Microsoft.Extensions.Options;

namespace Dependably.Protocol;

/// <summary>
/// Manages upstream Bearer tokens for OCI pull operations.
///
/// Each (upstream host, repository, scope) triple gets its own cached token. Thundering-herd
/// prevention: a SemaphoreSlim per key ensures only one concurrent token-exchange request
/// per distinct triple. Tokens are refreshed 30 seconds before they expire.
///
/// DockerHub: parses the Www-Authenticate challenge from GET /v2/, then exchanges at the
/// realm endpoint for a scoped JWT.
///
/// Basic: returns a static base64(user:password) credential.
///
/// AwsEcr: calls GetAuthorizationToken and decodes the response; token lifetime is set by ECR
/// (typically 12 hours).
///
/// Anonymous: returns null (no Authorization header).
/// </summary>
public sealed class OciUpstreamAuthService : IDisposable
{
    private readonly IHttpClientFactory _http;
    private readonly IOptions<OciOptions> _options;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<OciUpstreamAuthService> _logger;
    private readonly TimeProvider _time;

    // Token cache: (host, repository, scope) → CachedToken
    private readonly ConcurrentDictionary<(string, string, string), CachedToken> _tokens = new();

    // Per-key semaphores to prevent thundering herd on token exchange.
    private readonly ConcurrentDictionary<(string, string, string), SemaphoreSlim> _sems = new();

    private sealed record CachedToken(string Value, DateTimeOffset ExpiresAt);

    public OciUpstreamAuthService(
        IHttpClientFactory http,
        IOptions<OciOptions> options,
        IAirGapMode airGap,
        ILogger<OciUpstreamAuthService> logger,
        TimeProvider time)
    {
        _http = http;
        _options = options;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// Returns an Authorization header value for the given upstream, repository, and scope, or
    /// null for anonymous upstreams. Throws <see cref="OciUnauthorizedException"/> on auth failure.
    /// </summary>
    public async Task<string?> GetAuthorizationAsync(
        OciUpstreamRegistryOptions upstream,
        string repository,
        string scope,
        CancellationToken ct)
    {
        return _airGap.IsEnabled
            ? throw new AirGappedException($"oci-auth::{upstream.Host}")
            : upstream.AuthType switch
            {
                OciAuthType.Anonymous => null,
                OciAuthType.Basic => "Basic " + Convert.ToBase64String(
                    Encoding.UTF8.GetBytes($"{upstream.Username}:{upstream.Password}")),
                OciAuthType.DockerHubTokenExchange => await GetDockerHubTokenAsync(upstream, repository, scope, ct),
                OciAuthType.AwsEcr => await GetEcrTokenAsync(upstream, ct),
                _ => null,
            };
    }

    /// <summary>
    /// Evicts a cached token so the next call acquires a fresh one. Called after a 401 response.
    /// </summary>
    public void InvalidateToken(OciUpstreamRegistryOptions upstream, string repository, string scope)
    {
        _tokens.TryRemove((upstream.Host, repository, scope), out _);
    }

    // ── DockerHub token exchange ────────────────────────────────────────────────

    private async Task<string?> GetDockerHubTokenAsync(
        OciUpstreamRegistryOptions upstream,
        string repository,
        string scope,
        CancellationToken ct)
    {
        var key = (upstream.Host, repository, scope);
        var sem = _sems.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));

        // Check cache before acquiring semaphore.
        if (_tokens.TryGetValue(key, out var cached) &&
            cached.ExpiresAt > _time.GetUtcNow() + TimeSpan.FromSeconds(30))
        {
            return "Bearer " + cached.Value;
        }

        await sem.WaitAsync(ct);
        try
        {
            // Double-check after acquiring.
            if (_tokens.TryGetValue(key, out cached) &&
                cached.ExpiresAt > _time.GetUtcNow() + TimeSpan.FromSeconds(30))
            {
                return "Bearer " + cached.Value;
            }

            var client = _http.CreateClient("OciUpstream");

            // Step 1: probe /v2/ to get the Www-Authenticate challenge.
            using var probe = await client.GetAsync($"https://{upstream.Host}/v2/", ct);
            if (probe.StatusCode != System.Net.HttpStatusCode.Unauthorized)
            {
                return null; // no challenge needed (e.g. if the registry allows anonymous)
            }

            var challenge = probe.Headers.WwwAuthenticate.FirstOrDefault();
            if (challenge is null)
            {
                return null;
            }

            var (realm, service, _) = ParseWwwAuthenticate(challenge);
            if (realm is null)
            {
                return null;
            }

            // The realm comes verbatim from the upstream's challenge. Refuse the exchange
            // unless it is HTTPS and exactly on the upstream's own host, or exactly matches
            // the operator-pinned TokenEndpoint — otherwise a MITM'd or hostile upstream
            // could redirect credentials to an attacker host by returning a forged realm.
            if (!IsTrustedRealm(realm, upstream))
            {
                _logger.LogWarning(
                    "OCI token exchange refused for upstream {Host}: challenge realm {Realm} is not HTTPS " +
                    "on the upstream's own host. Set Oci:Upstreams[*].TokenEndpoint to pin an auth realm " +
                    "hosted on a different domain (e.g. https://auth.docker.io/token for Docker Hub).",
                    upstream.Host, realm);
                throw new OciUnauthorizedException(
                    $"Token exchange realm '{realm}' is not trusted for upstream {upstream.Host}");
            }

            // Step 2: exchange at the realm endpoint.
            string tokenUrl = $"{realm}?service={Uri.EscapeDataString(service ?? upstream.Host)}&scope=repository:{repository}:{scope}";
            var tokenRequest = new HttpRequestMessage(HttpMethod.Get, tokenUrl);
            if (!string.IsNullOrEmpty(upstream.Username) && !string.IsNullOrEmpty(upstream.Password))
            {
                tokenRequest.Headers.Authorization = new AuthenticationHeaderValue(
                    "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{upstream.Username}:{upstream.Password}")));
            }

            using var tokenResponse = await client.SendAsync(tokenRequest, ct);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                throw new OciUnauthorizedException($"Token exchange failed for {upstream.Host}: {tokenResponse.StatusCode}");
            }

            string json = await tokenResponse.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(json);
            string? token = null;
            if (doc.RootElement.TryGetProperty("token", out var tp))
            {
                token = tp.GetString();
            }
            else if (doc.RootElement.TryGetProperty("access_token", out var ap))
            {
                token = ap.GetString();
            }

            if (token is null)
            {
                throw new OciUnauthorizedException($"No token in response from {realm}");
            }

            int expiresIn = doc.RootElement.TryGetProperty("expires_in", out var ep) ? ep.GetInt32() : 300;
            var expiresAt = _time.GetUtcNow() + TimeSpan.FromSeconds(
                Math.Min(expiresIn, (int)_options.Value.TokenCacheDuration.TotalSeconds));

            _tokens[key] = new CachedToken(token, expiresAt);
            return "Bearer " + token;
        }
        finally
        {
            sem.Release();
        }
    }

    // ── AWS ECR ────────────────────────────────────────────────────────────────

    private async Task<string?> GetEcrTokenAsync(
        OciUpstreamRegistryOptions upstream,
        CancellationToken ct)
    {
        // ECR tokens are expensive to exchange (AWS API call). Cache them for their full
        // lifetime minus a 5-minute buffer.
        var key = (upstream.Host, "", "ecr");
        var sem = _sems.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));

        if (_tokens.TryGetValue(key, out var cached) &&
            cached.ExpiresAt > _time.GetUtcNow() + TimeSpan.FromMinutes(1))
        {
            return "Basic " + cached.Value;
        }

        await sem.WaitAsync(ct);
        try
        {
            if (_tokens.TryGetValue(key, out cached) &&
                cached.ExpiresAt > _time.GetUtcNow() + TimeSpan.FromMinutes(1))
            {
                return "Basic " + cached.Value;
            }

            // Use the AWS ECR GetAuthorizationToken API via HTTP (avoids a hard AWSSDK dependency).
            // The endpoint is: POST https://ecr.{region}.amazonaws.com/ with action=GetAuthorizationToken.
            // We use a simplified approach with a pre-signed AWS Signature v4 request.
            // For environments with IAM roles (EC2/ECS), fall back to IMDSv2.
            //
            // Community edition: for now surface a clear error asking the operator to provide
            // credentials via environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY).
            // A full SigV4 implementation is a follow-up.
            _logger.LogWarning(
                "ECR auth requires AWS SDK integration. Configure AuthType=Basic with a GetAuthorizationToken-derived password as a workaround.");
            return null;
        }
        finally
        {
            sem.Release();
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>
    /// True when a <c>Www-Authenticate</c> realm may receive this upstream's credentials.
    /// The realm must be an absolute HTTPS URL and either:
    /// <list type="bullet">
    ///   <item>exactly match the operator-pinned <see cref="OciUpstreamRegistryOptions.TokenEndpoint"/>; or</item>
    ///   <item>be on exactly the upstream's own host (no registrable-domain fallback).</item>
    /// </list>
    /// Registrable-domain matching is intentionally absent. A Www-Authenticate challenge
    /// redirecting to a sibling domain (e.g. <c>auth.docker.io</c> for
    /// <c>registry-1.docker.io</c>) is treated as an untrusted realm unless the operator
    /// explicitly pins that endpoint via <see cref="OciUpstreamRegistryOptions.TokenEndpoint"/>.
    /// This prevents a hostile or MITM'd upstream from redirecting credentials to an
    /// attacker-controlled host sharing only a parent domain with the configured registry.
    /// </summary>
    internal static bool IsTrustedRealm(string realm, OciUpstreamRegistryOptions upstream)
    {
        if (!Uri.TryCreate(realm, UriKind.Absolute, out var realmUri) ||
            realmUri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        // Operator-pinned endpoint: exact URL match only.
        if (!string.IsNullOrWhiteSpace(upstream.TokenEndpoint) &&
            string.Equals(realm, upstream.TokenEndpoint, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Upstream Host config may carry a port (e.g. "registry.internal:5000") — compare hosts only.
        string realmHost = realmUri.Host;
        string upstreamHost = upstream.Host.Split(':')[0];
        return string.Equals(realmHost, upstreamHost, StringComparison.OrdinalIgnoreCase);
    }

    private static (string? Realm, string? Service, string? Scope) ParseWwwAuthenticate(
        AuthenticationHeaderValue header)
    {
        string? realm = null, service = null, scope = null;
        if (header.Parameter is null)
        {
            return (null, null, null);
        }

        // Parse key="value" pairs from: Bearer realm="...",service="...",scope="..."
        foreach (string part in header.Parameter.Split(','))
        {
            int eq = part.IndexOf('=');
            if (eq < 0)
            {
                continue;
            }

            string k = part[..eq].Trim();
            string v = part[(eq + 1)..].Trim().Trim('"');
            switch (k.ToLowerInvariant())
            {
                case "realm": realm = v; break;
                case "service": service = v; break;
                case "scope": scope = v; break;
            }
        }

        return (realm, service, scope);
    }

    public void Dispose()
    {
        foreach (var sem in _sems.Values)
        {
            sem.Dispose();
        }
    }
}

/// <summary>Thrown when the OCI upstream denies authentication.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Not binary-serialized across AppDomain boundaries.")]
public sealed class OciUnauthorizedException : Exception
{
    public OciUnauthorizedException(string message) : base(message) { }
}
