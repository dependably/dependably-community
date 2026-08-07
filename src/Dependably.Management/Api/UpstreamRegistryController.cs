using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Per-org upstream proxy registries, surfaced under Settings → Proxy. Each ecosystem owns a
/// priority-ordered list; the proxy fetch path tries entries top-to-bottom and an ecosystem
/// with no entries has proxying disabled. URLs pass the same SSRF guard
/// (<see cref="UpstreamUrlValidator"/>) used everywhere upstream URLs are accepted.
///
/// OCI upstreams use the same table but have a richer field set: auth_type, prefixes (for
/// repository-prefix routing), and an optional token_endpoint pin. The secret is write-only:
/// never returned in GET responses; callers see a computed <c>hasSecret</c> boolean instead.
/// </summary>
[ApiController]
[Authorize]
public sealed class UpstreamRegistryController : OrgScopedControllerBase
{
    private readonly UpstreamRegistryRepository _registries;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly EnvelopeProtector _envelope;
    private readonly IConfiguration _config;

    public UpstreamRegistryController(
        UpstreamRegistryRepository registries,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems,
        EnvelopeProtector envelope,
        IConfiguration config)
    {
        _registries = registries;
        _guard = guard;
        _audit = audit;
        _problems = problems;
        _envelope = envelope;
        _config = config;
    }

    // Instance-level opt-out that permits plaintext http:// upstreams. Default false: an http
    // upstream carries both the artifact and its declared checksum over the same cleartext
    // channel, so an on-path attacker substitutes both consistently and the content-addressing
    // invariant verifies bytes it never should have trusted.
    private bool AllowInsecureUpstreams =>
        _config.GetValue("Proxy:AllowInsecureUpstreams", defaultValue: false);

    /// <summary>GET /api/v1/orgs/{org}/upstream-registries</summary>
    [HttpGet("api/v1/upstream-registries")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        var entries = await _registries.ListAsync(CurrentTenantId(), ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/orgs/{org}/upstream-registries</summary>
    [HttpPost("api/v1/upstream-registries")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> Add([FromBody] AddUpstreamRegistryRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string ecosystem = req.Ecosystem?.Trim().ToLowerInvariant() ?? "";
        if (!UpstreamRegistryRepository.IsSupportedEcosystem(ecosystem))
        {
            return _problems.ValidationErrorActionKey("ecosystem", "error.common.mustBeOneOf", string.Join(", ", UpstreamRegistryRepository.SupportedEcosystems));
        }

        string orgId = CurrentTenantId();

        return ecosystem == "oci"
            ? await AddOciAsync(orgId, req, ct)
            : await AddNonOciAsync(orgId, ecosystem, req, ct);
    }

    private async Task<IActionResult> AddNonOciAsync(
        string orgId, string ecosystem, AddUpstreamRegistryRequest req, CancellationToken ct)
    {
        // Prefixes and tokenEndpoint are OCI-only (repository-prefix routing / token-exchange pin).
        if (req.Prefixes is not null || req.TokenEndpoint is not null)
        {
            return _problems.ValidationErrorActionKey("prefixes", "error.upstream.ociOnlyFields");
        }

        string? url = NormalizeUpstreamBaseUrl(ecosystem, req.Url?.Trim());
        // upstream_protocol is Terraform-only: every other ecosystem serves the same protocol it
        // fetches, so the field has nothing to discriminate and a stray value would silently do
        // nothing (ADR 0003).
        string? protocol = string.IsNullOrWhiteSpace(req.Protocol) ? null : req.Protocol.Trim().ToLowerInvariant();
        // Parse auth_type. Non-OCI supports anonymous (default), bearer (Authorization: Bearer
        // <secret>), and basic (Authorization: Basic base64(user:secret)).
        string authType = (req.AuthType ?? "anonymous").Trim().ToLowerInvariant();
        string? username = string.IsNullOrWhiteSpace(req.Username) ? null : req.Username.Trim();
        string? secret = string.IsNullOrWhiteSpace(req.Secret) ? null : req.Secret;

        var validationProblem = ValidateNonOciUrl(url)
            ?? ValidateNonOciRpmAuth(ecosystem, req)
            ?? ValidateNonOciProtocol(ecosystem, protocol)
            ?? ValidateNonOciAuthFields(authType, username, secret)
            ?? ValidateNonOciCredentialTransport(url, authType)
            ?? ValidateNonOciSecretPrecondition(secret);
        if (validationProblem is not null)
        {
            return validationProblem;
        }

        string? name = string.IsNullOrWhiteSpace(req.Name) ? null : req.Name.Trim();
        var entry = await _registries.AddAsync(
            orgId, new NewUpstreamRegistry(ecosystem, url!, name, authType, username, secret, Protocol: protocol), ct);

        // secret is write-only: log authType/hasSecret only, never the value.
        await _audit.LogAsync("upstream_registry_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = entry.Ecosystem,
                url = entry.Url,
                name = entry.Name,
                authType,
                hasSecret = entry.HasSecret,
                protocol = entry.Protocol,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);

        return CreatedAtAction(nameof(List), null, entry);
    }

    // Basic URL shape, plus: reject plaintext http:// upstreams unless the instance opts in. An
    // http upstream lets an on-path attacker rewrite the artifact and its declared checksum
    // together, defeating the proxy's content-addressing integrity story.
    private IActionResult? ValidateNonOciUrl(string? url)
    {
        string? urlProblem = UpstreamUrlValidator.ValidateUrl(url);
        return urlProblem is not null
            ? _problems.ValidationErrorAction("url", urlProblem)
            : !AllowInsecureUpstreams
                && Uri.TryCreate(url, UriKind.Absolute, out var schemeCheck)
                && schemeCheck.Scheme == Uri.UriSchemeHttp
                ? _problems.ValidationErrorActionKey("url", "error.upstream.httpsRequired")
                : null;
    }

    // RPM upstreams are anonymous-only for now (RPM mirrors are public distro repos and the
    // RPM proxy does not thread per-upstream credentials).
    private IActionResult? ValidateNonOciRpmAuth(string ecosystem, AddUpstreamRegistryRequest req) =>
        ecosystem == "rpm" && (req.AuthType is not null || req.Username is not null || req.Secret is not null)
            ? _problems.ValidationErrorActionKey("authType", "error.upstream.rpmAnonymousOnly")
            : null;

    private IActionResult? ValidateNonOciProtocol(string ecosystem, string? protocol) =>
        protocol is not null && ecosystem != "terraform"
            ? _problems.ValidationErrorActionKey("protocol", "error.upstream.protocolTerraformOnly")
            : !UpstreamRegistryRepository.IsSupportedProtocol(protocol)
                ? _problems.ValidationErrorActionKey(
                    "protocol", "error.upstream.protocolInvalid", UpstreamRegistryRepository.MirrorProtocol)
                : null;

    // Refuse to pair a credential with a plaintext http:// upstream — the envelope-encrypted
    // secret would transit the network in cleartext on every proxy miss. Anonymous http
    // upstreams (internal mirrors) stay allowed.
    private IActionResult? ValidateNonOciCredentialTransport(string? url, string authType) =>
        authType != "anonymous"
            && Uri.TryCreate(url, UriKind.Absolute, out var parsedUrl)
            && parsedUrl.Scheme == Uri.UriSchemeHttp
            ? _problems.ValidationErrorActionKey("url", "error.upstream.httpsRequiredForAuth")
            : null;

    // Fail closed: a secret can only be stored when the master key is configured (D275-1).
    private IActionResult? ValidateNonOciSecretPrecondition(string? secret) =>
        secret is not null && !_envelope.IsConfigured
            ? _problems.ValidationErrorActionKey("secret", "error.upstream.masterKeyRequired")
            : null;

    /// <summary>
    /// Normalizes an upstream base URL to the shape the proxy paths append onto.
    ///
    /// Every ecosystem's fetcher builds its URLs as <c>{base}/{something}</c>, so a stored trailing
    /// slash yields a double slash on every request. NuGet gets one more: its base is the v3
    /// SERVICE ROOT (<c>https://api.nuget.org/v3</c>), but the URL an operator has in hand — the
    /// one NuGet's own UI and docs show, and the one <c>nuget.config</c> takes — is the service
    /// index, <c>https://api.nuget.org/v3/index.json</c>. Pasting that produces
    /// <c>…/v3/index.json/registration5-semver1/…</c>, which 404s forever, and a permanent 404 on
    /// registration is invisible: the handler falls back to local-only data and serves a
    /// structurally valid document that simply omits every upstream version.
    ///
    /// Normalizing rather than rejecting: the operator's input is unambiguous about intent, and
    /// the two forms differ by a suffix the server can remove exactly.
    /// </summary>
    internal static string? NormalizeUpstreamBaseUrl(string ecosystem, string? url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return url;
        }

        string normalized = url.TrimEnd('/');
        const string ServiceIndexSuffix = "/index.json";
        if (ecosystem == "nuget" && normalized.EndsWith(ServiceIndexSuffix, StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[..^ServiceIndexSuffix.Length].TrimEnd('/');
        }

        // Never normalize a URL down to nothing — "https://" alone is malformed input the
        // validator below should reject on its own terms, not something to silently accept.
        return normalized.Length > 0 ? normalized : url;
    }

    // Validates the auth_type-specific field requirements for a non-OCI upstream registry.
    // Returns null when the fields are valid for the given auth_type.
    private IActionResult? ValidateNonOciAuthFields(string authType, string? username, string? secret)
    {
        switch (authType)
        {
            case "anonymous":
                return username is not null || secret is not null
                    ? _problems.ValidationErrorActionKey("authType", "error.upstream.anonymousNoCredentials")
                    : null;
            case "bearer":
                return secret is null
                    ? _problems.ValidationErrorActionKey("secret", "error.upstream.bearerSecretRequired")
                    : null;
            case "basic":
                if (username is null)
                {
                    return _problems.ValidationErrorActionKey("username", "error.upstream.basicUsernameRequired");
                }

                return secret is null
                    ? _problems.ValidationErrorActionKey("secret", "error.upstream.basicSecretRequired")
                    : null;
            default:
                return _problems.ValidationErrorActionKey("authType", "error.upstream.authTypeInvalid");
        }
    }

    private async Task<IActionResult> AddOciAsync(
        string orgId, AddUpstreamRegistryRequest req, CancellationToken ct)
    {
        // Host is required for OCI (stored in the url column).
        string host = (req.Url ?? req.Host ?? "").Trim();
        if (string.IsNullOrEmpty(host))
        {
            return _problems.ValidationErrorActionKey("url", "error.upstream.ociHostRequired");
        }

        // SSRF: validate the host by synthesising a full https:// URL.
        string? ssrfProblem = UpstreamUrlValidator.ValidateUrl($"https://{host}");
        if (ssrfProblem is not null)
        {
            return _problems.ValidationErrorAction("url", ssrfProblem);
        }

        // Prefixes are required and must be non-empty.
        if (req.Prefixes is null || req.Prefixes.Count == 0)
        {
            return _problems.ValidationErrorActionKey("prefixes", "error.upstream.ociPrefixRequired");
        }

        var (authType, authTypeProblem) = ParseOciAuthType(req.AuthType, req.Username, req.Secret);
        if (authTypeProblem is not null)
        {
            return authTypeProblem;
        }

        // Fail closed: OCI secrets are now encrypted at rest, so storing one requires the master
        // key (D275-1 retrofits OCI's previously-plaintext secrets to the same fail-closed posture).
        if (!string.IsNullOrWhiteSpace(req.Secret) && !_envelope.IsConfigured)
        {
            return _problems.ValidationErrorActionKey("secret", "error.upstream.masterKeyRequired");
        }

        string? name = string.IsNullOrWhiteSpace(req.Name) ? null : req.Name.Trim();
        var ociReq = new NewOciUpstreamRegistry(
            Host: host,
            AuthType: authType,
            Prefixes: req.Prefixes,
            Name: name,
            Username: string.IsNullOrWhiteSpace(req.Username) ? null : req.Username.Trim(),
            Secret: string.IsNullOrWhiteSpace(req.Secret) ? null : req.Secret,
            TokenEndpoint: string.IsNullOrWhiteSpace(req.TokenEndpoint) ? null : req.TokenEndpoint.Trim());

        var entry = await _registries.AddOciAsync(orgId, ociReq, ct);

        // secret is write-only: log authType/host/prefixes/hasSecret only.
        await _audit.LogAsync("upstream_registry_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = "oci",
                host,
                authType = UpstreamRegistryRepository.OciAuthTypeToString(authType),
                prefixes = req.Prefixes,
                hasSecret = entry.HasSecret,
                name,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);

        return CreatedAtAction(nameof(List), null, entry);
    }

    // Parses and validates the OCI auth_type plus its required companion fields (username/secret
    // for "basic"). aws_ecr is not yet implemented and is rejected explicitly. Returns the parsed
    // enum with a null problem on success; the problem is non-null on any validation failure.
    private (OciAuthType AuthType, IActionResult? Problem) ParseOciAuthType(
        string? rawAuthType, string? username, string? secret)
    {
        OciAuthType authType;
        switch ((rawAuthType ?? "anonymous").ToLowerInvariant())
        {
            case "anonymous":
                authType = OciAuthType.Anonymous;
                break;
            case "basic":
                authType = OciAuthType.Basic;
                break;
            case "dockerhub_token_exchange":
                authType = OciAuthType.DockerHubTokenExchange;
                break;
            case "aws_ecr":
                return (OciAuthType.Anonymous, _problems.ValidationErrorActionKey("authType", "error.upstream.awsEcrUnsupported"));
            default:
                return (OciAuthType.Anonymous, _problems.ValidationErrorActionKey("authType", "error.upstream.ociAuthTypeInvalid"));
        }

        if (authType == OciAuthType.Basic)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return (authType, _problems.ValidationErrorActionKey("username", "error.upstream.basicUsernameRequired"));
            }

            if (string.IsNullOrWhiteSpace(secret))
            {
                return (authType, _problems.ValidationErrorActionKey("secret", "error.upstream.basicSecretRequired"));
            }
        }

        return (authType, null);
    }

    /// <summary>DELETE /api/v1/orgs/{org}/upstream-registries/{id}</summary>
    [HttpDelete("api/v1/upstream-registries/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string orgId = CurrentTenantId();
        await _registries.DeleteAsync(orgId, id, ct);

        await _audit.LogAsync("upstream_registry_removed", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { id }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);

        return NoContent();
    }

    /// <summary>
    /// PUT /api/v1/orgs/{org}/upstream-registries/{id}/symbol-server
    ///
    /// Sets or clears a NuGet upstream's symbol-server base URL. An absent or empty
    /// <c>symbolServerUrl</c> CLEARS it, switching symbol proxying off for that upstream — the
    /// fail-closed state. Clearing is an explicit operator action precisely so the nuget.org seed
    /// cannot silently reinstate it on the next boot.
    /// </summary>
    [HttpPut("api/v1/upstream-registries/{id}/symbol-server")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> SetSymbolServer(
        string id, [FromBody] SetSymbolServerRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string? url = string.IsNullOrWhiteSpace(req.SymbolServerUrl) ? null : req.SymbolServerUrl.Trim();
        if (url is not null)
        {
            // A symbol server is fetched server-side, so an operator-supplied URL here is an SSRF
            // primitive exactly like an upstream base URL — same validation, same http opt-in.
            string? urlProblem = UpstreamUrlValidator.ValidateUrl(url);
            if (urlProblem is not null)
            {
                return _problems.ValidationErrorAction("symbolServerUrl", urlProblem);
            }

            if (!AllowInsecureUpstreams
                && Uri.TryCreate(url, UriKind.Absolute, out var schemeCheck)
                && schemeCheck.Scheme == Uri.UriSchemeHttp)
            {
                return _problems.ValidationErrorActionKey("symbolServerUrl", "error.upstream.httpsRequired");
            }
        }

        string orgId = CurrentTenantId();
        await _registries.SetSymbolServerUrlAsync(orgId, id, url, ct);

        await _audit.LogAsync("upstream_registry_symbol_server_set", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(
                new { id, cleared = url is null },
                Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);

        return NoContent();
    }

    /// <summary>PUT /api/v1/orgs/{org}/upstream-registries/{ecosystem}/order</summary>
    [HttpPut("api/v1/upstream-registries/{ecosystem}/order")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Reorder(
        string ecosystem, [FromBody] ReorderUpstreamRegistryRequest req, CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (result is not null)
        {
            return result;
        }

        string eco = ecosystem?.Trim().ToLowerInvariant() ?? "";
        if (!UpstreamRegistryRepository.IsSupportedEcosystem(eco))
        {
            return _problems.ValidationErrorActionKey("ecosystem", "error.common.mustBeOneOf", string.Join(", ", UpstreamRegistryRepository.SupportedEcosystems));
        }

        var ids = req.Ids ?? [];
        string orgId = CurrentTenantId();
        await _registries.ReorderAsync(orgId, eco, ids, ct);

        await _audit.LogAsync("upstream_registry_reordered", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { ecosystem = eco, ids }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail), ct: ct);

        return NoContent();
    }
}
