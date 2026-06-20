using Dependably.Configuration;
using Dependably.Infrastructure;
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

    public UpstreamRegistryController(
        UpstreamRegistryRepository registries,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems)
    {
        _registries = registries;
        _guard = guard;
        _audit = audit;
        _problems = problems;
    }

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
            return _problems.ValidationErrorAction(
                "ecosystem",
                $"Must be one of: {string.Join(", ", UpstreamRegistryRepository.SupportedEcosystems)}.");
        }

        string orgId = CurrentTenantId();

        return ecosystem == "oci"
            ? await AddOciAsync(orgId, req, ct)
            : await AddNonOciAsync(orgId, ecosystem, req, ct);
    }

    private async Task<IActionResult> AddNonOciAsync(
        string orgId, string ecosystem, AddUpstreamRegistryRequest req, CancellationToken ct)
    {
        // OCI-only fields must not appear on non-OCI requests.
        if (req.AuthType is not null || req.Prefixes is not null || req.TokenEndpoint is not null
            || req.Secret is not null)
        {
            return _problems.ValidationErrorAction(
                "authType",
                "Fields authType, prefixes, tokenEndpoint, and secret are only valid for ecosystem=oci.");
        }

        string? url = req.Url?.Trim();
        string? urlProblem = UpstreamUrlValidator.ValidateUrl(url);
        if (urlProblem is not null)
        {
            return _problems.ValidationErrorAction("url", urlProblem);
        }

        string? name = string.IsNullOrWhiteSpace(req.Name) ? null : req.Name.Trim();
        var entry = await _registries.AddAsync(orgId, ecosystem, url!, name, ct);

        await _audit.LogAsync("upstream_registry_added", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem = entry.Ecosystem,
                url = entry.Url,
                name = entry.Name,
            }), ct: ct);

        return CreatedAtAction(nameof(List), null, entry);
    }

    private async Task<IActionResult> AddOciAsync(
        string orgId, AddUpstreamRegistryRequest req, CancellationToken ct)
    {
        // Host is required for OCI (stored in the url column).
        string host = (req.Url ?? req.Host ?? "").Trim();
        if (string.IsNullOrEmpty(host))
        {
            return _problems.ValidationErrorAction("url", "Host is required for OCI upstreams.");
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
            return _problems.ValidationErrorAction("prefixes", "At least one prefix is required for OCI upstreams.");
        }

        // Parse and validate auth_type. aws_ecr is not yet implemented; reject it explicitly.
        OciAuthType authType;
        switch ((req.AuthType ?? "anonymous").ToLowerInvariant())
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
                return _problems.ValidationErrorAction(
                    "authType",
                    "AuthType 'aws_ecr' is not supported. Use 'basic' with a GetAuthorizationToken-derived password.");
            default:
                return _problems.ValidationErrorAction(
                    "authType",
                    "authType must be one of: anonymous, basic, dockerhub_token_exchange.");
        }

        // basic requires username + secret.
        if (authType == OciAuthType.Basic)
        {
            if (string.IsNullOrWhiteSpace(req.Username))
            {
                return _problems.ValidationErrorAction("username", "username is required for authType=basic.");
            }

            if (string.IsNullOrWhiteSpace(req.Secret))
            {
                return _problems.ValidationErrorAction("secret", "secret is required for authType=basic.");
            }
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
            }), ct: ct);

        return CreatedAtAction(nameof(List), null, entry);
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
            detail: System.Text.Json.JsonSerializer.Serialize(new { id }), ct: ct);

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
            return _problems.ValidationErrorAction(
                "ecosystem",
                $"Must be one of: {string.Join(", ", UpstreamRegistryRepository.SupportedEcosystems)}.");
        }

        var ids = req.Ids ?? [];
        string orgId = CurrentTenantId();
        await _registries.ReorderAsync(orgId, eco, ids, ct);

        await _audit.LogAsync("upstream_registry_reordered", orgId, GetUserId(),
            detail: System.Text.Json.JsonSerializer.Serialize(new { ecosystem = eco, ids }), ct: ct);

        return NoContent();
    }
}
