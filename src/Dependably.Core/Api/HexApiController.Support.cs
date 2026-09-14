using System.Text;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Hex;
using Dependably.Infrastructure.Publish;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>The auth, negotiation and view helpers behind <see cref="HexApiController"/>.</summary>
public sealed partial class HexApiController
{
    private const string ErlangContentType = "application/vnd.hex+erlang";

    private readonly record struct ReadGate(string OrgId, TokenRecord? Token, IActionResult? Error);

    private readonly record struct HostedWriteGate(string OrgId, TokenRecord? Token, Package? Package, PackageVersion? Version, IActionResult? Error);

    private static bool RepoAliasOk(string? repo) => repo is null or HexIndexBuilder.RepositoryName;

    // A Hex API key rides in the Authorization header with no scheme, or as Bearer/Basic; every
    // form resolves through the shared resolver and a token from another org counts as none.
    private async Task<TokenRecord?> ResolveHexTokenAsync(string orgId, CancellationToken ct)
    {
        var token = await Request.ResolveTokenAsync(_svc.Tokens, ct);
        AuthDenialRecorder.RecordTenantMismatch(HttpContext, token, orgId, ecosystem: Ecosystem);
        return token is not null && token.OrgId == orgId ? token : null;
    }

    private async Task<ReadGate> AuthorizeReadAsync(string orgId, CancellationToken ct)
    {
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await ResolveHexTokenAsync(orgId, ct);
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"hex\"";
            return new ReadGate(orgId, null, Unauthorized());
        }

        if (token is not null && !token.HasCapability(Capabilities.ReadMetadata))
        {
            AuthDenialRecorder.RecordCapabilityDenied(
                HttpContext, token, required: Capabilities.ReadMetadata, ecosystem: Ecosystem, orgId: orgId);
            return new ReadGate(orgId, token, Error(StatusCodes.Status403Forbidden, "read:metadata capability required."));
        }

        return new ReadGate(orgId, token, null);
    }

    // Token, capability, and a hosted (not proxied) version of a valid coordinate, in that order,
    // so a caller without the capability learns nothing about which versions exist.
    private async Task<HostedWriteGate> AuthorizeHostedWriteAsync(
        string name, string version, string? repo, string capability, CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        if (!RepoAliasOk(repo) || !HexNaming.IsValidPackageName(name) || !HexNaming.IsValidVersion(version))
        {
            return new HostedWriteGate(orgId, null, null, null, NotFoundTerm());
        }

        var token = await ResolveHexTokenAsync(orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"hex\"";
            return new HostedWriteGate(orgId, null, null, null, Unauthorized());
        }

        if (!token.HasCapability(capability))
        {
            AuthDenialRecorder.RecordCapabilityDenied(
                HttpContext, token, required: capability, ecosystem: Ecosystem, orgId: orgId);
            return new HostedWriteGate(orgId, token, null, null, Error(StatusCodes.Status403Forbidden, $"{capability} capability required."));
        }

        var pkg = await _svc.Packages.GetByPurlNameAsync(orgId, Ecosystem, name, ct);
        var ver = pkg is null ? null : await _svc.Packages.GetVersionAsync(pkg.Id, version, ct);
        return ver is null || ver.Origin == "proxy"
            ? new HostedWriteGate(orgId, token, pkg, null, NotFoundTerm())
            : new HostedWriteGate(orgId, token, pkg, ver, null);
    }

    private async Task<byte[]?> ReadBodyBoundedAsync(long cap, CancellationToken ct)
    {
        var limited = new LimitedReadStream(Request.Body, cap, "hex request body");
        try
        {
            using var ms = new MemoryStream();
            await limited.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    // ── Content negotiation ──────────────────────────────────────────────────

    private static bool IsErlangContentType(string? contentType) =>
        contentType is not null && contentType.Contains("vnd.hex+erlang", StringComparison.OrdinalIgnoreCase);

    private bool ClientWantsErlang() =>
        Request.Headers.Accept.Any(a => a is not null && a.Contains("vnd.hex+erlang", StringComparison.OrdinalIgnoreCase));

    /// <summary>The body in the client's format: an Erlang term for hex_core, JSON for anyone else.</summary>
    private IActionResult Reply(int status, Dictionary<string, object?> body)
    {
        if (ClientWantsErlang())
        {
            Response.StatusCode = status;
            return File(ErlangTermFormat.Encode(body), ErlangContentType);
        }

        return new JsonResult(body) { StatusCode = status };
    }

    private IActionResult Error(int status, string message, Dictionary<string, object?>? errors = null)
    {
        var body = new Dictionary<string, object?> { ["status"] = status, ["message"] = message };
        if (errors is not null)
        {
            body["errors"] = errors;
        }

        return Reply(status, body);
    }

    private IActionResult NotFoundTerm() => Error(StatusCodes.Status404NotFound, "not found");

    private string BaseUrl() => $"{Request.Scheme}://{Request.Host}";

    // ── Views ────────────────────────────────────────────────────────────────

    private Dictionary<string, object?> PackageView(string name, IReadOnlyList<HexIndexedRelease> held)
    {
        string latest = held.Select(r => r.Version)
            .OrderByDescending(v => v, Comparer<string>.Create((a, b) => EcosystemVersionOrdering.Compare("hex", a, b) ?? string.CompareOrdinal(a, b)))
            .First();
        var retirements = new Dictionary<string, object?>();
        foreach (var r in held.Where(r => r.Facts.RetiredReason is not null))
        {
            retirements[r.Version] = new Dictionary<string, object?>
            {
                ["reason"] = HexReleaseRepository.ReasonToWire(r.Facts.RetiredReason!.Value),
                ["message"] = r.Facts.RetiredMessage,
            };
        }

        return new Dictionary<string, object?>
        {
            ["name"] = name,
            ["repository"] = HexIndexBuilder.RepositoryName,
            ["releases"] = held.Select(r => (object?)new Dictionary<string, object?>
            {
                ["version"] = r.Version,
                ["url"] = $"{BaseUrl()}/hex/api/packages/{name}/releases/{r.Version}",
                ["has_docs"] = r.Facts.HasDocs,
                ["inserted_at"] = r.PublishedAt?.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            }).ToList(),
            ["retirements"] = retirements,
            ["latest_version"] = latest,
            ["latest_stable_version"] = held.Select(r => r.Version).Where(v => !v.Contains('-'))
                .OrderByDescending(v => v, Comparer<string>.Create((a, b) => EcosystemVersionOrdering.Compare("hex", a, b) ?? string.CompareOrdinal(a, b)))
                .FirstOrDefault(),
            ["url"] = $"{BaseUrl()}/hex/api/packages/{name}",
            ["html_url"] = $"{BaseUrl()}/package/hex/{name}",
        };
    }

    private Dictionary<string, object?> ReleaseView(string name, HexIndexedRelease r)
    {
        var requirements = new Dictionary<string, object?>();
        foreach (var q in r.Facts.Requirements)
        {
            requirements[q.Name] = new Dictionary<string, object?>
            {
                ["requirement"] = q.Requirement,
                ["optional"] = q.Optional,
                ["app"] = q.App ?? q.Name,
            };
        }

        return new Dictionary<string, object?>
        {
            ["version"] = r.Version,
            ["checksum"] = r.OuterChecksumHex.ToLowerInvariant(),
            ["has_docs"] = r.Facts.HasDocs,
            ["meta"] = new Dictionary<string, object?>
            {
                ["app"] = r.Facts.App ?? name,
                ["build_tools"] = r.Facts.BuildTools.Select(b => (object?)b).ToList(),
                ["elixir"] = r.Facts.Elixir,
            },
            ["requirements"] = requirements,
            ["retirement"] = r.Facts.RetiredReason is { } reason
                ? new Dictionary<string, object?> { ["reason"] = HexReleaseRepository.ReasonToWire(reason), ["message"] = r.Facts.RetiredMessage }
                : null,
            ["inserted_at"] = r.PublishedAt?.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["updated_at"] = r.PublishedAt?.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["url"] = $"{BaseUrl()}/hex/api/packages/{name}/releases/{r.Version}",
            ["html_url"] = $"{BaseUrl()}/package/hex/{name}/{r.Version}",
            ["package_url"] = $"{BaseUrl()}/hex/api/packages/{name}",
        };
    }
}

/// <summary>Scoped DI bundle for the write half of the Hex API plane.</summary>
public sealed record HexApiControllerServices(
    IPackagePublishService Publish,
    EdgePublishGuard EdgeGuard,
    AuditRepository Audit,
    LicenseRepository Licenses,
    IUploadLimitResolver UploadLimits,
    IPackageEventSink EventSink,
    HexIdentityLookup Identity);
