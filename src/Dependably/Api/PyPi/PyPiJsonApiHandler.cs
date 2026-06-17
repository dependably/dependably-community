using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Handles GET /pypi/{package}/json and GET /pypi/{package}/{version}/json — the PyPI JSON API
/// endpoints. Synthesizes a local JSON document for hosted packages or proxies the upstream
/// document verbatim for proxy-only packages.
/// </summary>
public sealed class PyPiJsonApiHandler(
    OrgRepository orgs,
    PackageRepository packages,
    TokenRepository tokens,
    UpstreamClient upstream,
    ClaimResolver claimResolver,
    UpstreamRegistryResolver registries)
{
    // Serializer options for synthesized PyPI JSON documents — created once and reused so
    // every serialization shares the same cached type metadata.
    private static readonly JsonSerializerOptions CompactJsonOptions = new() { WriteIndented = false };

    public Task<IActionResult> PackageJsonAsync(
        HttpContext httpContext, string orgId, string package, CancellationToken ct)
        => PackageJsonCoreAsync(httpContext, orgId, package, version: null, ct);

    public Task<IActionResult> PackageVersionJsonAsync(
        HttpContext httpContext, string orgId, string package, string version, CancellationToken ct)
        => PackageJsonCoreAsync(httpContext, orgId, package, version, ct);

    private async Task<IActionResult> PackageJsonCoreAsync(
        HttpContext httpContext, string orgId, string package, string? version, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        string purlName = PurlNormalizer.PyPiName(package);

        if (!PathSafeValidator.ValidateUpstreamSegment(purlName, "package").IsValid)
        {
            return new NotFoundResult();
        }

        if (version is not null && !PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid)
        {
            return new NotFoundResult();
        }

        var pkg = await packages.GetByPurlNameAsync(orgId, "pypi", purlName, ct);

        // Determine whether passthrough to upstream is available.
        bool passthroughAllowed = settings!.ProxyPassthroughEffective
            && await claimResolver.IsProxyFetchAllowedAsync(orgId, "pypi", purlName, ct);

        // Collect local versions scoped to origin=uploaded (hosted packages).
        IReadOnlyList<PackageVersion>? hostedVersions = null;
        if (pkg is not null)
        {
            var allVersions = await packages.GetVersionsAsync(pkg.Id, ct);
            hostedVersions = allVersions.Where(v => v.Origin == "uploaded").ToList();
        }

        bool hasHosted = hostedVersions is { Count: > 0 };

        // Mixed or hosted-only: synthesize the local JSON document (local shadows upstream,
        // consistent with SimpleIndex merge behaviour).
        if (hasHosted)
        {
            if (!settings.AnonymousPull && token is null)
            {
                httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return new UnauthorizedResult();
            }
            return SynthesizeLocalJsonDocument(pkg!, hostedVersions!, version, purlName);
        }

        // No hosted versions — proxy the upstream JSON document when passthrough is enabled.
        if (passthroughAllowed)
        {
            if (!settings.AnonymousPull && token is null)
            {
                httpContext.Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
                return new UnauthorizedResult();
            }
            return await ProxyUpstreamJsonDocumentAsync(orgId, purlName, version, ct);
        }

        return new NotFoundResult();
    }

    /// <summary>
    /// Synthesizes a PyPI JSON API document from locally-hosted package versions. Includes
    /// only fields derivable from stored metadata — fields not captured at upload time are
    /// omitted rather than fabricated. URL rewriting to local download routes is intentional
    /// here; the upstream JSON document proxy path does NOT rewrite URLs so consumers get
    /// the unmodified upstream shape for proxy-only packages.
    /// </summary>
    private static IActionResult SynthesizeLocalJsonDocument(
        Package pkg, IReadOnlyList<PackageVersion> versions,
        string? requestedVersion, string purlName)
    {
        var releases = BuildLocalReleaseFiles(versions);

        var infoVersion = SelectInfoVersion(versions, requestedVersion);
        if (infoVersion is null)
        {
            return new NotFoundResult();
        }

        var info = new Dictionary<string, object?>
        {
            ["name"] = pkg.Name,
            ["package_url"] = $"https://pypi.org/project/{purlName}/",
            ["project_url"] = $"https://pypi.org/project/{purlName}/",
            ["version"] = infoVersion.Version,
            // summary, author, license etc. are not captured at upload time for PyPI packages
            // hosted in this registry — fields absent from stored metadata are omitted rather
            // than emitted as null to match PyPI's own omission behaviour for sparse packages.
        };

        var infoVersionFiles = releases.TryGetValue(infoVersion.Version, out var vFiles)
            ? vFiles
            : new List<object>();

        var doc = new Dictionary<string, object?>
        {
            ["info"] = info,
            ["releases"] = releases,
            ["urls"] = infoVersionFiles,
        };

        string json = JsonSerializer.Serialize(doc, CompactJsonOptions);
        return new ContentResult { Content = json, ContentType = "application/json", StatusCode = StatusCodes.Status200OK };
    }

    // Builds the per-version file lists for a synthesized JSON document, keyed by version string.
    private static Dictionary<string, List<object>> BuildLocalReleaseFiles(IReadOnlyList<PackageVersion> versions)
    {
        var releases = new Dictionary<string, List<object>>();
        foreach (var v in versions)
        {
            if (!releases.TryGetValue(v.Version, out var files))
            {
                files = new List<object>();
                releases[v.Version] = files;
            }
            files.Add(BuildLocalFileEntry(v));
        }
        return releases;
    }

    private static Dictionary<string, object?> BuildLocalFileEntry(PackageVersion v)
    {
        string filename = v.BlobKey.Split('/').Last();
        string downloadUrl = PyPiSimpleIndexHelper.OrgPath($"packages/{filename}");

        var fileEntry = new Dictionary<string, object?>
        {
            ["filename"] = filename,
            ["url"] = downloadUrl,
            ["yanked"] = v.Yanked,
        };
        if (v.YankReason is not null)
        {
            fileEntry["yanked_reason"] = v.YankReason;
        }
        if (v.ChecksumSha256 is not null)
        {
            fileEntry["digests"] = new Dictionary<string, string> { ["sha256"] = v.ChecksumSha256 };
        }
        if (v.SizeBytes > 0)
        {
            fileEntry["size"] = v.SizeBytes;
        }
        if (v.PublishedAt is not null)
        {
            fileEntry["upload_time_iso_8601"] = v.PublishedAt.Value.ToString("o");
        }
        return fileEntry;
    }

    // Picks the version surfaced in `info` and `urls`: the requested version when one is
    // named, otherwise the latest non-yanked version by creation order (first version when
    // all are yanked). Null when nothing matches.
    private static PackageVersion? SelectInfoVersion(
        IReadOnlyList<PackageVersion> versions, string? requestedVersion)
    {
        return requestedVersion is not null
            ? versions.FirstOrDefault(v =>
                string.Equals(v.Version, requestedVersion, StringComparison.OrdinalIgnoreCase))
            : versions.FirstOrDefault(v => !v.Yanked) ?? (versions.Count > 0 ? versions[0] : null);
    }

    /// <summary>
    /// Forwards the PyPI JSON API document from the highest-priority configured upstream.
    /// Serves the upstream response verbatim (URLs are not rewritten — the upstream document
    /// points at files.pythonhosted.org, and scanners/version checkers using this endpoint
    /// want the authoritative upstream metadata shape, not a local proxy URL).
    /// </summary>
    private async Task<IActionResult> ProxyUpstreamJsonDocumentAsync(
        string orgId, string purlName, string? version, CancellationToken ct)
    {
        var bases = await registries.ResolveAsync(orgId, "pypi", ct);
        if (bases.Count == 0)
        {
            return new NotFoundResult();
        }

        foreach (string upstreamBase in bases)
        {
            try
            {
                string path = version is not null
                    ? $"{upstreamBase}/pypi/{purlName}/{version}/json"
                    : $"{upstreamBase}/pypi/{purlName}/json";

                var resp = await upstream.GetOrFetchMetadataAsync(path, ct);
                if (!resp.IsSuccessStatusCode)
                {
                    continue;
                }

                return new ContentResult { Content = resp.BodyAsString(), ContentType = "application/json", StatusCode = StatusCodes.Status200OK };
            }
            catch
            {
                // Upstream unreachable — try the next configured upstream.
            }
        }

        return new NotFoundResult();
    }
}
