using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using NuGet.Versioning;

namespace Dependably.Protocol;

/// <summary>
/// Resolves the upstream-declared latest-stable version for a proxied package.
/// </summary>
public interface IUpstreamLatestVersionResolver
{
    /// <summary>
    /// Resolves the upstream latest-stable version for <paramref name="purlName"/>, or <c>null</c>
    /// when the ecosystem is unsupported or upstream declares no version.
    /// </summary>
    Task<string?> ResolveAsync(string ecosystem, string orgId, string purlName, CancellationToken ct = default);
}

/// <summary>
/// Resolves the upstream-declared "latest" version for a proxied package, per ecosystem. The
/// result feeds <c>packages.upstream_latest_version</c>, which drives the packages-list "Latest"
/// indicator and the package-detail "behind upstream" banner.
///
/// "Latest" is the highest STABLE release:
/// <list type="bullet">
///   <item>npm — <c>dist-tags.latest</c> (already the stable channel).</item>
///   <item>PyPI — <c>info.version</c> (the latest non-prerelease release).</item>
///   <item>NuGet — the highest non-prerelease version in the flatcontainer index, falling back to
///         the highest prerelease only when no stable release exists.</item>
///   <item>Maven — <c>metadata/versioning/release</c>, falling back to <c>latest</c> (which may be
///         a <c>-SNAPSHOT</c>) only when no release has been published.</item>
/// </list>
///
/// npm/PyPI upstreams come from configuration (the public registry defaults); NuGet/Maven have no
/// universal default, so their upstreams are resolved per-org through <see cref="UpstreamRegistryResolver"/>.
///
/// Methods return <c>null</c> when the upstream definitively has no latest (non-success status,
/// empty/missing version data) and let transient/parse exceptions propagate so callers can decide
/// whether to retry (the daily refresh) or swallow (the first-fetch seed).
/// </summary>
public sealed class UpstreamLatestVersionResolver : IUpstreamLatestVersionResolver
{
    private readonly UpstreamClient _upstream;
    private readonly UpstreamRegistryResolver _registries;
    private readonly IConfiguration _config;

    public UpstreamLatestVersionResolver(
        UpstreamClient upstream,
        UpstreamRegistryResolver registries,
        IConfiguration config)
    {
        _upstream = upstream;
        _registries = registries;
        _config = config;
    }

    /// <inheritdoc />
    public Task<string?> ResolveAsync(string ecosystem, string orgId, string purlName, CancellationToken ct = default) =>
        ecosystem switch
        {
            "npm" => ResolveNpmAsync(purlName, ct),
            "pypi" => ResolvePyPiAsync(purlName, ct),
            "nuget" => ResolveNuGetAsync(orgId, purlName, ct),
            "maven" => ResolveMavenAsync(orgId, purlName, ct),
            _ => Task.FromResult<string?>(null),
        };

    private async Task<string?> ResolveNpmAsync(string purlName, CancellationToken ct)
    {
        string upstream = (_config["Npm:Upstream"] ?? "https://registry.npmjs.org").TrimEnd('/');
        // Scoped packages arrive percent-encoded (%40scope%2Fpkg); the packument URL uses @scope/pkg.
        string packageName = Uri.UnescapeDataString(purlName).Replace("%40", "@").Replace("%2F", "/");
        var resp = await _upstream.GetOrFetchMetadataAsync($"{upstream}/{packageName}", ct);
        if (!resp.IsSuccessStatusCode)
        {
            return null;
        }

        using var doc = JsonDocument.Parse(resp.Body);
        return doc.RootElement.TryGetProperty("dist-tags", out var distTags)
            && distTags.TryGetProperty("latest", out var latestEl)
            && latestEl.ValueKind == JsonValueKind.String
            ? NullIfBlank(latestEl.GetString())
            : null;
    }

    private async Task<string?> ResolvePyPiAsync(string purlName, CancellationToken ct)
    {
        string upstream = (_config["PyPI:Upstream"] ?? "https://pypi.org").TrimEnd('/');
        var resp = await _upstream.GetOrFetchMetadataAsync($"{upstream}/pypi/{purlName}/json", ct);
        if (!resp.IsSuccessStatusCode)
        {
            return null;
        }

        using var doc = JsonDocument.Parse(resp.Body);
        return doc.RootElement.TryGetProperty("info", out var info)
            && info.TryGetProperty("version", out var versionEl)
            && versionEl.ValueKind == JsonValueKind.String
            ? NullIfBlank(versionEl.GetString())
            : null;
    }

    private async Task<string?> ResolveNuGetAsync(string orgId, string id, CancellationToken ct)
    {
        // Reject path-shaped ids before they reach the upstream URL (defence in depth — ids
        // sourced from cache_artifact were validated at fetch time, but this method is also
        // reachable on the first-fetch path).
        if (id.Contains('/') || id.Contains("..", StringComparison.Ordinal))
        {
            return null;
        }

        foreach (string baseUrl in await _registries.ResolveAsync(orgId, "nuget", ct))
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(
                $"{baseUrl}/flatcontainer/{id.ToLowerInvariant()}/index.json", ct);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            using var doc = JsonDocument.Parse(resp.Body);
            if (!doc.RootElement.TryGetProperty("versions", out var versionsEl)
                || versionsEl.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var parsed = versionsEl.EnumerateArray()
                .Select(v => v.GetString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => NuGetVersion.TryParse(s, out var nv) ? nv : null)
                .OfType<NuGetVersion>()
                .ToList();
            if (parsed.Count == 0)
            {
                continue;
            }

            // Prefer the highest stable release; only consider prereleases when none is stable.
            var stable = parsed.Where(v => !v.IsPrerelease).ToList();
            var pick = (stable.Count > 0 ? stable : parsed)
                .OrderByDescending(v => v, VersionComparer.Default)
                .First();
            // Normalize to the canonical NuGet form so it matches cache_artifact.version exactly
            // (the LatestState CASE compares ca.version = upstream_latest_version literally).
            return pick.ToNormalizedString().ToLowerInvariant();
        }

        return null;
    }

    private async Task<string?> ResolveMavenAsync(string orgId, string coordinate, CancellationToken ct)
    {
        // The maven purl name is "groupId:artifactId"; the metadata path is groupId-as-path/artifact.
        int sep = coordinate.IndexOf(':');
        if (sep <= 0 || sep == coordinate.Length - 1)
        {
            return null;
        }

        string groupId = coordinate[..sep];
        string artifact = coordinate[(sep + 1)..];
        if (coordinate.Contains("..", StringComparison.Ordinal) || artifact.Contains('/'))
        {
            return null;
        }

        string groupPath = groupId.Replace('.', '/');
        foreach (string baseUrl in await _registries.ResolveAsync(orgId, "maven", ct))
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(
                $"{baseUrl}/{groupPath}/{artifact}/maven-metadata.xml", ct);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            var versioning = XDocument.Parse(resp.BodyAsString()).Root?.Element("versioning");
            if (versioning is null)
            {
                continue;
            }

            // <release> is the latest stable; <latest> can point at a -SNAPSHOT, so only use it
            // when no release has been published.
            string? pick = NullIfBlank(versioning.Element("release")?.Value)
                ?? NullIfBlank(versioning.Element("latest")?.Value);
            if (pick is not null)
            {
                return pick;
            }
        }

        return null;
    }

    private static string? NullIfBlank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;
}
