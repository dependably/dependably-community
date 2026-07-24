using System.Globalization;
using System.Text.Json;
using System.Xml.Linq;
using Dependably.Api;
using Dependably.Api.NuGetProtocol;
using NuGet.Versioning;

namespace Dependably.Protocol;

/// <summary>
/// The upstream-declared latest-stable version for a package, plus its publish timestamp when the
/// ecosystem's metadata carries one. <see cref="Version"/> is null when the ecosystem is
/// unsupported or upstream declares no version; <see cref="PublishedAt"/> is independently null
/// when a version was resolved but the metadata source consulted for it carries no per-release
/// timestamp (or the timestamp fetch/parse failed) — never inferred from the version's absence.
/// <see cref="StableVersionsDescending"/> carries every STABLE version upstream declares, newest
/// first in the ecosystem's native ordering — the raw material for the per-version
/// versions-behind operational-risk count (see <see cref="EcosystemVersionOrdering"/>). Null when
/// the ecosystem's metadata document doesn't enumerate the full version set or the fetch failed.
/// </summary>
public sealed record UpstreamLatestVersion(
    string? Version, DateTimeOffset? PublishedAt, IReadOnlyList<string>? StableVersionsDescending = null)
{
    public static readonly UpstreamLatestVersion None = new(null, null, null);
}

/// <summary>
/// Resolves the upstream-declared latest-stable version for a proxied package.
/// </summary>
public interface IUpstreamLatestVersionResolver
{
    /// <summary>
    /// Resolves the upstream latest-stable version (and its publish timestamp, where the
    /// ecosystem's metadata carries one) for <paramref name="purlName"/>.
    /// </summary>
    Task<UpstreamLatestVersion> ResolveAsync(string ecosystem, string orgId, string purlName, CancellationToken ct = default);
}

/// <summary>
/// Resolves the upstream-declared "latest" version for a proxied package, per ecosystem. The
/// result feeds <c>packages.upstream_latest_version</c> / <c>upstream_latest_published_at</c>,
/// which drive the packages-list "Latest" and "Abandoned" indicators and the package-detail
/// "behind upstream" banner.
///
/// "Latest" is the highest STABLE release:
/// <list type="bullet">
///   <item>npm — <c>dist-tags.latest</c> (already the stable channel); publish time from the
///         packument's <c>time[version]</c> map.</item>
///   <item>PyPI — <c>info.version</c> (the latest non-prerelease release); publish time from the
///         top-level <c>urls[]</c> array's <c>upload_time_iso_8601</c> (the latest release's own
///         file listing).</item>
///   <item>NuGet — the highest non-prerelease version in the flatcontainer index, falling back to
///         the highest prerelease only when no stable release exists; publish time from a
///         second, best-effort fetch of that version's registration leaf (flatcontainer carries
///         no timestamp).</item>
///   <item>Maven — <c>metadata/versioning/release</c>, falling back to <c>latest</c> (which may be
///         a <c>-SNAPSHOT</c>) only when no release has been published; publish time from the same
///         document's <c>metadata/versioning/lastUpdated</c> (a whole-metadata timestamp, not
///         necessarily the release version's own publish time, but the cheapest signal Maven
///         exposes without a per-version fetch).</item>
///   <item>Cargo — the highest stable non-yanked version in the sparse index, which enumerates
///         every published version with its yank state; the index carries no publish date, so
///         the timestamp stays null.</item>
///   <item>Go — <c>@latest</c>, the module proxy's own choice of latest version, with the
///         <c>Time</c> it reports alongside; that endpoint does not enumerate the full version
///         set, so the stable-version list stays null.</item>
/// </list>
///
/// Every ecosystem's upstream base URL is resolved per-org through <see cref="UpstreamRegistryResolver"/>
/// — the same DB-backed, priority-ordered source the hosted proxy handlers use — so an edge node's
/// seeded master row (with its Bearer reader token) and a tenant's configured mirror are honored
/// identically here, rather than a hardcoded public-registry default bypassing both.
///
/// Methods return <see cref="UpstreamLatestVersion.None"/> when the upstream definitively has no
/// latest (non-success status, empty/missing version data) and let transient/parse exceptions
/// propagate so callers can decide whether to retry (the daily refresh) or swallow (the first-fetch
/// seed). A resolved version with an unresolvable/absent timestamp still returns non-null Version.
/// </summary>
public sealed class UpstreamLatestVersionResolver : IUpstreamLatestVersionResolver
{
    private readonly UpstreamClient _upstream;
    private readonly UpstreamRegistryResolver _registries;

    public UpstreamLatestVersionResolver(
        UpstreamClient upstream,
        UpstreamRegistryResolver registries)
    {
        _upstream = upstream;
        _registries = registries;
    }

    /// <inheritdoc />
    public Task<UpstreamLatestVersion> ResolveAsync(string ecosystem, string orgId, string purlName, CancellationToken ct = default) =>
        ecosystem switch
        {
            "npm" => ResolveNpmAsync(orgId, purlName, ct),
            "pypi" => ResolvePyPiAsync(orgId, purlName, ct),
            "nuget" => ResolveNuGetAsync(orgId, purlName, ct),
            "maven" => ResolveMavenAsync(orgId, purlName, ct),
            "cargo" => ResolveCargoAsync(orgId, purlName, ct),
            "golang" => ResolveGoAsync(orgId, purlName, ct),
            _ => Task.FromResult(UpstreamLatestVersion.None),
        };

    /// <summary>
    /// Cargo: the sparse index enumerates every published version with its yank state. Yanked
    /// versions are excluded — a yanked crate is not a release Cargo resolves to. The index
    /// carries no publish date, so PublishedAt stays null.
    /// </summary>
    private async Task<UpstreamLatestVersion> ResolveCargoAsync(string orgId, string purlName, CancellationToken ct)
    {
        foreach (var source in await _registries.ResolveAsync(orgId, "cargo", ct))
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/{CargoController.IndexPath(purlName)}", source.AuthorizationHeader, ct);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            var stableVersions = EcosystemVersionOrdering.OrderStableDescending(
                "cargo",
                CargoLookupMetadata.ParseIndex(resp.BodyAsString()).Where(e => !e.Yanked).Select(e => e.Version));
            if (stableVersions.Count == 0)
            {
                continue;
            }

            return new UpstreamLatestVersion(stableVersions[0], null, stableVersions);
        }

        return UpstreamLatestVersion.None;
    }

    /// <summary>
    /// Go: <c>@latest</c> answers with the module proxy's own choice of latest version and its
    /// publish time. That endpoint does not enumerate the full version set, so
    /// StableVersionsDescending stays null (unknown, not empty).
    /// </summary>
    private async Task<UpstreamLatestVersion> ResolveGoAsync(string orgId, string purlName, CancellationToken ct)
    {
        string encodedModule = GoController.EncodeBangEncoding(purlName);
        foreach (var source in await _registries.ResolveAsync(orgId, "golang", ct))
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/{encodedModule}/@latest", source.AuthorizationHeader, ct);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            using var doc = JsonDocument.Parse(resp.Body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? latest = doc.RootElement.TryGetProperty("Version", out var versionEl)
                && versionEl.ValueKind == JsonValueKind.String
                ? NullIfBlank(versionEl.GetString())
                : null;
            if (latest is null)
            {
                continue;
            }

            var publishedAt = doc.RootElement.TryGetProperty("Time", out var timeEl)
                && timeEl.ValueKind == JsonValueKind.String
                ? ParseTimestampOrNull(timeEl.GetString())
                : null;

            return new UpstreamLatestVersion(latest, publishedAt, null);
        }

        return UpstreamLatestVersion.None;
    }

    private async Task<UpstreamLatestVersion> ResolveNpmAsync(string orgId, string purlName, CancellationToken ct)
    {
        // Scoped packages arrive percent-encoded (%40scope%2Fpkg); the packument URL uses @scope/pkg.
        string packageName = Uri.UnescapeDataString(purlName).Replace("%40", "@").Replace("%2F", "/");

        foreach (var source in await _registries.ResolveAsync(orgId, "npm", ct))
        {
            // Abbreviated-document fallback for packuments past the metadata byte cap; the
            // abbreviated document has no time[] map, which this method already tolerates
            // (publishedAt stays null).
            var resp = await NpmPackumentFetcher.FetchAsync(
                _upstream, $"{source.Url}/{packageName}", source.AuthorizationHeader, logger: null, ct);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            using var doc = JsonDocument.Parse(resp.Body);
            string? latest = doc.RootElement.TryGetProperty("dist-tags", out var distTags)
                && distTags.TryGetProperty("latest", out var latestEl)
                && latestEl.ValueKind == JsonValueKind.String
                ? NullIfBlank(latestEl.GetString())
                : null;
            if (latest is null)
            {
                continue;
            }

            var publishedAt = doc.RootElement.TryGetProperty("time", out var time)
                && time.ValueKind == JsonValueKind.Object
                && time.TryGetProperty(latest, out var timeEl)
                && timeEl.ValueKind == JsonValueKind.String
                ? ParseTimestampOrNull(timeEl.GetString())
                : null;

            var stableVersions = doc.RootElement.TryGetProperty("versions", out var versionsEl)
                && versionsEl.ValueKind == JsonValueKind.Object
                ? EcosystemVersionOrdering.OrderStableDescending(
                    "npm", versionsEl.EnumerateObject().Select(v => v.Name))
                : null;

            return new UpstreamLatestVersion(latest, publishedAt, stableVersions);
        }

        return UpstreamLatestVersion.None;
    }

    private async Task<UpstreamLatestVersion> ResolvePyPiAsync(string orgId, string purlName, CancellationToken ct)
    {
        foreach (var source in await _registries.ResolveAsync(orgId, "pypi", ct))
        {
            var resp = await _upstream.GetOrFetchMetadataAsync($"{source.Url}/pypi/{purlName}/json", source.AuthorizationHeader, ct);
            if (!resp.IsSuccessStatusCode)
            {
                continue;
            }

            using var doc = JsonDocument.Parse(resp.Body);
            string? latest = doc.RootElement.TryGetProperty("info", out var info)
                && info.TryGetProperty("version", out var versionEl)
                && versionEl.ValueKind == JsonValueKind.String
                ? NullIfBlank(versionEl.GetString())
                : null;
            if (latest is null)
            {
                continue;
            }

            // The top-level "urls" array lists the latest release's own distribution files (the
            // same set as releases[info.version]) — no second fetch needed for its publish time.
            var publishedAt = ExtractPyPiPublishedAt(doc.RootElement);

            var stableVersions = doc.RootElement.TryGetProperty("releases", out var releasesEl)
                && releasesEl.ValueKind == JsonValueKind.Object
                ? EcosystemVersionOrdering.OrderStableDescending(
                    "pypi", releasesEl.EnumerateObject().Select(v => v.Name))
                : null;

            return new UpstreamLatestVersion(latest, publishedAt, stableVersions);
        }

        return UpstreamLatestVersion.None;
    }

    // The first "urls" entry carrying a parseable upload_time_iso_8601 wins — every file in the
    // array belongs to the same release, so the first timestamp found is representative.
    private static DateTimeOffset? ExtractPyPiPublishedAt(JsonElement root)
    {
        if (!root.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var file in urls.EnumerateArray())
        {
            if (file.TryGetProperty("upload_time_iso_8601", out var uploadEl)
                && uploadEl.ValueKind == JsonValueKind.String
                && ParseTimestampOrNull(uploadEl.GetString()) is { } ts)
            {
                return ts;
            }
        }

        return null;
    }

    private async Task<UpstreamLatestVersion> ResolveNuGetAsync(string orgId, string id, CancellationToken ct)
    {
        // Reject path-shaped ids before they reach the upstream URL (defence in depth — ids
        // sourced from cache_artifact were validated at fetch time, but this method is also
        // reachable on the first-fetch path).
        if (id.Contains('/') || id.Contains("..", StringComparison.Ordinal))
        {
            return UpstreamLatestVersion.None;
        }

        foreach (var source in await _registries.ResolveAsync(orgId, "nuget", ct))
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/flatcontainer/{id.ToLowerInvariant()}/index.json", source.AuthorizationHeader, ct);
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
            string version = pick.ToNormalizedString().ToLowerInvariant();
            var stableVersionsDescending = stable
                .OrderByDescending(v => v, VersionComparer.Default)
                .Select(v => v.ToNormalizedString().ToLowerInvariant())
                .ToList();

            var publishedAt = await FetchNuGetPublishedAtAsync(source, id, version, ct);
            return new UpstreamLatestVersion(version, publishedAt, stableVersionsDescending);
        }

        return UpstreamLatestVersion.None;
    }

    // Flatcontainer carries no publish timestamp, so the picked version's date is a second,
    // best-effort fetch of its registration leaf ("published" or "catalogEntry.published").
    // Failure here must never fail latest-version resolution — the version is already resolved.
    private async Task<DateTimeOffset?> FetchNuGetPublishedAtAsync(
        UpstreamSource source, string id, string version, CancellationToken ct)
    {
        try
        {
            string leafUrl = $"{source.Url}/registration5-gz-semver2/{id.ToLowerInvariant()}/{version}.json";
            var resp = await _upstream.GetOrFetchMetadataAsync(leafUrl, source.AuthorizationHeader, ct);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(resp.Body);
            var root = doc.RootElement;
            string? published = TryGetString(root, "published")
                ?? (root.TryGetProperty("catalogEntry", out var entry) ? TryGetString(entry, "published") : null);
            var ts = ParseTimestampOrNull(published);
            // NuGet stamps 1900-01-01 as the "unset"/unlisted sentinel; coerce it to null so an
            // unlisted latest version reads as unknown rather than a false abandoned signal.
            return ts is { Year: >= NuGetNupkgProxyHelper.MinValidPublishedYear } ? ts : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    private async Task<UpstreamLatestVersion> ResolveMavenAsync(string orgId, string coordinate, CancellationToken ct)
    {
        // The maven purl name is "groupId:artifactId"; the metadata path is groupId-as-path/artifact.
        int sep = coordinate.IndexOf(':');
        if (sep <= 0 || sep == coordinate.Length - 1)
        {
            return UpstreamLatestVersion.None;
        }

        string groupId = coordinate[..sep];
        string artifact = coordinate[(sep + 1)..];
        if (coordinate.Contains("..", StringComparison.Ordinal) || artifact.Contains('/'))
        {
            return UpstreamLatestVersion.None;
        }

        string groupPath = groupId.Replace('.', '/');
        foreach (var source in await _registries.ResolveAsync(orgId, "maven", ct))
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/{groupPath}/{artifact}/maven-metadata.xml", source.AuthorizationHeader, ct);
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
                // <lastUpdated> is a whole-metadata-document timestamp (yyyyMMddHHmmss, UTC) — the
                // cheapest publish-time signal Maven exposes without a second per-version fetch.
                var publishedAt = ParseMavenLastUpdated(versioning.Element("lastUpdated")?.Value);
                var rawVersions = versioning.Element("versions")?.Elements("version")
                    .Select(v => v.Value) ?? Enumerable.Empty<string>();
                var stableVersions = EcosystemVersionOrdering.OrderStableDescending("maven", rawVersions);
                return new UpstreamLatestVersion(pick, publishedAt, stableVersions);
            }
        }

        return UpstreamLatestVersion.None;
    }

    private static DateTimeOffset? ParseMavenLastUpdated(string? raw) =>
        !string.IsNullOrWhiteSpace(raw)
            && DateTime.TryParseExact(
                raw, "yyyyMMddHHmmss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt)
            ? new DateTimeOffset(dt, TimeSpan.Zero)
            : null;

    private static DateTimeOffset? ParseTimestampOrNull(string? raw) =>
        !string.IsNullOrWhiteSpace(raw)
            && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var ts)
            ? ts
            : null;

    private static string? TryGetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;

    private static string? NullIfBlank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;
}
