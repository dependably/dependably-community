using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Pure-static helpers shared across npm handler classes: ETag computation, header
/// sanitisation, name safety checks, tarball filename parsing, and lazy-latest resolution.
/// No dependencies — no DI required.
/// </summary>
internal static class NpmSharedHelpers
{
    // SHA-256 hex digest prefix length used for ETags (16 hex chars = 64 bits of entropy).
    internal const int ETagHexPrefixLength = 16;

    internal static string ComputeETag(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..ETagHexPrefixLength].ToLowerInvariant() + "\"";
    }

    /// <summary>
    /// True when a decoded npm name is both well-shaped and safe to embed in an upstream proxy
    /// URL. npm admits exactly two shapes: unscoped ("name", no separator at all) and scoped
    /// ("@scope/name", exactly one separator with a non-empty scope after the '@'). Every
    /// segment must additionally pass <see cref="PathSafeValidator.ValidateUpstreamSegment"/>.
    ///
    /// The shape check is not cosmetic: a bare "@scope" with no name part is unresolvable, but
    /// registry.npmjs.org answers it with 405, not 404. Forwarding it upstream would therefore
    /// surface a caller's typo as an unhealthy-source signal (a lookup reports it as
    /// upstream-unavailable rather than a bad name), so a malformed name is rejected here
    /// before any upstream request is composed.
    /// </summary>
    internal static bool IsUpstreamSafeNpmName(string fullName)
    {
        string[] segments = fullName.Split('/');
        bool shapeValid = fullName.StartsWith('@')
            ? segments.Length == 2 && segments[0].Length > 1
            : segments.Length == 1;

        return shapeValid &&
            Array.TrueForAll(segments, s => PathSafeValidator.ValidateUpstreamSegment(s, "package").IsValid);
    }

    internal static string? ExtractVersionFromTarballFilename(string shortName, string file)
    {
        string baseName = file.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
        return baseName.Length > shortName.Length + 1 && baseName.StartsWith(shortName + "-", StringComparison.Ordinal)
            ? baseName[(shortName.Length + 1)..]
            : null;
    }

    /// <summary>
    /// Computes a lazy default for the 'latest' dist-tag when no persisted tags exist.
    /// Prefers the highest stable (non-prerelease) semver version. When all versions are
    /// prerelease, returns the version with the most recent CreatedAt. Returns null only
    /// when there are no active (non-yanked) versions.
    /// </summary>
    internal static string? ComputeLazyLatest(List<PackageVersion> activeVersions)
    {
        if (activeVersions.Count == 0)
        {
            return null;
        }

        // Stable versions: no prerelease label (semver prerelease = label after '-').
        var stable = activeVersions
            .Where(v => !v.Version.Contains('-'))
            .ToList();

        var candidates = stable.Count > 0 ? stable : activeVersions;

        // Pick highest by semver when parseable; fall back to newest by CreatedAt.
        var best = candidates
            .Select(v => (Version: v, Parsed: NuGet.Versioning.NuGetVersion.TryParse(v.Version, out var sv) ? sv : null))
            .OrderByDescending(x => x.Parsed, Comparer<NuGet.Versioning.NuGetVersion?>.Create((a, b) =>
                a is null && b is null ? 0 : a is null ? -1 : b is null ? 1 : a.CompareTo(b)))
            .ThenByDescending(x => x.Version.CreatedAt)
            .FirstOrDefault();

        return best.Version?.Version;
    }

    internal static string DecodeNpmName(string name) => NpmRouteHelper.DecodeRouteName(name);

    /// <summary>
    /// Computes a synthetic CouchDB-style packument revision (<c>_rev</c>) for a version set.
    /// The npm unpublish flow reads the packument's <c>_rev</c>, then PUTs the pruned packument
    /// to <c>/-rev/{_rev}</c> and DELETEs the tarball at <c>/-/{tarball}/-rev/{_rev}</c>. A
    /// packument with no <c>_rev</c> makes the CLI resolve <c>undefined</c> and PUT to
    /// <c>/-rev/undefined</c>, which never prunes the version, so the client reports success
    /// while the version still lists. The value is <c>{count}-{digest}</c> — the number of
    /// versions and a stable 12-hex-char SHA-256 digest of the sorted version keys — so it
    /// changes whenever the advertised version set changes and matches the <c>N-hex</c> shape
    /// real clients expect without persisting a revision counter.
    /// </summary>
    internal static string ComputeSyntheticRev(IEnumerable<string> versionKeys)
    {
        var sorted = versionKeys.OrderBy(v => v, StringComparer.Ordinal).ToList();
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', sorted)));
        string digest = Convert.ToHexString(hash)[..12].ToLowerInvariant();
        return $"{sorted.Count}-{digest}";
    }
}
