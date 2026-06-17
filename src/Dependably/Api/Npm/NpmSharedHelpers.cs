using System.Security.Cryptography;
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

    internal static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");

    /// <summary>
    /// True when a decoded npm name ("name" or "@scope/name") is safe to embed in an
    /// upstream proxy URL: at most two path segments, each passing
    /// <see cref="PathSafeValidator.ValidateUpstreamSegment"/>.
    /// </summary>
    internal static bool IsUpstreamSafeNpmName(string fullName)
    {
        string[] segments = fullName.Split('/');
        return segments.Length <= 2 &&
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
}
