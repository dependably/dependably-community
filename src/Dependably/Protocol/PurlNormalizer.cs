using System.Text.RegularExpressions;
using NuGet.Versioning;

namespace Dependably.Protocol;

public static partial class PurlNormalizer
{
    [GeneratedRegex(@"[-_.]+")]
    private static partial Regex PyPiSeparatorRegex();

    public static string PyPi(string name, string version)
    {
        var normalized = PyPiSeparatorRegex().Replace(name, "-").ToLowerInvariant();
        return $"pkg:pypi/{normalized}@{version}";
    }

    public static string Npm(string name, string version)
        => $"pkg:npm/{name}@{version}";

    public static string NuGet(string id, string version)
    {
        var normalized = NuGetVersion.TryParse(version, out var parsed)
            ? NormalizeNuGetVersion(parsed)
            : version;
        return $"pkg:nuget/{id}@{normalized}";
    }

    public static string NormalizeNuGetVersionString(string version)
    {
        return NuGetVersion.TryParse(version, out var parsed)
            ? NormalizeNuGetVersion(parsed)
            : version;
    }

    private static string NormalizeNuGetVersion(NuGetVersion v)
    {
        // Collapse 4-part version with zero revision to 3-part: 1.0.0.0 → 1.0.0
        if (v.Revision == 0 && !v.IsPrerelease && string.IsNullOrEmpty(v.Metadata))
            return $"{v.Major}.{v.Minor}.{v.Patch}";
        return v.ToNormalizedString();
    }
}
