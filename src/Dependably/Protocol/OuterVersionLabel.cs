using System.Text.RegularExpressions;
using NuGet.Versioning;

namespace Dependably.Protocol;

/// <summary>
/// Extracts a version string from the artefact's <em>outer label</em> — the wrapper-dir name
/// for gzipped tarballs, or the filename for ZIP-based formats. Used by the content-based
/// detection path so that two artefacts whose embedded manifests claim the same version but
/// whose outer labels disagree (e.g. two GitHub source archives of the same monorepo at
/// different release tags, both shipping a stale workspace manifest) can land as distinct
/// <c>(name, version)</c> rows.
///
/// <para>Tooling-produced artefacts are unaffected: <c>npm pack</c>'s <c>package/</c> wrapper
/// carries no version suffix; <c>python -m build</c> and <c>dotnet pack</c> emit filenames
/// whose version segment matches the embedded manifest. The override is a no-op for canonical
/// publish flows and only kicks in when the outer label disambiguates.</para>
/// </summary>
public static partial class OuterVersionLabel
{
    // Strict semver per semver.org: three numeric components plus optional prerelease and
    // build-metadata. Anchored to the end of the wrapper-dir, with a reluctant prefix so the
    // engine finds the leftmost dash whose suffix parses cleanly (handles names like
    // "mermaid-mermaid-11.13.0" without over-matching).
    [GeneratedRegex(@"^.+-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.+-]+)?(?:\+[0-9A-Za-z.-]+)?)$")]
    private static partial Regex SemverWrapperRegex();

    // PEP 440 is more permissive than semver — covers 1.0.0a1, 1.0.0.post1, 1.0.0+local, etc.
    // The leading \d gate prevents a name segment from being mistaken for a version.
    [GeneratedRegex(@"^.+-(\d[A-Za-z0-9.!+-]*)$")]
    private static partial Regex Pep440WrapperRegex();

    /// <summary>
    /// Tries to extract an npm-style semver from a gzipped-tar wrapper-dir name. Returns
    /// false for canonical <c>package/</c> wrappers, empty wrappers, and any shape that
    /// doesn't carry three numeric semver components after the last hyphen.
    /// </summary>
    public static bool TryFromNpmWrapper(string wrapperDir, out string version)
    {
        version = "";
        if (string.IsNullOrEmpty(wrapperDir)) return false;
        var m = SemverWrapperRegex().Match(wrapperDir);
        if (!m.Success) return false;
        version = m.Groups[1].Value;
        return true;
    }

    /// <summary>
    /// Tries to extract a PEP 440 version from a PyPI sdist wrapper-dir name
    /// (<c>{name}-{version}/</c> per PEP 314). Permissive enough to admit prerelease,
    /// post-release, dev-release, and local-version suffixes.
    /// </summary>
    public static bool TryFromPyPiSdistWrapper(string wrapperDir, out string version)
    {
        version = "";
        if (string.IsNullOrEmpty(wrapperDir)) return false;
        var m = Pep440WrapperRegex().Match(wrapperDir);
        if (!m.Success) return false;
        version = m.Groups[1].Value;
        return true;
    }

    /// <summary>
    /// Tries to extract the version segment from a PEP 427 wheel filename. The filename
    /// shape is <c>{dist}-{version}(-{build})?-{python}-{abi}-{platform}.whl</c>; the
    /// version is the second hyphen-delimited segment of the stem.
    /// </summary>
    public static bool TryFromWheelFilename(string filename, out string version)
    {
        version = "";
        if (string.IsNullOrEmpty(filename)) return false;
        if (!filename.EndsWith(".whl", StringComparison.OrdinalIgnoreCase)) return false;
        var stem = filename[..^4];
        var parts = stem.Split('-');
        // PEP 427 requires at least 5 dash-segments; we accept the 2nd as the version
        // candidate if it starts with a digit (PEP 440 versions always do).
        if (parts.Length < 5) return false;
        var candidate = parts[1];
        if (candidate.Length == 0 || !char.IsDigit(candidate[0])) return false;
        version = candidate;
        return true;
    }

    /// <summary>
    /// Tries to extract the version segment from a NuGet <c>{Id}.{Version}.nupkg</c>
    /// filename. NuGet ids can themselves contain dots (e.g. <c>Microsoft.AspNetCore.App</c>),
    /// so we scan dot positions left-to-right and return the first suffix that
    /// <see cref="NuGetVersion.TryParse"/> accepts as a valid NuGet version. This matches
    /// NuGet's own parsing rule: id segments are never numeric-leading, so the first
    /// digit-leading dot-segment marks the start of the version.
    /// </summary>
    public static bool TryFromNupkgFilename(string filename, out string version)
    {
        version = "";
        if (string.IsNullOrEmpty(filename)) return false;
        if (!filename.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase)
            && !filename.EndsWith(".snupkg", StringComparison.OrdinalIgnoreCase))
            return false;
        var stem = filename[..filename.LastIndexOf('.')];
        for (var i = 0; i < stem.Length - 1; i++)
        {
            if (stem[i] != '.') continue;
            var candidate = stem[(i + 1)..];
            if (candidate.Length == 0 || !char.IsDigit(candidate[0])) continue;
            if (NuGetVersion.TryParse(candidate, out _))
            {
                version = candidate;
                return true;
            }
        }
        return false;
    }
}
