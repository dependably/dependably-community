using System.Formats.Tar;
using System.IO.Compression;
using System.Text.Json.Nodes;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Decodes an npm tarball, finds the top-level <c>package.json</c>, and extracts the package
/// name and version. Used by both the npm publish controller and the bulk-import
/// controller so the validation rules stay aligned.
///
/// <para>Accepts <c>package.json</c> either at the root or inside a single wrapper directory
/// of any name (<c>npm pack</c> always writes <c>package/</c>, but tarballs from
/// <c>git archive</c>, GitHub release assets, or hand-rolled <c>tar</c> commands often use the
/// <c>{name}-{version}/</c> shape or no wrapper at all — npm itself strips one leading
/// directory on install, so the wrapper name is not significant).</para>
/// </summary>
public static class NpmTarballValidator
{
    public static ValidationResult Validate(byte[] bytes, out string? name, out string? version)
    {
        name = null;
        version = null;

        try
        {
            // Zip-bomb guard: the compressed input is bounded by upload limits, but the
            // decompressed size is attacker-controlled. Cap total decompressed bytes, the
            // entry count, and the size of the package.json entry we parse into memory.
            using var gzip = new LimitedReadStream(
                new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress),
                TarScanLimits.MaxTotalDecompressedBytes, "Tarball");
            using var tar = new TarReader(gzip, leaveOpen: false);

            int entryCount = 0;
            while (tar.GetNextEntry() is { } entry)
            {
                if (++entryCount > TarScanLimits.MaxEntries)
                {
                    return ValidationResult.Fail("content",
                        $"Tarball exceeds the {TarScanLimits.MaxEntries}-entry limit.");
                }

                if (!IsTopLevelPackageJson(entry.Name))
                {
                    continue;
                }

                return ParseManifestEntry(entry, out name, out version);
            }

            return ValidationResult.Fail("content", "Tarball is missing a top-level package.json");
        }
        catch (Exception ex)
        {
            return ValidationResult.Fail("content", $"Invalid gzip tar: {ex.Message}");
        }
    }

    // Reads the package.json entry, validates the name and version fields, and applies the
    // outer-label override for GitHub-style source archives.
    private static ValidationResult ParseManifestEntry(TarEntry entry, out string? name, out string? version)
    {
        using var entryStream = new LimitedReadStream(
            entry.DataStream!, TarScanLimits.MaxManifestBytes, "package.json");
        var json = JsonNode.Parse(entryStream);
        name = json?["name"]?.GetValue<string>();
        version = json?["version"]?.GetValue<string>();

        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(version))
        {
            return ValidationResult.Fail("content", "package.json missing name or version");
        }

        // Name shape gate (same rules as the npm publish controller). The import
        // path takes this name verbatim into blob-key construction, so slash-laden
        // manifest names other than a single @scope/ prefix must be rejected here.
        if (!NpmNameValidator.IsValidFullName(name))
        {
            return ValidationResult.Fail("content", $"Invalid npm package name: {name}");
        }

        // Outer-label override: when the wrapper directory looks like
        // {anything}-{semver}/ (typical of GitHub source archives whose root
        // package.json may be stale across release tags), the wrapper's semver
        // is authoritative for the version. `npm pack`'s `package/` wrapper
        // carries no version, so this is a no-op for canonical npm publish.
        string wrapper = WrapperOf(entry.Name);
        if (OuterVersionLabel.TryFromNpmWrapper(wrapper, out string? labelled))
        {
            version = labelled;
        }

        return ValidationResult.Ok();
    }

    // Matches `package.json` at the root or inside exactly one wrapper directory of any name.
    // Single-slash check rejects deeper paths like `package/subdir/package.json`.
    internal static bool IsTopLevelPackageJson(string entryName)
    {
        return entryName.Equals("package.json", StringComparison.OrdinalIgnoreCase) || entryName.EndsWith("/package.json", StringComparison.OrdinalIgnoreCase)
            && entryName.IndexOf('/') == entryName.LastIndexOf('/');
    }

    // Returns the wrapper-dir segment of a top-level entry name, or empty when the entry
    // sits at the archive root (no wrapper).
    private static string WrapperOf(string entryName)
    {
        int slash = entryName.IndexOf('/');
        return slash < 0 ? string.Empty : entryName[..slash];
    }
}
