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
            using var gzip = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
            using var tar = new TarReader(gzip, leaveOpen: false);

            while (tar.GetNextEntry() is { } entry)
            {
                if (IsTopLevelPackageJson(entry.Name))
                {
                    using var entryStream = entry.DataStream!;
                    var json = JsonNode.Parse(entryStream);
                    name = json?["name"]?.GetValue<string>();
                    version = json?["version"]?.GetValue<string>();

                    if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(version))
                        return ValidationResult.Fail("content", "package.json missing name or version");

                    // Outer-label override: when the wrapper directory looks like
                    // {anything}-{semver}/ (typical of GitHub source archives whose root
                    // package.json may be stale across release tags), the wrapper's semver
                    // is authoritative for the version. `npm pack`'s `package/` wrapper
                    // carries no version, so this is a no-op for canonical npm publish.
                    var wrapper = WrapperOf(entry.Name);
                    if (OuterVersionLabel.TryFromNpmWrapper(wrapper, out var labelled))
                        version = labelled;

                    return ValidationResult.Ok();
                }
            }

            return ValidationResult.Fail("content", "Tarball is missing a top-level package.json");
        }
        catch (Exception ex)
        {
            return ValidationResult.Fail("content", $"Invalid gzip tar: {ex.Message}");
        }
    }

    // Matches `package.json` at the root or inside exactly one wrapper directory of any name.
    // Single-slash check rejects deeper paths like `package/subdir/package.json`.
    internal static bool IsTopLevelPackageJson(string entryName)
    {
        if (entryName.Equals("package.json", StringComparison.OrdinalIgnoreCase))
            return true;
        return entryName.EndsWith("/package.json", StringComparison.OrdinalIgnoreCase)
            && entryName.IndexOf('/') == entryName.LastIndexOf('/');
    }

    // Returns the wrapper-dir segment of a top-level entry name, or empty when the entry
    // sits at the archive root (no wrapper).
    private static string WrapperOf(string entryName)
    {
        var slash = entryName.IndexOf('/');
        return slash < 0 ? string.Empty : entryName[..slash];
    }
}
