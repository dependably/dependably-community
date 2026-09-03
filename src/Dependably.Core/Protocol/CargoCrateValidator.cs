using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Publish-time cross-check of a Cargo <c>.crate</c> archive against the coordinates the publish
/// frame declared. <c>cargo build</c> compiles what is inside the archive, while this registry
/// records, scans and SBOMs the coordinate the frame said — so the two must agree before the
/// version is stored, the way npm cross-checks <c>package.json</c> and PyPI cross-checks
/// <c>METADATA</c>. Three facts are compared: the <c>[package]</c> table's <c>name</c> and
/// <c>version</c>, and the archive's root directory, which <c>cargo</c> itself requires to be
/// <c>{name}-{version}/</c> at unpack time.
/// <para>The archive is read under the same bounds as every other tar parser here
/// (<see cref="TarScanLimits"/>): total decompressed bytes, entry count, and the manifest entry's
/// own size. Nothing is written to disk.</para>
/// </summary>
public static class CargoCrateValidator
{
    /// <summary>
    /// Validates <paramref name="crate"/> against <paramref name="declaredName"/> and
    /// <paramref name="declaredVersion"/>. Returns <see cref="ValidationResult.Ok"/> when the
    /// embedded manifest agrees, and a failure naming the first disagreement otherwise. An
    /// archive with no root <c>Cargo.toml</c>, or one whose manifest lacks a parseable
    /// <c>[package]</c> name or version, is a failure — an unreadable identity is refused, not
    /// trusted. The stream is left open for the caller.
    /// </summary>
    public static ValidationResult Validate(Stream crate, string declaredName, string declaredVersion)
    {
        try
        {
            using var gzip = new LimitedReadStream(
                new GZipStream(crate, CompressionMode.Decompress, leaveOpen: true),
                TarScanLimits.MaxTotalDecompressedBytes, "Crate");
            using var tar = new TarReader(gzip, leaveOpen: false);

            int entryCount = 0;
            while (tar.GetNextEntry() is { } entry)
            {
                if (++entryCount > TarScanLimits.MaxEntries)
                {
                    return ValidationResult.Fail(
                        "content", $"Crate exceeds the {TarScanLimits.MaxEntries}-entry limit.");
                }

                if (entry.DataStream is null || !CargoTomlReader.IsRootCargoToml(entry.Name))
                {
                    continue;
                }

                return CompareManifest(entry, declaredName, declaredVersion);
            }

            return ValidationResult.Fail(
                "content", "Crate is missing a root Cargo.toml ({name}-{version}/Cargo.toml).");
        }
        catch (Exception ex)
        {
            return ValidationResult.Fail("content", $"Invalid gzip tar: {ex.Message}");
        }
    }

    // Reads the manifest entry under the manifest byte cap and compares its [package] identity
    // and the entry's root directory against the declared coordinates. Name and version are
    // compared ordinally: cargo writes both strings into the frame straight from the manifest,
    // so any difference at all means the frame was not produced from this archive.
    private static ValidationResult CompareManifest(TarEntry entry, string declaredName, string declaredVersion)
    {
        using var limited = new LimitedReadStream(
            entry.DataStream!, TarScanLimits.MaxManifestBytes, "Cargo.toml");
        using var ms = new MemoryStream();
        limited.CopyTo(ms);
        string text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);

        string? name = null;
        string? version = null;
        CargoTomlReader.ScanPackageTable(text, (key, value) =>
        {
            switch (key)
            {
                case "name" when name is null: name = value; break;
                case "version" when version is null: version = value; break;
                default: break;
            }
        });

        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(version))
        {
            return ValidationResult.Fail(
                "content", "Crate's Cargo.toml has no parseable [package] name and version.");
        }

        if (!string.Equals(name, declaredName, StringComparison.Ordinal))
        {
            return ValidationResult.Fail(
                "name", $"Crate's Cargo.toml names package '{name}' but the publish declared '{declaredName}'.");
        }

        if (!string.Equals(version, declaredVersion, StringComparison.Ordinal))
        {
            return ValidationResult.Fail(
                "vers", $"Crate's Cargo.toml is version '{version}' but the publish declared '{declaredVersion}'.");
        }

        string rootDir = entry.Name[..entry.Name.IndexOf('/')];
        string expectedRoot = $"{declaredName}-{declaredVersion}";
        return string.Equals(rootDir, expectedRoot, StringComparison.Ordinal)
            ? ValidationResult.Ok()
            : ValidationResult.Fail(
                "content", $"Crate unpacks to '{rootDir}/' but cargo requires '{expectedRoot}/' for these coordinates.");
    }
}
