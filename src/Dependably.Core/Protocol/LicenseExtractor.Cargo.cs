using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.IO;

namespace Dependably.Protocol;

/// <summary>
/// The Cargo half of <see cref="LicenseExtractor"/>: reading a crate's <c>Cargo.toml</c>
/// <c>[package]</c> table out of a <c>.crate</c> archive. Split from the other ecosystems by file
/// only — one partial class. The line-level TOML readers live in <see cref="CargoTomlReader"/>,
/// shared with the publish-time coordinate cross-check in <see cref="CargoCrateValidator"/>.
/// </summary>
public static partial class LicenseExtractor
{
    // ── Cargo ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Validates the crates.io publish-envelope <c>license</c> field (SPDX expression).
    /// <c>license-file</c> is never modelled here — it names a file bundled in the crate
    /// rather than carrying an SPDX expression itself, so it has no license signal to extract.
    /// </summary>
    public static ExtractedMetadata FromCargoPublishLicense(string? license)
    {
        return string.IsNullOrWhiteSpace(license) || !IsPlausibleSpdx(license)
            ? ExtractedMetadata.Empty
            : new ExtractedMetadata(new[] { license.Trim() }, null);
    }

    /// <summary>
    /// Walks a Cargo <c>.crate</c> tarball (gzip tar) to the crate's root-directory manifest
    /// (<c>{name}-{version}/Cargo.toml</c>, depth 1 — a nested <c>Cargo.toml</c> inside a
    /// bundled subdirectory is not the crate's own manifest) and pulls the <c>license</c> key
    /// out of the <c>[package]</c> table with a minimal line-based parser. No TOML library is
    /// used: crates.io normalizes a published manifest's <c>[package]</c> table onto single
    /// <c>key = "value"</c> lines, so line-based scanning is safe for this narrow case.
    /// <c>license-file</c> is ignored — it names a file inside the crate, not an SPDX
    /// expression — and a <c>license</c> key outside <c>[package]</c> (e.g. under
    /// <c>[dependencies.foo]</c>) is never matched.
    /// <para>Owns <paramref name="tarball"/> — see stream-ownership note on the class.</para>
    /// </summary>
    public static ExtractedMetadata FromCrateTarball(Stream tarball)
    {
        try
        {
            using var gzip = new LimitedReadStream(
                new GZipStream(tarball, CompressionMode.Decompress, leaveOpen: false),
                ArchiveDecompressLimits.MaxDecompressedBytes, "cargo crate tarball");
            using var tar = new TarReader(gzip, leaveOpen: false);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.DataStream is null)
                {
                    continue;
                }

                if (!CargoTomlReader.IsRootCargoToml(entry.Name))
                {
                    continue;
                }

                using var ms = new MemoryStream();
                entry.DataStream.CopyTo(ms);
                string text = Encoding.UTF8.GetString(ms.ToArray());
                var (license, homepage, repository, description, author) = ParseCargoTomlPackage(text);
                return new ExtractedMetadata(
                    license is not null ? new[] { license } : Array.Empty<string>(),
                    null, homepage, repository, description, author);
            }
        }
        catch { /* malformed gzip / tar — return empty metadata, callers tolerate */ }
        return ExtractedMetadata.Empty;
    }

    // `authors = ["A <a@x>", "B"]` — joined into one display string. Null for any other array key
    // or an empty array, which names nobody.
    private static string? AuthorsDisplay(string arrayKey, List<string> entries)
        => string.Equals(arrayKey, "authors", StringComparison.Ordinal) && entries.Count > 0
            ? string.Join(", ", entries)
            : null;

    /// <summary>
    /// The <c>[package]</c> values this parser collects, as a mutable carrier: the caller fills it
    /// line by line, and first-write-wins per key is expressed by each arm's own null guard.
    /// </summary>
    private sealed class CargoPackageFields
    {
        public string? License { get; set; }
        public string? Homepage { get; set; }
        public string? Repository { get; set; }
        public string? Description { get; set; }
        public string? Author { get; set; }
    }

    // First occurrence of each key wins. `license` additionally has to look like an SPDX
    // expression — a free-text licence field is not a licence identifier and must not be stored
    // as one.
    private static void ApplyCargoPackageKey(CargoPackageFields fields, string key, string value)
    {
        switch (key)
        {
            case "license" when fields.License is null && IsPlausibleSpdx(value): fields.License = value.Trim(); break;
            case "homepage" when fields.Homepage is null: fields.Homepage = value; break;
            case "repository" when fields.Repository is null: fields.Repository = value; break;
            case "description" when fields.Description is null: fields.Description = value; break;
            default: break;
        }
    }

    private static (string? License, string? Homepage, string? Repository, string? Description, string? Author)
        ParseCargoTomlPackage(string text)
    {
        var fields = new CargoPackageFields();
        CargoTomlReader.ScanPackageTable(
            text,
            (key, value) => ApplyCargoPackageKey(fields, key, value),
            (arrayKey, entries) => fields.Author ??= AuthorsDisplay(arrayKey, entries));

        string? license = fields.License;
        string? homepage = fields.Homepage;
        string? repository = fields.Repository;
        string? description = fields.Description;
        string? author = fields.Author;

        return (
            license,
            Clip(HttpUrlOrNull(homepage)),
            Clip(NormalizeRepositoryUrl(repository)),
            Clip(description),
            Clip(author));
    }
}
