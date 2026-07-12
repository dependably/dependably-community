using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.IO;

namespace Dependably.Protocol;

/// <summary>
/// Extracts SPDX license identifier(s) and (where available) a deprecation message
/// from package metadata. Each entry point is failure-tolerant: malformed input
/// returns <see cref="ExtractedMetadata.Empty"/> instead of throwing, so callers
/// can wire it inline next to the version-create call without try/catch.
///
/// <para><b>Stream ownership:</b> all stream-accepting entry points assume the
/// caller hands them a fresh stream positioned at offset 0 and never reads from it
/// afterwards. The extractor takes ownership and disposes the stream before returning.
/// Pass <c>await blob.OpenAsync(ct)</c> directly — do not wrap in <c>using</c>.</para>
///
/// Persistence: license SPDX values via <c>LicenseRepository.SetLicensesAsync</c>
/// (source: <c>"upstream"</c>); deprecation message via
/// <c>PackageRepository.UpdateDeprecatedAsync</c>.
/// </summary>
public static class LicenseExtractor
{
    // Maximum plausible SPDX identifier length (longest known SPDX expression fits well under 100).
    private const int MaxSpdxLength = 100;

    // RecyclableMemoryStream pool for the non-seekable-backend zip path. Default
    // configuration is appropriate for the proxy-fetch artefact range — buffers are
    // capped at the upstream 600 MB ceiling enforced in UpstreamClient.FetchAndStageAsync,
    // and extraction runs serially after the response has been written, so the worst
    // case is a single artefact-sized pooled buffer per fetch (NOT per concurrent
    // download).  Tune only if soak-test telemetry shows LOH pressure on S3/Azure.
    private static readonly RecyclableMemoryStreamManager _streamManager = new();

    public sealed record ExtractedMetadata(IReadOnlyList<string> Spdx, string? Deprecated)
    {
        public static readonly ExtractedMetadata Empty = new(Array.Empty<string>(), null);
    }

    // ── PyPI ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads METADATA from a wheel (zip) or PKG-INFO from an sdist (tar.gz / zip).
    /// <para>Owns <paramref name="stream"/> — see stream-ownership note on the class.</para>
    /// </summary>
    public static ExtractedMetadata FromPyPiPackageBytes(Stream stream, string filename)
    {
        try
        {
            string? text = filename.EndsWith(".whl", StringComparison.OrdinalIgnoreCase)
                ? ReadWheelMetadata(stream)
                : ReadSdistPkgInfo(stream, filename);
            if (text is null)
            {
                return ExtractedMetadata.Empty;
            }

            string[] spdx = ParsePyPiMetadataLicense(text);
            return new ExtractedMetadata(spdx, null);
        }
        catch { return ExtractedMetadata.Empty; }
        finally { stream.Dispose(); }
    }

    private static string? ReadWheelMetadata(Stream stream)
    {
        using var zip = OpenZipArchive(stream, "pypi-wheel");
        var entry = zip.Entries.FirstOrDefault(e =>
            e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
        if (entry is null)
        {
            return null;
        }

        using var entryStream = new LimitedReadStream(
            entry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "Wheel METADATA");
        using var reader = new StreamReader(entryStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string? ReadSdistPkgInfo(Stream stream, string filename)
    {
        // Most PyPI sdists are tar.gz; a small minority are zip. Try tar.gz first when the
        // filename suggests it, otherwise probe both with a buffered re-readable stream.
        bool preferTar = filename.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)
            || filename.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase);

        if (preferTar)
        {
            string? tarResult = TryReadSdistFromTarGz(stream);
            if (tarResult is not null)
            {
                return tarResult;
            }
            // Tar parse failed — we've consumed the upstream stream so we can't retry as
            // zip. PyPI almost never serves sdists with a tar.gz extension that aren't
            // actually tar.gz; returning null is the same fail-soft we had previously.
            return null;
        }

        // Unknown extension or .zip — buffer once via the pool so we can probe both
        // formats without an extra IO round-trip to the blob store.
        return TryReadSdistFromZipOrTarBuffered(stream);
    }

    private static string? TryReadSdistFromTarGz(Stream stream)
    {
        try
        {
            using var gzip = new LimitedReadStream(
                new GZipStream(stream, CompressionMode.Decompress, leaveOpen: false),
                ArchiveDecompressLimits.MaxDecompressedBytes, "PyPI sdist tar.gz");
            using var tar = new TarReader(gzip, leaveOpen: false);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.DataStream is null)
                {
                    continue;
                }

                if (!entry.Name.EndsWith("/PKG-INFO", StringComparison.Ordinal))
                {
                    continue;
                }

                using var ms = new MemoryStream();
                entry.DataStream.CopyTo(ms);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
        catch { /* malformed gzip / tar / over decompression limit — return null, caller tolerates */ }
        return null;
    }

    private static string? TryReadSdistFromZipOrTarBuffered(Stream stream)
    {
        // Buffer to a pooled stream so we can rewind between tar and zip probes without
        // re-reading from the blob store. The pooled buffer returns to the pool on dispose.
        using var pooled = _streamManager.GetStream("pypi-sdist-probe");
        stream.CopyTo(pooled);
        pooled.Position = 0;

        try
        {
            using var gzip = new LimitedReadStream(
                new GZipStream(pooled, CompressionMode.Decompress, leaveOpen: true),
                ArchiveDecompressLimits.MaxDecompressedBytes, "PyPI sdist tar.gz probe");
            using var tar = new TarReader(gzip, leaveOpen: false);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.DataStream is null)
                {
                    continue;
                }

                if (!entry.Name.EndsWith("/PKG-INFO", StringComparison.Ordinal))
                {
                    continue;
                }

                using var ms = new MemoryStream();
                entry.DataStream.CopyTo(ms);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
        catch { /* fall through to zip probe */ }

        try
        {
            pooled.Position = 0;
            using var zip = new ZipArchive(pooled, ZipArchiveMode.Read, leaveOpen: true);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.Name.Equals("PKG-INFO", StringComparison.Ordinal));
            if (entry is null)
            {
                return null;
            }

            using var entryStream = new LimitedReadStream(
                entry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "sdist PKG-INFO");
            using var reader = new StreamReader(entryStream, Encoding.UTF8);
            return reader.ReadToEnd();
        }
        catch { return null; }
    }

    /// <summary>
    /// RFC 822-style header parse. Stops at first blank line. Continuation lines
    /// (starting with whitespace) extend the prior field. Prefers
    /// <c>License-Expression</c> (PEP 639, SPDX) over the legacy free-text
    /// <c>License</c> field, which is only accepted when it looks SPDX-shaped.
    /// Classifier mapping is intentionally skipped — the long tail is too noisy.
    /// </summary>
    private static string[] ParsePyPiMetadataLicense(string text)
    {
        string? expression = null;
        string? freeForm = null;

        foreach (var (key, value) in ParseRfc822Headers(text))
        {
            if (key.Equals("License-Expression", StringComparison.OrdinalIgnoreCase) && IsPlausibleSpdx(value))
            {
                expression = value.Trim();
            }
            else if (key.Equals("License", StringComparison.OrdinalIgnoreCase) && IsPlausibleSpdx(value))
            {
                freeForm = value.Trim();
            }
        }

        return !string.IsNullOrEmpty(expression)
            ? (new[] { expression })
            : !string.IsNullOrEmpty(freeForm) ? (new[] { freeForm }) : Array.Empty<string>();
    }

    // RFC 822-style header parser. Stops at first blank line. Continuation lines (starting with
    // whitespace) extend the prior field. Yields (key, value) pairs in source order.
    private static IEnumerable<(string Key, string Value)> ParseRfc822Headers(string text)
    {
        string? currentKey = null;
        var sb = new StringBuilder();

        using var reader = new StringReader(text);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length == 0)
            {
                break;
            }

            if (currentKey is not null && (line[0] == ' ' || line[0] == '\t'))
            {
                sb.Append('\n').Append(line.TrimStart());
                continue;
            }

            if (currentKey is not null)
            {
                yield return (currentKey, sb.ToString());
            }

            int idx = line.IndexOf(':');
            if (idx <= 0) { currentKey = null; continue; }
            currentKey = line[..idx].Trim();
            sb.Clear();
            sb.Append(line[(idx + 1)..].Trim());
        }

        if (currentKey is not null)
        {
            yield return (currentKey, sb.ToString());
        }
    }

    /// <summary>
    /// Pulls a deprecation message out of a single <c>urls[]</c> entry from PyPI's
    /// per-version JSON API: <c>yanked: true</c> → <c>yanked_reason</c> when non-empty,
    /// otherwise the literal <c>"Yanked"</c> so the UI badge always has something to
    /// show. License never lives here (PyPI's metadata fields are on the wheel), so the
    /// SPDX list is always empty.
    /// </summary>
    public static ExtractedMetadata FromPyPiJsonFile(JsonElement urlEntry)
    {
        try
        {
            if (urlEntry.ValueKind != JsonValueKind.Object)
            {
                return ExtractedMetadata.Empty;
            }

            if (!urlEntry.TryGetProperty("yanked", out var yanked))
            {
                return ExtractedMetadata.Empty;
            }

            if (yanked.ValueKind != JsonValueKind.True)
            {
                return ExtractedMetadata.Empty;
            }

            string? reason = urlEntry.TryGetProperty("yanked_reason", out var r)
                && r.ValueKind == JsonValueKind.String ? r.GetString() : null;
            string message = string.IsNullOrWhiteSpace(reason) ? "Yanked" : reason!.Trim();
            return new ExtractedMetadata(Array.Empty<string>(), message);
        }
        catch { return ExtractedMetadata.Empty; }
    }

    /// <summary>
    /// Pulls a license identifier out of a PyPI JSON API <c>info</c> object without needing the
    /// wheel/sdist bytes: prefers <c>license_expression</c> (PEP 639, SPDX) over the legacy
    /// free-text <c>license</c> field, mirroring the METADATA-file precedence in
    /// <see cref="FromPyPiPackageBytes"/>. <c>info</c> always describes the project's latest
    /// release — callers evaluating an older version must not attribute this result to it.
    /// </summary>
    public static ExtractedMetadata FromPyPiJsonInfo(JsonElement info)
    {
        try
        {
            if (info.ValueKind != JsonValueKind.Object)
            {
                return ExtractedMetadata.Empty;
            }

            string? expression = ReadPlausibleSpdxProperty(info, "license_expression");
            string? freeForm = ReadPlausibleSpdxProperty(info, "license");
            string[] spdx = !string.IsNullOrEmpty(expression)
                ? [expression]
                : !string.IsNullOrEmpty(freeForm) ? [freeForm] : [];
            return new ExtractedMetadata(spdx, null);
        }
        catch { return ExtractedMetadata.Empty; }
    }

    private static string? ReadPlausibleSpdxProperty(JsonElement obj, string propertyName)
    {
        if (!obj.TryGetProperty(propertyName, out var el) || el.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? value = el.GetString();
        return value is not null && IsPlausibleSpdx(value) ? value.Trim() : null;
    }

    // ── npm ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parses an npm packument per-version object (or a package.json — same shape).
    /// Handles all three license forms: string (<c>"MIT"</c>), object
    /// (<c>{type, url}</c>), and legacy plural (<c>licenses: [{type}, ...]</c>).
    /// </summary>
    public static ExtractedMetadata FromNpmPackumentVersion(JsonNode? versionNode)
    {
        if (versionNode is null)
        {
            return ExtractedMetadata.Empty;
        }

        try
        {
            var spdx = ParseNpmLicense(versionNode);
            string? deprecated = null;
            try { deprecated = versionNode["deprecated"]?.GetValue<string>(); }
            catch { /* deprecated is sometimes a boolean — ignore */ }
            if (string.IsNullOrWhiteSpace(deprecated))
            {
                deprecated = null;
            }

            return new ExtractedMetadata(spdx, deprecated);
        }
        catch { return ExtractedMetadata.Empty; }
    }

    private static List<string> ParseNpmLicense(JsonNode versionNode)
    {
        var results = new List<string>();
        AddNpmSingleLicense(versionNode["license"], results);
        AddNpmLegacyLicensesArray(versionNode["licenses"], results);
        return results;
    }

    private static void AddNpmSingleLicense(JsonNode? license, List<string> results)
    {
        string? spdx = license switch
        {
            JsonValue v => SafeReadString(v),
            JsonObject o => SafeReadString(o["type"]),
            _ => null,
        };
        AddIfPlausibleSpdx(spdx, results);
    }

    private static void AddNpmLegacyLicensesArray(JsonNode? licenses, List<string> results)
    {
        if (licenses is not JsonArray arr)
        {
            return;
        }

        foreach (var item in arr)
        {
            string? spdx = item switch
            {
                JsonValue v => SafeReadString(v),
                JsonObject o => SafeReadString(o["type"]),
                _ => null,
            };
            AddIfPlausibleSpdx(spdx, results);
        }
    }

    private static string? SafeReadString(JsonNode? node)
    {
        if (node is null)
        {
            return null;
        }

        try { return node.GetValue<string>(); }
        catch { return null; /* non-string node — skip */ }
    }

    private static void AddIfPlausibleSpdx(string? candidate, List<string> results)
    {
        if (string.IsNullOrEmpty(candidate) || !IsPlausibleSpdx(candidate))
        {
            return;
        }

        string trimmed = candidate.Trim();
        if (!results.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
        {
            results.Add(trimmed);
        }
    }

    /// <summary>
    /// Walks an npm tarball to <c>package/package.json</c> and parses it.
    /// <para>Owns <paramref name="tarball"/> — see stream-ownership note on the class.
    /// Streams the gzip / tar without buffering the artefact; the per-entry
    /// <c>package.json</c> body is small (a few KB) and copied into a local
    /// <see cref="MemoryStream"/> for <see cref="JsonNode.Parse(byte[],JsonNodeOptions?,System.Text.Json.JsonDocumentOptions)"/>.</para>
    /// </summary>
    public static ExtractedMetadata FromNpmTarballPackageJson(Stream tarball)
    {
        try
        {
            using var gzip = new LimitedReadStream(
                new GZipStream(tarball, CompressionMode.Decompress, leaveOpen: false),
                ArchiveDecompressLimits.MaxDecompressedBytes, "npm tarball");
            using var tar = new TarReader(gzip, leaveOpen: false);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.DataStream is null)
                {
                    continue;
                }

                if (!entry.Name.EndsWith("package/package.json", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                using var ms = new MemoryStream();
                entry.DataStream.CopyTo(ms);
                var node = JsonNode.Parse(ms.ToArray());
                return FromNpmPackumentVersion(node);
            }
        }
        catch { /* malformed tarball — return empty metadata, callers tolerate */ }
        return ExtractedMetadata.Empty;
    }

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

                if (!IsRootCargoToml(entry.Name))
                {
                    continue;
                }

                using var ms = new MemoryStream();
                entry.DataStream.CopyTo(ms);
                string text = Encoding.UTF8.GetString(ms.ToArray());
                string? license = ParseCargoTomlPackageLicense(text);
                return license is not null
                    ? new ExtractedMetadata(new[] { license }, null)
                    : ExtractedMetadata.Empty;
            }
        }
        catch { /* malformed gzip / tar — return empty metadata, callers tolerate */ }
        return ExtractedMetadata.Empty;
    }

    // True for an entry name shaped exactly "<root-dir>/Cargo.toml" — one path separator,
    // the crate's own manifest at the tarball root. A deeper path (a Cargo.toml bundled in a
    // subdirectory) does not match.
    private static bool IsRootCargoToml(string entryName)
    {
        int slash = entryName.IndexOf('/');
        return slash > 0
            && entryName[(slash + 1)..].Equals("Cargo.toml", StringComparison.Ordinal)
            && entryName.LastIndexOf('/') == slash;
    }

    // Scans a Cargo.toml body line by line, tracking the active [section] header, and returns
    // the [package] table's license = "..." value. A license key encountered while any other
    // section is active (including a nested [package.metadata]) is skipped, so it can never be
    // mistaken for the crate's own license.
    private static string? ParseCargoTomlPackageLicense(string text)
    {
        string? currentSection = null;
        using var reader = new StringReader(text);
        while (reader.ReadLine() is { } rawLine)
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith('['))
            {
                int end = line.IndexOf(']');
                currentSection = end > 0 ? line[1..end].Trim() : null;
                continue;
            }

            if (!string.Equals(currentSection, "package", StringComparison.Ordinal))
            {
                continue;
            }

            int eq = line.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }

            string key = line[..eq].Trim();
            if (!key.Equals("license", StringComparison.Ordinal))
            {
                continue;
            }

            string? unquoted = UnquoteTomlBasicString(line[(eq + 1)..].Trim());
            return unquoted is not null && IsPlausibleSpdx(unquoted) ? unquoted.Trim() : null;
        }
        return null;
    }

    // Extracts the value of a TOML basic (double-quoted) string, ignoring any trailing inline
    // comment. Returns null for any other value shape (literal string, array, etc.) — the
    // narrow line-based parser only supports the form crates.io emits on publish.
    private static string? UnquoteTomlBasicString(string value)
    {
        if (value.Length < 2 || value[0] != '"')
        {
            return null;
        }

        int closingQuote = value.IndexOf('"', 1);
        return closingQuote > 0 ? value[1..closingQuote] : null;
    }

    // ── NuGet ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads the root <c>.nuspec</c> from a <c>.nupkg</c> and pulls
    /// <c>&lt;license type="expression"&gt;</c>. Other forms (<c>type="file"</c>,
    /// legacy <c>licenseUrl</c>) are intentionally ignored — they don't reliably
    /// resolve to SPDX. Deprecation never lives in the nuspec, so always null here.
    /// <para>Owns <paramref name="nupkgStream"/> — see stream-ownership note on the class.
    /// Memory cost on non-seekable backends: ≈ artefact size during extraction,
    /// bounded by the 600 MB upstream cap, single-instance per fetch (extraction runs
    /// after the response writes), NOT per concurrent download.</para>
    /// </summary>
    public static ExtractedMetadata FromNuspec(Stream nupkgStream)
    {
        try
        {
            using var zip = OpenZipArchive(nupkgStream, "nuspec");
            var entry = zip.Entries.FirstOrDefault(e =>
                e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains('/'));
            if (entry is null)
            {
                return ExtractedMetadata.Empty;
            }

            using var entryStream = new LimitedReadStream(
                entry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "nuspec");
            return ParseNuspecLicense(XDocument.Load(entryStream));
        }
        catch { return ExtractedMetadata.Empty; }
        finally { nupkgStream.Dispose(); }
    }

    /// <summary>
    /// Parses a standalone <c>.nuspec</c> XML document (e.g. fetched directly from a NuGet v3
    /// flat-container <c>{id}/{version}/{id}.nuspec</c> endpoint) without needing the enclosing
    /// <c>.nupkg</c> zip. Shares the license-element parsing with <see cref="FromNuspec"/>.
    /// </summary>
    public static ExtractedMetadata FromNuspecXml(string xml)
    {
        try
        {
            return ParseNuspecLicense(XDocument.Parse(xml));
        }
        catch { return ExtractedMetadata.Empty; }
    }

    private static ExtractedMetadata ParseNuspecLicense(XDocument doc)
    {
        string ns = doc.Root?.Name.NamespaceName ?? "";
        XNamespace xns = ns;
        var metadata = doc.Root?.Element(xns + "metadata");
        var licenseEl = metadata?.Element(xns + "license");
        if (licenseEl is null)
        {
            return ExtractedMetadata.Empty;
        }

        string? type = licenseEl.Attribute("type")?.Value;
        if (!string.Equals(type, "expression", StringComparison.OrdinalIgnoreCase))
        {
            return ExtractedMetadata.Empty;
        }

        string? value = licenseEl.Value?.Trim();
        return string.IsNullOrEmpty(value) || !IsPlausibleSpdx(value)
            ? ExtractedMetadata.Empty
            : new ExtractedMetadata(new[] { value }, null);
    }

    // ── Shared zip helper ─────────────────────────────────────────────────────

    /// <summary>
    /// Opens a <see cref="ZipArchive"/> over <paramref name="stream"/>, honouring the
    /// seekable-backend optimisation. <see cref="ZipArchive"/> needs random access:
    /// <list type="bullet">
    ///   <item>Seekable streams (e.g. <see cref="FileStream"/> from
    ///         <see cref="Storage.LocalBlobStore"/>) are passed through verbatim — zero
    ///         buffering.</item>
    ///   <item>Non-seekable streams (S3/Azure GET response streams) are first copied
    ///         into a pooled <see cref="RecyclableMemoryStream"/>. The caller's stream
    ///         is then disposed; the returned archive holds the pooled buffer and
    ///         returns it to the pool when disposed.</item>
    /// </list>
    /// </summary>
    private static ZipArchive OpenZipArchive(Stream stream, string tag)
    {
        if (stream.CanSeek)
        {
            return new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
        }

        // Buffer the non-seekable upstream into the pool, then open the archive over
        // the pooled stream. Disposing the archive disposes the pooled stream, which
        // returns its buffer to the manager — single artefact-sized allocation per fetch.
        var pooled = _streamManager.GetStream(tag);
        try
        {
            stream.CopyTo(pooled);
            pooled.Position = 0;
            stream.Dispose();
            return new ZipArchive(pooled, ZipArchiveMode.Read, leaveOpen: false);
        }
        catch
        {
            pooled.Dispose();
            throw;
        }
    }

    // ── Shared shape check ────────────────────────────────────────────────────

    /// <summary>
    /// Loose check: short, single-line, made of SPDX-friendly characters plus the
    /// PEP 639 / SPDX expression operators (spaces and parens). We store the value
    /// verbatim — complex expressions like <c>MIT OR Apache-2.0</c> end up as one
    /// row in <c>package_version_licenses</c>, which is a v1 simplification.
    ///
    /// Internal (not private) so other ingest paths that parse a license string
    /// outside this class's own extraction methods — e.g. <c>RpmController</c>
    /// mapping an RPM header <c>License</c> tag via <see cref="RpmLicenseMapper"/> —
    /// can reuse the same shape gate before persisting.
    /// </summary>
    internal static bool IsPlausibleSpdx(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string trimmed = value.Trim();
        if (trimmed.Length is 0 or > MaxSpdxLength)
        {
            return false;
        }

        if (trimmed.Contains('\n') || trimmed.Contains('\r'))
        {
            return false;
        }

        foreach (char c in trimmed)
        {
            if (!(char.IsLetterOrDigit(c) || c is '.' or '-' or '+' or ' ' or '(' or ')'))
            {
                return false;
            }
        }
        return true;
    }

    // ── Maven ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parses a Maven POM's <c>&lt;project&gt;&lt;licenses&gt;&lt;license&gt;</c> block, mapping
    /// each declared <c>&lt;name&gt;</c> / <c>&lt;url&gt;</c> to an SPDX identifier through a
    /// curated table (a URL match wins over a name match). POM namespaces vary — the default
    /// <c>http://maven.apache.org/POM/4.0.0</c>, an older namespace, or none at all — so every
    /// element is matched by local name, not qualified name. A declared name with no table entry
    /// falls through verbatim when it already passes the SPDX shape check (the same tolerance the
    /// PyPI free-text <c>License</c> field gets); anything else is dropped. Multiple
    /// <c>&lt;license&gt;</c> entries each contribute one identifier.
    /// <para>Owns <paramref name="stream"/> — see stream-ownership note on the class. XML parsing
    /// uses the framework default reader (DTD processing prohibited, no external resolver),
    /// mirroring <see cref="FromNuspecXml"/>, so a DTD/XXE payload throws and yields
    /// <see cref="ExtractedMetadata.Empty"/>.</para>
    /// </summary>
    public static ExtractedMetadata FromPomXml(Stream stream)
    {
        try
        {
            return ParsePomLicenses(XDocument.Load(stream));
        }
        catch { return ExtractedMetadata.Empty; }
        finally { stream.Dispose(); }
    }

    private static ExtractedMetadata ParsePomLicenses(XDocument doc)
    {
        var root = doc.Root;
        if (root is null || !root.Name.LocalName.Equals("project", StringComparison.Ordinal))
        {
            return ExtractedMetadata.Empty;
        }

        var licensesEl = root.Elements().FirstOrDefault(
            e => e.Name.LocalName.Equals("licenses", StringComparison.Ordinal));
        if (licensesEl is null)
        {
            return ExtractedMetadata.Empty;
        }

        var results = new List<string>();
        foreach (var licenseEl in licensesEl.Elements().Where(
            e => e.Name.LocalName.Equals("license", StringComparison.Ordinal)))
        {
            string? name = LocalChildValue(licenseEl, "name");
            string? url = LocalChildValue(licenseEl, "url");
            AddIfPlausibleSpdx(MapPomLicense(name, url), results);
        }

        return results.Count == 0 ? ExtractedMetadata.Empty : new ExtractedMetadata(results, null);
    }

    private static string? LocalChildValue(XElement parent, string localName)
    {
        var el = parent.Elements().FirstOrDefault(
            e => e.Name.LocalName.Equals(localName, StringComparison.Ordinal));
        string? value = el?.Value?.Trim();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    /// <summary>
    /// Resolves one <c>&lt;license&gt;</c> to an SPDX identifier: a normalized-URL match wins,
    /// then a normalized-name match, then the raw name falls through verbatim (the caller's
    /// shape check keeps it only when it already looks SPDX-shaped).
    /// </summary>
    private static string? MapPomLicense(string? name, string? url)
    {
        return url is not null && PomUrlToSpdx.TryGetValue(NormalizeUrl(url), out string? byUrl)
            ? byUrl
            : name is not null && PomNameToSpdx.TryGetValue(NormalizeName(name), out string? byName)
                ? byName
                : name;
    }

    // Lowercase + whitespace-collapsed so table keys match regardless of the casing and internal
    // spacing upstream POMs use for the same license string. Internal (not private) so
    // LicenseNormalizer can reuse the exact same key-derivation algorithm against the
    // spdx_license.name→identifier map and the alias overlay.
    internal static string NormalizeName(string name)
    {
        var sb = new StringBuilder(name.Length);
        bool prevSpace = false;
        foreach (char c in name.Trim())
        {
            if (char.IsWhiteSpace(c))
            {
                if (!prevSpace)
                {
                    sb.Append(' ');
                    prevSpace = true;
                }
            }
            else
            {
                sb.Append(char.ToLowerInvariant(c));
                prevSpace = false;
            }
        }
        return sb.ToString();
    }

    // Scheme-agnostic, trailing-slash-agnostic, lowercase so http/https and a trailing slash all
    // collapse to one table key.
    private static string NormalizeUrl(string url)
    {
        string u = url.Trim().ToLowerInvariant();
        if (u.StartsWith("https://", StringComparison.Ordinal))
        {
            u = u["https://".Length..];
        }
        else if (u.StartsWith("http://", StringComparison.Ordinal))
        {
            u = u["http://".Length..];
        }
        return u.TrimEnd('/');
    }

    // Curated name→SPDX table. Keys are pre-normalized (lowercase, single-spaced) to match
    // NormalizeName output. Covers the license strings the common Maven Central artifacts declare.
    private static readonly Dictionary<string, string> PomNameToSpdx = new(StringComparer.Ordinal)
    {
        // Apache-2.0
        ["apache license, version 2.0"] = "Apache-2.0",
        ["the apache software license, version 2.0"] = "Apache-2.0",
        ["apache license version 2.0"] = "Apache-2.0",
        ["apache license 2.0"] = "Apache-2.0",
        ["apache 2.0"] = "Apache-2.0",
        ["apache 2"] = "Apache-2.0",
        ["apache-2.0"] = "Apache-2.0",
        // MIT
        ["mit license"] = "MIT",
        ["the mit license"] = "MIT",
        ["the mit license (mit)"] = "MIT",
        ["mit"] = "MIT",
        // BSD-2-Clause
        ["bsd 2-clause license"] = "BSD-2-Clause",
        ["the bsd 2-clause license"] = "BSD-2-Clause",
        ["simplified bsd license"] = "BSD-2-Clause",
        ["bsd-2-clause"] = "BSD-2-Clause",
        // BSD-3-Clause
        ["bsd 3-clause license"] = "BSD-3-Clause",
        ["the bsd 3-clause license"] = "BSD-3-Clause",
        ["new bsd license"] = "BSD-3-Clause",
        ["the new bsd license"] = "BSD-3-Clause",
        ["modified bsd license"] = "BSD-3-Clause",
        ["bsd-3-clause"] = "BSD-3-Clause",
        // EPL-1.0
        ["eclipse public license 1.0"] = "EPL-1.0",
        ["eclipse public license - v 1.0"] = "EPL-1.0",
        ["eclipse public license v1.0"] = "EPL-1.0",
        ["epl-1.0"] = "EPL-1.0",
        // EPL-2.0
        ["eclipse public license 2.0"] = "EPL-2.0",
        ["eclipse public license - v 2.0"] = "EPL-2.0",
        ["eclipse public license v2.0"] = "EPL-2.0",
        ["epl-2.0"] = "EPL-2.0",
        // LGPL-2.1 (only vs or-later per declared text; bare LGPL-2.1 is a deprecated SPDX id —
        // GetReviewQueueAsync filters deprecated ids out of the default review queue, so every
        // GNU family mapping below resolves to a non-deprecated -only/-or-later id)
        ["gnu lesser general public license, version 2.1"] = "LGPL-2.1-only",
        ["gnu lesser general public license v2.1"] = "LGPL-2.1-only",
        ["lgpl 2.1"] = "LGPL-2.1-only",
        ["lgpl-2.1"] = "LGPL-2.1-only",
        ["lgpl-2.1-only"] = "LGPL-2.1-only",
        ["gnu lesser general public license v2.1 or later"] = "LGPL-2.1-or-later",
        ["lgpl-2.1-or-later"] = "LGPL-2.1-or-later",
        // LGPL-3.0 (only vs or-later per declared text)
        ["gnu lesser general public license v3.0"] = "LGPL-3.0-only",
        ["gnu lesser general public license, version 3"] = "LGPL-3.0-only",
        ["lgpl 3.0"] = "LGPL-3.0-only",
        ["lgpl-3.0"] = "LGPL-3.0-only",
        ["lgpl-3.0-only"] = "LGPL-3.0-only",
        ["gnu lesser general public license v3.0 or later"] = "LGPL-3.0-or-later",
        ["lgpl-3.0-or-later"] = "LGPL-3.0-or-later",
        // GPL-2.0 (only vs or-later per declared text; bare GPL-2.0 is deprecated)
        ["gnu general public license, version 2"] = "GPL-2.0-only",
        ["gnu general public license v2.0"] = "GPL-2.0-only",
        ["gpl 2.0"] = "GPL-2.0-only",
        ["gpl-2.0"] = "GPL-2.0-only",
        ["gpl-2.0-only"] = "GPL-2.0-only",
        ["gnu general public license v2.0 or later"] = "GPL-2.0-or-later",
        ["gpl-2.0-or-later"] = "GPL-2.0-or-later",
        // GPL-3.0 (only vs or-later per declared text; bare GPL-3.0 is deprecated)
        ["gnu general public license, version 3"] = "GPL-3.0-only",
        ["gnu general public license v3.0"] = "GPL-3.0-only",
        ["gpl 3.0"] = "GPL-3.0-only",
        ["gpl-3.0"] = "GPL-3.0-only",
        ["gpl-3.0-only"] = "GPL-3.0-only",
        ["gnu general public license v3.0 or later"] = "GPL-3.0-or-later",
        ["gpl-3.0-or-later"] = "GPL-3.0-or-later",
        // MPL-2.0
        ["mozilla public license 2.0"] = "MPL-2.0",
        ["mozilla public license version 2.0"] = "MPL-2.0",
        ["mozilla public license, version 2.0"] = "MPL-2.0",
        ["mpl 2.0"] = "MPL-2.0",
        ["mpl-2.0"] = "MPL-2.0",
        // CDDL-1.0
        ["common development and distribution license 1.0"] = "CDDL-1.0",
        ["common development and distribution license (cddl) v1.0"] = "CDDL-1.0",
        ["common development and distribution license"] = "CDDL-1.0",
        ["cddl 1.0"] = "CDDL-1.0",
        ["cddl-1.0"] = "CDDL-1.0",
        // ISC
        ["isc license"] = "ISC",
        ["the isc license"] = "ISC",
        ["isc"] = "ISC",
    };

    // Curated URL→SPDX table. Keys are pre-normalized (scheme-stripped, lowercase, no trailing
    // slash) to match NormalizeUrl output. A URL match takes precedence over a name match.
    private static readonly Dictionary<string, string> PomUrlToSpdx = new(StringComparer.Ordinal)
    {
        // Apache-2.0
        ["apache.org/licenses/license-2.0"] = "Apache-2.0",
        ["www.apache.org/licenses/license-2.0"] = "Apache-2.0",
        ["apache.org/licenses/license-2.0.txt"] = "Apache-2.0",
        ["www.apache.org/licenses/license-2.0.txt"] = "Apache-2.0",
        // MIT
        ["opensource.org/licenses/mit"] = "MIT",
        ["opensource.org/licenses/mit-license.php"] = "MIT",
        // BSD
        ["opensource.org/licenses/bsd-2-clause"] = "BSD-2-Clause",
        ["opensource.org/licenses/bsd-3-clause"] = "BSD-3-Clause",
        // EPL
        ["eclipse.org/legal/epl-v10.html"] = "EPL-1.0",
        ["www.eclipse.org/legal/epl-v10.html"] = "EPL-1.0",
        ["eclipse.org/legal/epl-2.0"] = "EPL-2.0",
        ["www.eclipse.org/legal/epl-2.0"] = "EPL-2.0",
        // LGPL / GPL — every canonical gnu.org license URL is unversioned as to "only" vs
        // "or later" (that distinction lives in the covered work's declared text, not the URL),
        // so URL matches resolve to the non-deprecated -only id; -or-later is name-only above.
        ["gnu.org/licenses/lgpl-2.1.html"] = "LGPL-2.1-only",
        ["www.gnu.org/licenses/lgpl-2.1.html"] = "LGPL-2.1-only",
        ["gnu.org/licenses/old-licenses/lgpl-2.1.html"] = "LGPL-2.1-only",
        ["gnu.org/licenses/lgpl-3.0.html"] = "LGPL-3.0-only",
        ["www.gnu.org/licenses/lgpl-3.0.html"] = "LGPL-3.0-only",
        ["gnu.org/licenses/gpl-2.0.html"] = "GPL-2.0-only",
        ["www.gnu.org/licenses/gpl-2.0.html"] = "GPL-2.0-only",
        ["gnu.org/licenses/gpl-3.0.html"] = "GPL-3.0-only",
        ["www.gnu.org/licenses/gpl-3.0.html"] = "GPL-3.0-only",
        // MPL
        ["mozilla.org/mpl/2.0"] = "MPL-2.0",
        ["www.mozilla.org/mpl/2.0"] = "MPL-2.0",
        ["mozilla.org/en-us/mpl/2.0"] = "MPL-2.0",
        // CDDL / ISC
        ["opensource.org/licenses/cddl-1.0"] = "CDDL-1.0",
        ["opensource.org/licenses/isc"] = "ISC",
    };
}
