using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace Dependably.Protocol;

/// <summary>
/// Extracts SPDX license identifier(s) and (where available) a deprecation message
/// from package metadata. Each entry point is failure-tolerant: malformed input
/// returns <see cref="ExtractedMetadata.Empty"/> instead of throwing, so callers
/// can wire it inline next to the version-create call without try/catch.
///
/// Persistence: license SPDX values via <c>LicenseRepository.SetLicensesAsync</c>
/// (source: <c>"upstream"</c>); deprecation message via
/// <c>PackageRepository.UpdateDeprecatedAsync</c>.
/// </summary>
public static class LicenseExtractor
{
    public sealed record ExtractedMetadata(IReadOnlyList<string> Spdx, string? Deprecated)
    {
        public static readonly ExtractedMetadata Empty = new(Array.Empty<string>(), null);
    }

    // ── PyPI ──────────────────────────────────────────────────────────────────

    /// <summary>Reads METADATA from a wheel (zip) or PKG-INFO from an sdist (tar.gz / zip).</summary>
    public static ExtractedMetadata FromPyPiPackageBytes(byte[] bytes, string filename)
    {
        try
        {
            var text = filename.EndsWith(".whl", StringComparison.OrdinalIgnoreCase)
                ? ReadWheelMetadata(bytes)
                : ReadSdistPkgInfo(bytes);
            if (text is null) return ExtractedMetadata.Empty;
            var spdx = ParsePyPiMetadataLicense(text);
            return new ExtractedMetadata(spdx, null);
        }
        catch { return ExtractedMetadata.Empty; }
    }

    private static string? ReadWheelMetadata(byte[] bytes)
    {
        using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        var entry = zip.Entries.FirstOrDefault(e =>
            e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
        if (entry is null) return null;
        using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string? ReadSdistPkgInfo(byte[] bytes)
    {
        // Most PyPI sdists are tar.gz; a small minority are zip.
        try
        {
            using var gzip = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
            using var tar = new TarReader(gzip, leaveOpen: false);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.DataStream is null) continue;
                if (!entry.Name.EndsWith("/PKG-INFO", StringComparison.Ordinal)) continue;
                using var ms = new MemoryStream();
                entry.DataStream.CopyTo(ms);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
        catch { /* fall through to zip */ }

        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.Name.Equals("PKG-INFO", StringComparison.Ordinal));
            if (entry is null) return null;
            using var stream = entry.Open();
            using var reader = new StreamReader(stream, Encoding.UTF8);
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
                expression = value.Trim();
            else if (key.Equals("License", StringComparison.OrdinalIgnoreCase) && IsPlausibleSpdx(value))
                freeForm = value.Trim();
        }

        if (!string.IsNullOrEmpty(expression)) return new[] { expression };
        if (!string.IsNullOrEmpty(freeForm)) return new[] { freeForm };
        return Array.Empty<string>();
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
            if (line.Length == 0) break;

            if (currentKey is not null && (line[0] == ' ' || line[0] == '\t'))
            {
                sb.Append('\n').Append(line.TrimStart());
                continue;
            }

            if (currentKey is not null)
                yield return (currentKey, sb.ToString());

            var idx = line.IndexOf(':');
            if (idx <= 0) { currentKey = null; continue; }
            currentKey = line[..idx].Trim();
            sb.Clear();
            sb.Append(line[(idx + 1)..].Trim());
        }

        if (currentKey is not null)
            yield return (currentKey, sb.ToString());
    }

    // ── npm ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parses an npm packument per-version object (or a package.json — same shape).
    /// Handles all three license forms: string (<c>"MIT"</c>), object
    /// (<c>{type, url}</c>), and legacy plural (<c>licenses: [{type}, ...]</c>).
    /// </summary>
    public static ExtractedMetadata FromNpmPackumentVersion(JsonNode? versionNode)
    {
        if (versionNode is null) return ExtractedMetadata.Empty;
        try
        {
            var spdx = ParseNpmLicense(versionNode);
            string? deprecated = null;
            try { deprecated = versionNode["deprecated"]?.GetValue<string>(); }
            catch { /* deprecated is sometimes a boolean — ignore */ }
            if (string.IsNullOrWhiteSpace(deprecated)) deprecated = null;
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
        var spdx = license switch
        {
            JsonValue v  => SafeReadString(v),
            JsonObject o => SafeReadString(o["type"]),
            _            => null,
        };
        AddIfPlausibleSpdx(spdx, results);
    }

    private static void AddNpmLegacyLicensesArray(JsonNode? licenses, List<string> results)
    {
        if (licenses is not JsonArray arr) return;
        foreach (var item in arr)
        {
            var spdx = item switch
            {
                JsonValue v  => SafeReadString(v),
                JsonObject o => SafeReadString(o["type"]),
                _            => null,
            };
            AddIfPlausibleSpdx(spdx, results);
        }
    }

    private static string? SafeReadString(JsonNode? node)
    {
        if (node is null) return null;
        try { return node.GetValue<string>(); }
        catch { return null; /* non-string node — skip */ }
    }

    private static void AddIfPlausibleSpdx(string? candidate, List<string> results)
    {
        if (string.IsNullOrEmpty(candidate) || !IsPlausibleSpdx(candidate)) return;
        var trimmed = candidate.Trim();
        if (!results.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
            results.Add(trimmed);
    }

    /// <summary>Walks an npm tarball to <c>package/package.json</c> and parses it.</summary>
    public static ExtractedMetadata FromNpmTarballPackageJson(byte[] tarball)
    {
        try
        {
            using var gzip = new GZipStream(new MemoryStream(tarball), CompressionMode.Decompress);
            using var tar = new TarReader(gzip, leaveOpen: false);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.DataStream is null) continue;
                if (!entry.Name.EndsWith("package/package.json", StringComparison.OrdinalIgnoreCase))
                    continue;
                using var ms = new MemoryStream();
                entry.DataStream.CopyTo(ms);
                var node = JsonNode.Parse(ms.ToArray());
                return FromNpmPackumentVersion(node);
            }
        }
        catch { /* malformed tarball — return empty metadata, callers tolerate */ }
        return ExtractedMetadata.Empty;
    }

    // ── NuGet ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads the root <c>.nuspec</c> from a <c>.nupkg</c> and pulls
    /// <c>&lt;license type="expression"&gt;</c>. Other forms (<c>type="file"</c>,
    /// legacy <c>licenseUrl</c>) are intentionally ignored — they don't reliably
    /// resolve to SPDX. Deprecation never lives in the nuspec, so always null here.
    /// </summary>
    public static ExtractedMetadata FromNuspec(byte[] nupkgBytes)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(nupkgBytes), ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains('/'));
            if (entry is null) return ExtractedMetadata.Empty;

            using var stream = entry.Open();
            var doc = XDocument.Load(stream);
            var ns = doc.Root?.Name.NamespaceName ?? "";
            XNamespace xns = ns;
            var metadata = doc.Root?.Element(xns + "metadata");
            var licenseEl = metadata?.Element(xns + "license");
            if (licenseEl is null) return ExtractedMetadata.Empty;

            var type = licenseEl.Attribute("type")?.Value;
            if (!string.Equals(type, "expression", StringComparison.OrdinalIgnoreCase))
                return ExtractedMetadata.Empty;

            var value = licenseEl.Value?.Trim();
            if (string.IsNullOrEmpty(value) || !IsPlausibleSpdx(value))
                return ExtractedMetadata.Empty;

            return new ExtractedMetadata(new[] { value }, null);
        }
        catch { return ExtractedMetadata.Empty; }
    }

    // ── Shared shape check ────────────────────────────────────────────────────

    /// <summary>
    /// Loose check: short, single-line, made of SPDX-friendly characters plus the
    /// PEP 639 / SPDX expression operators (spaces and parens). We store the value
    /// verbatim — complex expressions like <c>MIT OR Apache-2.0</c> end up as one
    /// row in <c>package_version_licenses</c>, which is a v1 simplification.
    /// </summary>
    private static bool IsPlausibleSpdx(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var trimmed = value.Trim();
        if (trimmed.Length is 0 or > 100) return false;
        if (trimmed.Contains('\n') || trimmed.Contains('\r')) return false;
        foreach (var c in trimmed)
        {
            if (!(char.IsLetterOrDigit(c) || c is '.' or '-' or '+' or ' ' or '(' or ')'))
                return false;
        }
        return true;
    }
}
