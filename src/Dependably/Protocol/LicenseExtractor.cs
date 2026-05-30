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
/// <para><b>Stream ownership (#105):</b> all stream-accepting entry points assume the
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
    // RecyclableMemoryStream pool for the non-seekable-backend zip path (#105). Default
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
            var text = filename.EndsWith(".whl", StringComparison.OrdinalIgnoreCase)
                ? ReadWheelMetadata(stream)
                : ReadSdistPkgInfo(stream, filename);
            if (text is null) return ExtractedMetadata.Empty;
            var spdx = ParsePyPiMetadataLicense(text);
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
        if (entry is null) return null;
        using var entryStream = entry.Open();
        using var reader = new StreamReader(entryStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string? ReadSdistPkgInfo(Stream stream, string filename)
    {
        // Most PyPI sdists are tar.gz; a small minority are zip. Try tar.gz first when the
        // filename suggests it, otherwise probe both with a buffered re-readable stream.
        var preferTar = filename.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)
            || filename.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase);

        if (preferTar)
        {
            var tarResult = TryReadSdistFromTarGz(stream);
            if (tarResult is not null) return tarResult;
            // Tar parse failed — we've consumed the upstream stream so we can't retry as
            // zip. PyPI almost never serves sdists with a tar.gz extension that aren't
            // actually tar.gz; returning null is the same fail-soft we had before #105.
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
            using var gzip = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: false);
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
        catch { /* malformed gzip / tar — return null, caller tolerates */ }
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
            using var gzip = new GZipStream(pooled, CompressionMode.Decompress, leaveOpen: true);
            using var tar = new TarReader(gzip, leaveOpen: true);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.DataStream is null) continue;
                if (!entry.Name.EndsWith("/PKG-INFO", StringComparison.Ordinal)) continue;
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
            if (entry is null) return null;
            using var entryStream = entry.Open();
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
            if (urlEntry.ValueKind != JsonValueKind.Object) return ExtractedMetadata.Empty;
            if (!urlEntry.TryGetProperty("yanked", out var yanked)) return ExtractedMetadata.Empty;
            if (yanked.ValueKind != JsonValueKind.True) return ExtractedMetadata.Empty;

            string? reason = urlEntry.TryGetProperty("yanked_reason", out var r)
                && r.ValueKind == JsonValueKind.String ? r.GetString() : null;
            var message = string.IsNullOrWhiteSpace(reason) ? "Yanked" : reason!.Trim();
            return new ExtractedMetadata(Array.Empty<string>(), message);
        }
        catch { return ExtractedMetadata.Empty; }
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
            using var gzip = new GZipStream(tarball, CompressionMode.Decompress, leaveOpen: false);
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
            if (entry is null) return ExtractedMetadata.Empty;

            using var entryStream = entry.Open();
            var doc = XDocument.Load(entryStream);
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
        finally { nupkgStream.Dispose(); }
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
