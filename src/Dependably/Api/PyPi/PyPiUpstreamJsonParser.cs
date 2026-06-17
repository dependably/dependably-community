using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Pure-static helpers for parsing the PyPI JSON API response on first fetch.
/// Extracted from <see cref="PyPiProxyFetcher"/> to keep that class under the
/// S1200 coupling limit — the JSON parsing types (<see cref="JsonDocument"/>,
/// <see cref="JsonElement"/>, etc.) are isolated here.
/// </summary>
internal static class PyPiUpstreamJsonParser
{
    /// <summary>
    /// Parses a PyPI JSON API <c>urls[]</c> entry matching <paramref name="file"/>,
    /// returning the <c>upload_time_iso_8601</c>, <c>digests.sha256</c>, and deprecation
    /// status from the matched entry. Returns <see cref="PyPiJsonMetadata.Empty"/> when
    /// no matching entry is found or parsing fails.
    /// </summary>
    internal static PyPiJsonMetadata ParseUrlsArrayForFile(byte[] jsonBody, string file)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonBody);
            if (!doc.RootElement.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array)
            {
                return PyPiJsonMetadata.Empty;
            }

            var match = urls.EnumerateArray().FirstOrDefault(entry => EntryMatchesFilename(entry, file));
            return match.ValueKind == JsonValueKind.Undefined ? PyPiJsonMetadata.Empty : ParseUrlEntry(match);
        }
        catch { return PyPiJsonMetadata.Empty; }
    }

    private static bool EntryMatchesFilename(JsonElement entry, string file) =>
        entry.TryGetProperty("filename", out var fn) &&
        fn.ValueKind == JsonValueKind.String &&
        string.Equals(fn.GetString(), file, StringComparison.OrdinalIgnoreCase);

    private static PyPiJsonMetadata ParseUrlEntry(JsonElement entry)
    {
        DateTimeOffset? publishedAt = null;
        string? iso = entry.TryGetProperty("upload_time_iso_8601", out var t) ? t.GetString() : null;
        if (DateTimeOffset.TryParse(iso, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
        {
            publishedAt = ts;
        }

        string? sha256 = null;
        if (entry.TryGetProperty("digests", out var digests)
            && digests.ValueKind == JsonValueKind.Object
            && digests.TryGetProperty("sha256", out var d)
            && d.ValueKind == JsonValueKind.String)
        {
            sha256 = d.GetString()?.ToLowerInvariant();
        }

        string? deprecated = LicenseExtractor.FromPyPiJsonFile(entry).Deprecated;

        return new PyPiJsonMetadata(publishedAt, sha256, deprecated);
    }
}
