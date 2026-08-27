using System.Globalization;
using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// HTTP implementation of <see cref="IThreatFeedSource"/> against the public feeds:
/// the CISA KEV catalog JSON (override via <c>KEV_FEED_URL</c> for mirrors/tests) and the
/// FIRST.org EPSS API (override via <c>EPSS_API_URL</c>). Uses the named "threatfeed"
/// HttpClient registered alongside the OSV client, sharing the SSRF connect-time guard.
/// </summary>
public sealed class HttpThreatFeedSource : IThreatFeedSource
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default for the KEV_FEED_URL environment variable / config key; operators override this to point at a mirror.")]
    public const string DefaultKevFeedUrl =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default for the EPSS_API_URL environment variable / config key; operators override this to point at a mirror.")]
    public const string DefaultEpssApiUrl = "https://api.first.org/data/v1/epss";

    // FIRST.org documents a 100-parameter ceiling per request; staying at it keeps the daily
    // pass to a handful of calls for a typical instance.
    private const int EpssBatchSize = 100;

    // The KEV catalog is a few megabytes today and grows slowly as CISA adds entries; the EPSS
    // batch responses are smaller still (100 CVEs per call). A malicious or compromised feed
    // endpoint should not be able to force unbounded buffering, so both reads share a generous
    // cap well above any expected catalog size without matching the tighter package-metadata cap.
    internal const long MaxFeedResponseBytes = 64L * 1024 * 1024; // 64 MB

    private readonly IHttpClientFactory _httpFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<HttpThreatFeedSource> _logger;

    public HttpThreatFeedSource(
        IHttpClientFactory httpFactory,
        IConfiguration config,
        ILogger<HttpThreatFeedSource> logger)
    {
        _httpFactory = httpFactory;
        _config = config;
        _logger = logger;
    }

    public async Task<IReadOnlyDictionary<string, KevEntry>> GetKevCatalogAsync(CancellationToken ct = default)
    {
        string url = _config["KEV_FEED_URL"] ?? DefaultKevFeedUrl;
        var http = _httpFactory.CreateClient("threatfeed");

        // ResponseHeadersRead is load-bearing: the default (ResponseContentRead) would have
        // HttpClient buffer the whole body before the cap check below ever runs, defeating it.
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        byte[] body = await UpstreamClient.ReadBodyCappedAsync(response, MaxFeedResponseBytes, url, ct);
        using var doc = JsonDocument.Parse(body);

        var entries = new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase);
        int skipped = 0;
        int ransomware = 0;
        if (doc.RootElement.TryGetProperty("vulnerabilities", out var vulns)
            && vulns.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in vulns.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object
                    && entry.TryGetProperty("cveID", out var cve)
                    && cve.ValueKind == JsonValueKind.String
                    && !string.IsNullOrWhiteSpace(cve.GetString()))
                {
                    var parsed = new KevEntry(
                        ParseRansomwareUse(entry),
                        ReadDate(entry, "dateAdded"),
                        ReadDate(entry, "dueDate"),
                        ReadString(entry, "requiredAction"),
                        ReadCwes(entry),
                        ReadString(entry, "notes"));
                    entries[cve.GetString()!.Trim()] = parsed;
                    if (parsed.KnownRansomwareCampaignUse == true)
                    {
                        ransomware++;
                    }
                }
                else
                {
                    skipped++;
                }
            }
        }

        if (skipped > 0)
        {
            _logger.LogWarning("KEV feed contained {Skipped} entries without a usable cveID; skipped.", skipped);
        }

        _logger.LogInformation(
            "KEV feed loaded: {Count} CVE ids, {Ransomware} marked as known ransomware-campaign use.",
            entries.Count, ransomware);
        return entries;
    }

    /// <summary>
    /// Maps CISA's <c>knownRansomwareCampaignUse</c> to the tri-state the column stores.
    /// <c>Known</c> is true and <c>Unknown</c> is false — "Unknown" is CISA asserting no known
    /// use, which is an answer. Anything else, including the field being absent, is null: no
    /// assertion at all. Deliberately not a truthy-string check, so a value this code has never
    /// seen reads as "no assertion" rather than being guessed at.
    /// </summary>
    private static bool? ParseRansomwareUse(JsonElement entry)
    {
        if (!entry.TryGetProperty("knownRansomwareCampaignUse", out var flag)
            || flag.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? value = flag.GetString()?.Trim();
        return string.Equals(value, "Known", StringComparison.OrdinalIgnoreCase) ? true
            : string.Equals(value, "Unknown", StringComparison.OrdinalIgnoreCase) ? false
            : null;
    }

    // KEV publishes calendar dates (YYYY-MM-DD), not instants. Stored as given rather than
    // normalised to a UTC timestamp, because inventing a time of day would be fabricating
    // precision the source does not have.
    private static string? ReadDate(JsonElement entry, string property) =>
        entry.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
        && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;

    // requiredAction and notes are free-text prose fields. Same fail-soft posture as
    // ReadDate/ParseRansomwareUse: a missing or non-string field yields null rather than
    // throwing, and an all-whitespace value is treated as absent rather than a coerced "".
    private static string? ReadString(JsonElement entry, string property) =>
        entry.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String
        && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;

    // cwes is an array of CWE classification ids. Absence of the property entirely is distinct
    // from the property being present with zero elements — null vs. an empty (non-null) list —
    // so callers can tell "CISA never asked" from "CISA recorded zero classifications". A
    // malformed entry (wrong shape, or an array containing something other than a non-blank
    // string) is skipped without failing the whole catalogue entry, matching this parser's
    // posture elsewhere: a strange field never aborts the pass.
    private static IReadOnlyList<string>? ReadCwes(JsonElement entry)
    {
        if (!entry.TryGetProperty("cwes", out var cwes) || cwes.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var ids = new List<string>();
        foreach (var item in cwes.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString()))
            {
                ids.Add(item.GetString()!.Trim());
            }
        }
        return ids;
    }

    public async Task<EpssQueryResult> GetEpssScoresAsync(
        IReadOnlyCollection<string> cveIds, CancellationToken ct = default)
    {
        string baseUrl = _config["EPSS_API_URL"] ?? DefaultEpssApiUrl;
        var http = _httpFactory.CreateClient("threatfeed");

        var scores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        var queried = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string[] batch in cveIds.Distinct(StringComparer.OrdinalIgnoreCase).Chunk(EpssBatchSize))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string url = $"{baseUrl}?cve={Uri.EscapeDataString(string.Join(",", batch))}";
                // ResponseHeadersRead is load-bearing here too — see GetKevCveIdsAsync.
                using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
                response.EnsureSuccessStatusCode();
                byte[] body = await UpstreamClient.ReadBodyCappedAsync(response, MaxFeedResponseBytes, url, ct);
                using var doc = JsonDocument.Parse(body);

                if (doc.RootElement.TryGetProperty("data", out var data)
                    && data.ValueKind == JsonValueKind.Array)
                {
                    ParseEpssDataArray(data, scores);
                }

                // The whole batch counts as queried even for CVEs the API didn't return —
                // absence from a successful response means "unknown to EPSS", a stampable answer.
                queried.UnionWith(batch);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // One failed batch must not abort the pass; the affected CVEs stay out of
                // Queried so their rows go unstamped and retry on the next pass.
                _logger.LogWarning(ex, "EPSS batch of {Count} CVEs failed; continuing with remaining batches.", batch.Length);
            }
        }

        _logger.LogInformation(
            "EPSS query complete: {Scored} scored of {Queried} queried ({Total} requested).",
            scores.Count, queried.Count, cveIds.Count);
        return new EpssQueryResult(scores, queried);
    }

    // Iterates the EPSS "data" array and populates the scores dictionary.
    // EPSS encodes scores as strings ("0.97558"); entries missing either property
    // or carrying a non-numeric value are skipped silently. The percentile is optional in the
    // same sense: a row without a usable one still yields a score, with a null percentile, rather
    // than being dropped — the probability is the field the existing gate arm depends on.
    private static void ParseEpssDataArray(JsonElement data, Dictionary<string, EpssScore> scores)
    {
        foreach (var entry in data.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            if (!entry.TryGetProperty("cve", out var cve) || cve.ValueKind != JsonValueKind.String)
            {
                continue;
            }
            if (!entry.TryGetProperty("epss", out var epss) || epss.ValueKind != JsonValueKind.String)
            {
                continue;
            }
            if (!double.TryParse(epss.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out double score))
            {
                continue;
            }

            scores[cve.GetString()!] = new EpssScore(score, ParsePercentile(entry));
        }
    }

    // EPSS encodes the percentile as a string, like the probability. Out-of-range values are
    // dropped rather than clamped: a percentile outside 0..1 means the feed changed shape, and
    // recording a guess would put a wrong number behind a gate threshold.
    private static double? ParsePercentile(JsonElement entry) =>
        entry.TryGetProperty("percentile", out var percentile)
        && percentile.ValueKind == JsonValueKind.String
        && double.TryParse(
            percentile.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out double value)
        && value is >= 0.0 and <= 1.0
            ? value
            : null;
}
