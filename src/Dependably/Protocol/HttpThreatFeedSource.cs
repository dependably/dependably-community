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

    public async Task<IReadOnlySet<string>> GetKevCveIdsAsync(CancellationToken ct = default)
    {
        string url = _config["KEV_FEED_URL"] ?? DefaultKevFeedUrl;
        var http = _httpFactory.CreateClient("threatfeed");

        // ResponseHeadersRead is load-bearing: the default (ResponseContentRead) would have
        // HttpClient buffer the whole body before the cap check below ever runs, defeating it.
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        byte[] body = await UpstreamClient.ReadBodyCappedAsync(response, MaxFeedResponseBytes, url, ct);
        using var doc = JsonDocument.Parse(body);

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int skipped = 0;
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
                    ids.Add(cve.GetString()!.Trim());
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

        _logger.LogInformation("KEV feed loaded: {Count} CVE ids.", ids.Count);
        return ids;
    }

    public async Task<EpssQueryResult> GetEpssScoresAsync(
        IReadOnlyCollection<string> cveIds, CancellationToken ct = default)
    {
        string baseUrl = _config["EPSS_API_URL"] ?? DefaultEpssApiUrl;
        var http = _httpFactory.CreateClient("threatfeed");

        var scores = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
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
    // or carrying a non-numeric value are skipped silently.
    private static void ParseEpssDataArray(JsonElement data, Dictionary<string, double> scores)
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
            scores[cve.GetString()!] = score;
        }
    }
}
