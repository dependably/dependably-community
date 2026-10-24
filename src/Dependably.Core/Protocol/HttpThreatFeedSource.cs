using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Dependably.Protocol;

/// <summary>
/// HTTP implementation of <see cref="IThreatFeedSource"/> against the public feeds:
/// the CISA KEV catalog JSON (override via <c>KEV_FEED_URL</c> for mirrors/tests) and the
/// FIRST.org EPSS API (override via <c>EPSS_API_URL</c>) and daily bulk file (override via
/// <c>EPSS_BULK_URL</c>). Uses the named "threatfeed"
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

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default for the EPSS_BULK_URL environment variable / config key; operators override this to point at a mirror.")]
    public const string DefaultEpssBulkUrl = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

    // The bulk file is about 3 MB compressed and 12 MB of CSV today. The caps leave room for the
    // model to grow several times over without letting a hostile endpoint (or a gzip bomb behind
    // an operator-set mirror) drive memory.
    internal const long MaxEpssBulkDecompressedBytes = 128L * 1024 * 1024;

    // The published "-current" name answers with a relative redirect to the dated file. A
    // redirect is followed only within the same host, a bounded number of times, so the
    // no-auto-redirect SSRF posture of the client is kept.
    private const int MaxBulkRedirects = 3;

    private static readonly Regex EpssScoreDateHeader =
        new(@"score_date:(\d{4}-\d{2}-\d{2})", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    private static readonly Regex EpssCveShape =
        new(@"^CVE-\d{4}-\d{4,}$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));

    // FIRST.org documents a 100-parameter ceiling per request; staying at it keeps the daily
    // pass to a handful of calls for a typical instance.
    private const int EpssBatchSize = 100;

    // The KEV catalog is a few megabytes today and grows slowly as CISA adds entries; the EPSS
    // batch responses are smaller still (100 CVEs per call). A malicious or compromised feed
    // endpoint should not be able to force unbounded buffering, so both reads share a generous
    // cap well above any expected catalog size without matching the tighter package-metadata cap.
    internal const long MaxFeedResponseBytes = 64L * 1024 * 1024; // 64 MB

    /// <summary>Config key for the overall time one feed fetch (headers and body) may take, in seconds.</summary>
    public const string FetchTimeoutSecondsKey = "THREAT_FEED_FETCH_TIMEOUT_SECONDS";

    internal static readonly TimeSpan DefaultFetchTimeout = TimeSpan.FromMinutes(5);

    private readonly IHttpClientFactory _httpFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<HttpThreatFeedSource> _logger;
    private readonly TimeProvider _time;

    public HttpThreatFeedSource(
        IHttpClientFactory httpFactory,
        IConfiguration config,
        ILogger<HttpThreatFeedSource> logger,
        TimeProvider time)
    {
        _httpFactory = httpFactory;
        _config = config;
        _logger = logger;
        _time = time;
    }

    // HttpClient.Timeout stops applying once the response headers arrive, so a mirror that sends
    // headers and then trickles the body would hold a read open for as long as the caller's token
    // lives. Each fetch runs under its own overall deadline, measured on the injected clock, that
    // covers the headers and the body together.
    private TimeSpan FetchTimeout =>
        int.TryParse(_config[FetchTimeoutSecondsKey], NumberStyles.None, CultureInfo.InvariantCulture, out int seconds)
        && seconds > 0
            ? TimeSpan.FromSeconds(seconds)
            : DefaultFetchTimeout;

    private async Task<T> WithFetchDeadlineAsync<T>(string url, Func<CancellationToken, Task<T>> fetch, CancellationToken ct)
    {
        using var deadline = new CancellationTokenSource(FetchTimeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, deadline.Token);
        try
        {
            return await fetch(linked.Token);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            // Reported as a failed fetch, not a cancellation: the caller's token did not fire, so a
            // caller that treats cancellation as shutdown must not read this as one.
            throw new TimeoutException($"Threat feed fetch from {url} exceeded {FetchTimeout.TotalSeconds:0} seconds.");
        }
    }

    public async Task<IReadOnlyDictionary<string, KevEntry>> GetKevCatalogAsync(CancellationToken ct = default)
    {
        string url = _config["KEV_FEED_URL"] ?? DefaultKevFeedUrl;
        var http = _httpFactory.CreateClient("threatfeed");

        byte[] body = await WithFetchDeadlineAsync(url, async token =>
        {
            // ResponseHeadersRead is load-bearing: the default (ResponseContentRead) would have
            // HttpClient buffer the whole body before the cap check below ever runs, defeating it.
            using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
            response.EnsureSuccessStatusCode();
            return await UpstreamClient.ReadBodyCappedAsync(response, MaxFeedResponseBytes, url, token);
        }, ct);
        using var doc = JsonDocument.Parse(body);

        var entries = new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase);
        int skipped = 0;
        int ransomware = 0;
        if (doc.RootElement.TryGetProperty("vulnerabilities", out var vulns)
            && vulns.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in vulns.EnumerateArray())
            {
                if (!TryReadKevEntry(entry, out string? cveId, out var parsed))
                {
                    skipped++;
                    continue;
                }

                entries[cveId] = parsed;
                if (parsed.KnownRansomwareCampaignUse == true)
                {
                    ransomware++;
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
    // One catalogue entry: an object carrying a non-blank string cveID. Anything else is a
    // malformed record the caller counts as skipped rather than failing the whole feed on.
    private static bool TryReadKevEntry(
        JsonElement entry,
        [NotNullWhen(true)] out string? cveId,
        [NotNullWhen(true)] out KevEntry? parsed)
    {
        cveId = null;
        parsed = null;

        if (entry.ValueKind != JsonValueKind.Object
            || !entry.TryGetProperty("cveID", out var cve)
            || cve.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(cve.GetString()))
        {
            return false;
        }

        cveId = cve.GetString()!.Trim();
        parsed = new KevEntry(
            ParseRansomwareUse(entry),
            ReadDate(entry, "dateAdded"),
            ReadDate(entry, "dueDate"),
            ReadString(entry, "requiredAction"),
            ReadCwes(entry),
            ReadString(entry, "notes"));
        return true;
    }

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
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null is a distinct documented state here: it means CISA published no cwes "
                        + "property at all, which callers must tell apart from a present-but-empty "
                        + "array meaning CISA recorded zero classifications.")]
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
                byte[] body = await WithFetchDeadlineAsync(url, async token =>
                {
                    // ResponseHeadersRead is load-bearing here too: see GetKevCatalogAsync.
                    using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
                    response.EnsureSuccessStatusCode();
                    return await UpstreamClient.ReadBodyCappedAsync(response, MaxFeedResponseBytes, url, token);
                }, ct);
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

    public async Task<EpssBulkFile> GetEpssBulkAsync(CancellationToken ct = default)
    {
        string url = _config["EPSS_BULK_URL"] ?? DefaultEpssBulkUrl;
        var http = _httpFactory.CreateClient("threatfeed");

        byte[] body = await WithFetchDeadlineAsync(url, token => FetchEpssBulkBodyAsync(http, url, token), ct);
        var file = ParseEpssBulk(body, out int skipped);
        if (skipped > 0)
        {
            _logger.LogWarning("EPSS bulk file contained {Skipped} unusable rows; skipped.", skipped);
        }

        _logger.LogInformation(
            "EPSS bulk file loaded: {Count} CVE scores, score date {ScoreDate}.",
            file.Scores.Count, file.ScoreDate ?? "unstated");
        return file;
    }

    private static async Task<byte[]> FetchEpssBulkBodyAsync(
        HttpClient http, string url, CancellationToken ct)
    {
        var current = new Uri(url, UriKind.Absolute);
        for (int hop = 0; ; hop++)
        {
            using var response = await http.GetAsync(current, HttpCompletionOption.ResponseHeadersRead, ct);
            if (IsRedirect(response.StatusCode) && response.Headers.Location is { } location)
            {
                var next = location.IsAbsoluteUri ? location : new Uri(current, location);
                if (hop >= MaxBulkRedirects
                    || !string.Equals(next.Host, current.Host, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(next.Scheme, current.Scheme, StringComparison.OrdinalIgnoreCase))
                {
                    throw new HttpRequestException(
                        $"EPSS bulk file redirected to {next.GetLeftPart(UriPartial.Path)}, which is not followed.");
                }

                current = next;
                continue;
            }

            response.EnsureSuccessStatusCode();
            return await UpstreamClient.ReadBodyCappedAsync(response, MaxFeedResponseBytes, current.ToString(), ct);
        }
    }

    private static bool IsRedirect(System.Net.HttpStatusCode status) => status is
        System.Net.HttpStatusCode.MovedPermanently or System.Net.HttpStatusCode.Found
        or System.Net.HttpStatusCode.SeeOther or System.Net.HttpStatusCode.TemporaryRedirect
        or System.Net.HttpStatusCode.PermanentRedirect;

    /// <summary>
    /// Parses FIRST.org's gzipped CSV: an optional <c>#model_version:…,score_date:…</c> comment
    /// line, the <c>cve,epss,percentile</c> header, then one row per CVE. A file whose first
    /// non-comment line is not that header is a different format, and throws rather than being
    /// read by position. A row with an unusable CVE id or a value outside 0..1 is skipped and
    /// counted; it never fails the file.
    /// </summary>
    internal static EpssBulkFile ParseEpssBulk(byte[] gzipped, out int skipped)
    {
        skipped = 0;
        using var compressed = new MemoryStream(gzipped, writable: false);
        using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
        using var bounded = new CappedReadStream(gzip, MaxEpssBulkDecompressedBytes);
        using var reader = new StreamReader(bounded, Encoding.UTF8);

        var scores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        string? scoreDate = null;
        bool sawHeader = false;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] == '#')
            {
                scoreDate ??= EpssScoreDateHeader.Match(line) is { Success: true } m ? m.Groups[1].Value : null;
                continue;
            }

            if (!sawHeader)
            {
                RequireEpssHeader(line);
                sawHeader = true;
                continue;
            }

            if (TryParseEpssRow(line, out string? cve, out var score))
            {
                scores[cve] = score;
            }
            else
            {
                skipped++;
            }
        }

        return sawHeader
            ? new EpssBulkFile(scores, scoreDate)
            : throw new InvalidDataException("EPSS bulk file has no cve,epss,percentile header.");
    }

    private static void RequireEpssHeader(string line)
    {
        if (!IsEpssHeader(line))
        {
            throw new InvalidDataException("EPSS bulk file does not start with the cve,epss,percentile header.");
        }
    }

    private static bool IsEpssHeader(string line)
    {
        string[] columns = line.Split(',');
        return columns.Length >= 3
            && columns[0].Trim().Equals("cve", StringComparison.OrdinalIgnoreCase)
            && columns[1].Trim().Equals("epss", StringComparison.OrdinalIgnoreCase)
            && columns[2].Trim().Equals("percentile", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseEpssRow(
        string line, [NotNullWhen(true)] out string? cve, [NotNullWhen(true)] out EpssScore? score)
    {
        cve = null;
        score = null;
        string[] fields = line.Split(',');
        if (fields.Length < 3)
        {
            return false;
        }

        string id = fields[0].Trim();
        if (!EpssCveShape.IsMatch(id)
            || !double.TryParse(fields[1], NumberStyles.Float, CultureInfo.InvariantCulture, out double probability)
            || probability is < 0.0 or > 1.0
            || double.IsNaN(probability))
        {
            return false;
        }

        // The percentile is optional in the same sense as on the API path: an unusable one keeps
        // the score and drops the rank.
        double? percentile = double.TryParse(fields[2], NumberStyles.Float, CultureInfo.InvariantCulture, out double p)
            && p is >= 0.0 and <= 1.0
            ? p
            : null;
        cve = id.ToUpperInvariant();
        score = new EpssScore(probability, percentile);
        return true;
    }

    // Fails the read once more than the cap has come out of the decompressor, so a small gzip body
    // cannot inflate without bound.
    private sealed class CappedReadStream(Stream inner, long maxBytes) : Stream
    {
        private long _read;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = inner.Read(buffer, offset, count);
            _read += n;
            return _read > maxBytes
                ? throw new InvalidDataException("EPSS bulk file decompresses past the size limit.")
                : n;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
