using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Protocol;

/// <summary>
/// Client for the OSV.dev vulnerability database API.
/// Supports single-PURL queries and batch queries (up to 1000 PURLs per request).
/// Implements exponential backoff on 429 responses.
/// </summary>
public sealed class OsvClient : IOsvSource
{
    // /querybatch returns only {id, modified} per vuln. After parsing the batch response,
    // we hydrate full advisory data via GET /vulns/{id}. Cap the per-call hydration count
    // so a single large tenant can't fan us out into thousands of GETs against OSV.
    private const int MaxHydrationsPerBatch = 500;
    private const int HydrationConcurrency = 8;

    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<OsvClient> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public OsvClient(IHttpClientFactory httpFactory, ILogger<OsvClient> logger)
    {
        _httpFactory = httpFactory;
        _logger = logger;
    }

    /// <summary>Query OSV for advisories affecting a single PURL. Always hydrated.</summary>
    public async Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
    {
        var body = JsonSerializer.Serialize(new { package = new { purl } }, JsonOpts);
        using var response = await PostWithRetryAsync("query", body, ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("OSV query returned {Status} for {Purl}", response.StatusCode, purl);
            return [];
        }

        var json = await response.Content.ReadAsStringAsync(ct);
        var result = JsonSerializer.Deserialize<OsvQueryResponse>(json, JsonOpts);
        return result?.Vulns?.Select(v => ParseAdvisory(v, isHydrated: true)).ToList() ?? [];
    }

    /// <summary>
    /// Batch-query OSV for up to 1000 PURLs. Returns a list of advisory lists,
    /// one per input PURL, in the same order as <paramref name="purls"/>.
    ///
    /// /querybatch returns only {id, modified} per vuln, so we follow up with
    /// GET /vulns/{id} to hydrate full advisory data. Hydration is deduped across
    /// the entire batch, capped at <see cref="MaxHydrationsPerBatch"/>, and bounded
    /// by <see cref="HydrationConcurrency"/>. IDs that fail hydration fall back to
    /// the stripped record (IsHydrated=false), which the scan service skips.
    /// </summary>
    public async Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default)
    {
        var queries = purls.Select(p => new { package = new { purl = p } }).ToList();
        var body = JsonSerializer.Serialize(new { queries }, JsonOpts);
        using var response = await PostWithRetryAsync("querybatch", body, ct);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("OSV querybatch returned {Status}", response.StatusCode);
            return purls.Select(_ => new List<OsvAdvisory>()).ToList();
        }

        var json = await response.Content.ReadAsStringAsync(ct);
        var batchResult = JsonSerializer.Deserialize<OsvBatchResponse>(json, JsonOpts);
        var perPurlRaw = batchResult?.Results?
            .Select(r => r.Vulns?.ToList() ?? new List<OsvVulnRaw>())
            .ToList()
            ?? purls.Select(_ => new List<OsvVulnRaw>()).ToList();

        // Dedup IDs across the entire batch — the same advisory often shows up under many PURLs.
        var uniqueIds = perPurlRaw
            .SelectMany(list => list)
            .Select(v => v.Id)
            .Where(id => !string.IsNullOrEmpty(id))
            .Select(id => id!)
            .Distinct()
            .ToList();

        // Cap per-call hydration; overflow IDs fall back to non-hydrated records.
        var idsToHydrate = uniqueIds;
        if (uniqueIds.Count > MaxHydrationsPerBatch)
        {
            _logger.LogWarning(
                "OSV hydration capped at {Cap} of {Total} unique advisory IDs in this batch",
                MaxHydrationsPerBatch, uniqueIds.Count);
            idsToHydrate = uniqueIds.Take(MaxHydrationsPerBatch).ToList();
        }

        // Successful hydrations are stored here; failures are not, which gives us an
        // implicit per-call negative cache (TryGetValue below falls back to stripped).
        // Combined with Distinct() above, a failing ID is never retried within this batch.
        var hydrated = new ConcurrentDictionary<string, OsvAdvisory>();
        using var sem = new SemaphoreSlim(HydrationConcurrency);

        await Task.WhenAll(idsToHydrate.Select(async id =>
        {
            await sem.WaitAsync(ct);
            try
            {
                var advisory = await FetchAdvisoryAsync(id, ct);
                if (advisory is not null) hydrated[id] = advisory;
            }
            finally { sem.Release(); }
        }));

        // Build per-PURL advisory lists. Use hydrated where available; fall back to
        // stripped (IsHydrated=false) so the scan service can skip non-hydrated records.
        return perPurlRaw.Select(list => list
            .Select(raw => hydrated.TryGetValue(raw.Id ?? "", out var h)
                ? h
                : ParseAdvisory(raw, isHydrated: false))
            .ToList()).ToList();
    }

    /// <summary>Fetch a single advisory's full details via GET /vulns/{id}. Returns null on any failure.</summary>
    private async Task<OsvAdvisory?> FetchAdvisoryAsync(string id, CancellationToken ct)
    {
        try
        {
            using var response = await GetWithRetryAsync($"vulns/{Uri.EscapeDataString(id)}", ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("OSV vulns/{Id} returned {Status}", id, response.StatusCode);
                return null;
            }
            var json = await response.Content.ReadAsStringAsync(ct);
            var raw = JsonSerializer.Deserialize<OsvVulnRaw>(json, JsonOpts);
            return raw is null ? null : ParseAdvisory(raw, isHydrated: true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "OSV vulns/{Id} fetch failed", id);
            return null;
        }
    }

    private Task<HttpResponseMessage> PostWithRetryAsync(string path, string body, CancellationToken ct)
        => SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        }, ct);

    private Task<HttpResponseMessage> GetWithRetryAsync(string path, CancellationToken ct)
        => SendWithRetryAsync(() => new HttpRequestMessage(HttpMethod.Get, path), ct);

    private async Task<HttpResponseMessage> SendWithRetryAsync(Func<HttpRequestMessage> requestFactory, CancellationToken ct)
    {
        // Create the client once — BaseAddress is configured at registration in Program.cs.
        var http = _httpFactory.CreateClient("osv");
        int delay = 1000;

        for (int attempt = 0; attempt < 3; attempt++)
        {
            // HttpRequestMessage is not reusable; build a fresh one each attempt.
            var response = await http.SendAsync(requestFactory(), ct);

            if (response.StatusCode != HttpStatusCode.TooManyRequests)
                return response;

            // Read Retry-After before disposing the response.
            var retryAfterHeader = response.Headers.TryGetValues("Retry-After", out var vals)
                ? vals.FirstOrDefault() : null;
            response.Dispose();

            if (retryAfterHeader is not null && int.TryParse(retryAfterHeader, out var retrySeconds))
                delay = retrySeconds * 1000;

            _logger.LogWarning("OSV rate-limited; retrying in {Delay}ms (attempt {Attempt}/3)", delay, attempt + 1);
            try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { break; }
            delay = Math.Min(delay * 2, 4000);
        }

        // Return a synthetic 429 after exhausting retries.
        return new HttpResponseMessage(HttpStatusCode.TooManyRequests);
    }

    private static OsvAdvisory ParseAdvisory(OsvVulnRaw raw, bool isHydrated)
    {
        // Build per-package affected lists, preserving the package identity from each entry.
        var affectedPackages = raw.Affected?
            .Where(a => a.Package is not null)
            .Select(a => new OsvAffectedPackage(
                Purl: a.Package!.Purl,
                Ecosystem: a.Package.Ecosystem,
                Name: a.Package.Name,
                Versions: a.Versions?.Distinct().ToArray() ?? []))
            .ToArray() ?? [];

        // Extract CVSS score and severity text from the severity array
        string? severity = null;
        double? cvssScore = null;
        var cvssEntry = raw.Severity?.FirstOrDefault(s =>
            s.Type?.StartsWith("CVSS", StringComparison.OrdinalIgnoreCase) == true);
        if (cvssEntry?.Score is not null)
            cvssScore = OsvScoring.ParseCvssBaseScore(cvssEntry.Score, out severity);

        // Fall back to database_specific.severity for severity text
        if (severity is null && raw.DatabaseSpecific?.TryGetValue("severity", out var dbSev) == true)
            severity = dbSev?.ToString();

        return new OsvAdvisory(
            Id: raw.Id ?? "",
            Aliases: raw.Aliases?.ToArray() ?? [],
            Summary: raw.Summary,
            Severity: OsvScoring.NormalizeSeverity(severity),
            CvssScore: cvssScore,
            AffectedPackages: affectedPackages,
            Published: raw.Published,
            Modified: raw.Modified,
            IsHydrated: isHydrated);
    }

    // CVSS scoring + severity normalisation moved to OsvScoring (shared with LocalOsvSource).

    // ── Raw OSV JSON shapes ───────────────────────────────────────────────────

    private sealed record OsvQueryResponse(List<OsvVulnRaw>? Vulns);

    private sealed record OsvBatchResponse(List<OsvQueryResponse>? Results);

    private sealed record OsvVulnRaw(
        string? Id,
        List<string>? Aliases,
        string? Summary,
        List<OsvSeverityRaw>? Severity,
        List<OsvAffectedRaw>? Affected,
        string? Published,
        string? Modified,
        [property: JsonPropertyName("database_specific")] Dictionary<string, object?>? DatabaseSpecific);

    private sealed record OsvSeverityRaw(string? Type, string? Score);

    private sealed record OsvAffectedRaw(OsvPackageRaw? Package, List<string>? Versions);

    private sealed record OsvPackageRaw(string? Ecosystem, string? Name, string? Purl);
}

/// <summary>
/// A parsed OSV advisory returned by <see cref="OsvClient"/>.
/// <see cref="IsHydrated"/> is true only when the record came from the per-id endpoints
/// (/query or /vulns/{id}); /querybatch returns id+modified only and yields IsHydrated=false.
/// Callers must filter on IsHydrated before persisting — see VulnerabilityScanService.
/// </summary>
public sealed record OsvAdvisory(
    string Id,
    string[] Aliases,
    string? Summary,
    string? Severity,
    double? CvssScore,
    OsvAffectedPackage[] AffectedPackages,
    string? Published,
    string? Modified,
    bool IsHydrated);

/// <summary>
/// One entry from an OSV advisory's <c>affected[]</c> array — a specific package
/// (identified by PURL, ecosystem, and name) together with the versions affected.
/// </summary>
public sealed record OsvAffectedPackage(
    string? Purl,
    string? Ecosystem,
    string? Name,
    string[] Versions);
