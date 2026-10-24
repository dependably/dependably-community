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

    // Purls per batch call re-queried through /query because hydration left them incomplete.
    private const int MaxFullQueryFallbacksPerBatch = 100;

    // Retry parameters for OSV rate-limit responses (429 Too Many Requests).
    private const int OsvRetryMaxAttempts = 3;
    private const int OsvRetryInitialDelayMs = 1000;
    private const int OsvRetryMaxDelayMs = 4000;
    private const int OsvRetryBackoffMultiplier = 2;

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
    public async Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default) =>
        (await TryQueryAsync(purl, ct)).Advisories;

    /// <summary>
    /// Same query as <see cref="QueryAsync"/>, but reports whether OSV was actually reached
    /// (<see cref="OsvQueryResult.Reached"/> false on a network failure, 5xx, any other
    /// non-2xx status, or a page chain that cannot be completed — a failed later page, or more
    /// than <see cref="MaxQueryPages"/> pages; these are the failure modes <see cref="QueryAsync"/>
    /// swallows into an empty list). A 2xx response with zero vulns is a genuine reached-and-clean
    /// answer.
    /// </summary>
    public async Task<OsvQueryResult> TryQueryAsync(string purl, CancellationToken ct = default)
    {
        var advisories = new List<OsvAdvisory>();
        string? pageToken = null;
        for (int page = 0; page < MaxQueryPages; page++)
        {
            HttpResponseMessage response;
            try
            {
                response = await PostWithRetryAsync(
                    "query", body: JsonSerializer.Serialize(new { package = new { purl }, page_token = pageToken }, JsonOpts), ct);
            }
            catch (Exception ex) when (IsTransportFailure(ex, ct))
            {
                _logger.LogWarning(ex, "OSV query fetch failed: {ExceptionType} for {Purl}", ex.GetType().Name, purl);
                return new OsvQueryResult([], Reached: false);
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("OSV query returned {Status} for {Purl}", response.StatusCode, purl);
                    return new OsvQueryResult([], Reached: false);
                }

                string json = await response.Content.ReadAsStringAsync(ct);
                advisories.AddRange(ParseHydratedVulns(json));
                pageToken = ReadNextPageToken(json);
            }

            if (string.IsNullOrEmpty(pageToken))
            {
                return new OsvQueryResult(advisories, Reached: true);
            }
        }

        // An unfinished chain is a truncated answer: serving it would let an advisory on a later
        // page read as a clean version.
        _logger.LogWarning("OSV query for {Purl} exceeded {Pages} pages", purl, MaxQueryPages);
        return new OsvQueryResult([], Reached: false);
    }

    // A purl with more matches than one response holds is paged; a chain longer than this is
    // reported unreached rather than served truncated.
    private const int MaxQueryPages = 50;

    // A feed with more matches than one response holds (a kernel) is paged; a result that would
    // need more pages than this is reported unreached rather than served truncated.
    private const int MaxDistroQueryPages = 50;

    /// <summary>
    /// Release-scoped query: OSV matches the version against the feed's ranges server-side with
    /// the distro's own version ordering, so no comparison happens here, and the response is
    /// followed through <c>next_page_token</c> so a large feed is not silently truncated.
    ///
    /// OSV rejects an unknown base ecosystem but answers an unknown RELEASE of a known family with
    /// an empty 200, which cannot be told from a feed with no matches. A release outside
    /// <see cref="DistroScopes.IsKnownRelease"/> is therefore reported uncovered without a query.
    /// </summary>
    public async Task<OsvScopedQueryResult> TryQueryDistroPackageAsync(
        DistroScope scope, string name, string version, CancellationToken ct = default)
    {
        if (!DistroScopes.IsKnownRelease(scope))
        {
            return new OsvScopedQueryResult([], Reached: true, Covered: false);
        }

        var advisories = new List<OsvAdvisory>();
        string? pageToken = null;
        for (int page = 0; page < MaxDistroQueryPages; page++)
        {
            string body = JsonSerializer.Serialize(
                new { version, package = new { name, ecosystem = scope.OsvEcosystem }, page_token = pageToken }, JsonOpts);
            HttpResponseMessage response;
            try
            {
                response = await PostWithRetryAsync("query", body, ct);
            }
            catch (Exception ex) when (IsTransportFailure(ex, ct))
            {
                _logger.LogWarning(ex, "OSV scoped query fetch failed: {ExceptionType} for {Ecosystem}", ex.GetType().Name, scope.OsvEcosystem);
                return new OsvScopedQueryResult([], Reached: false, Covered: false);
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("OSV scoped query returned {Status} for {Ecosystem}", response.StatusCode, scope.OsvEcosystem);
                    return new OsvScopedQueryResult([], Reached: false, Covered: false);
                }

                string json = await response.Content.ReadAsStringAsync(ct);
                advisories.AddRange(ParseHydratedVulns(json));
                pageToken = ReadNextPageToken(json);
            }

            if (string.IsNullOrEmpty(pageToken))
            {
                return new OsvScopedQueryResult(advisories, Reached: true);
            }
        }

        _logger.LogWarning("OSV scoped query for {Ecosystem} exceeded {Pages} pages", scope.OsvEcosystem, MaxDistroQueryPages);
        return new OsvScopedQueryResult([], Reached: false, Covered: false);
    }

    private static string? ReadNextPageToken(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("next_page_token", out var token) && token.ValueKind == JsonValueKind.String
            ? token.GetString()
            : null;
    }

    /// <summary>
    /// Parses a <c>{"vulns":[…]}</c> body into hydrated advisories, capturing each element's
    /// raw JSON text on the advisory so the full schema can be persisted. The per-element
    /// text — not the whole envelope — is what lands in <c>vulnerabilities.osv_json</c>.
    /// </summary>
    private static List<OsvAdvisory> ParseHydratedVulns(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("vulns", out var vulns)
            || vulns.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var list = new List<OsvAdvisory>(vulns.GetArrayLength());
        foreach (var el in vulns.EnumerateArray())
        {
            var raw = el.Deserialize<OsvVulnRaw>(JsonOpts);
            if (raw is null)
            {
                continue;
            }

            list.Add(ParseAdvisory(raw, isHydrated: true, rawJson: el.GetRawText()));
        }
        return list;
    }

    /// <summary>
    /// Batch-query OSV for up to 1000 PURLs. Returns a list of advisory lists,
    /// one per input PURL, in the same order as <paramref name="purls"/>.
    ///
    /// /querybatch returns only {id, modified} per vuln, so we follow up with
    /// GET /vulns/{id} to hydrate full advisory data. Hydration is deduped across
    /// the entire batch, capped at <see cref="MaxHydrationsPerBatch"/>, and bounded
    /// by <see cref="HydrationConcurrency"/>. An id OSV answers 404/400 for is dropped (OSV holds
    /// no such record). A purl left with an unhydrated id (past the cap, or a hydration that did
    /// not reach OSV, including a timeout) is re-queried in full through the paged single query;
    /// if that is not reached either, the id stays as the stripped record (IsHydrated=false). The
    /// batch stays reached; a caller must not record a purl carrying a stripped record as screened
    /// unless it already holds that advisory.
    /// </summary>
    public async Task<List<List<OsvAdvisory>>> QueryBatchAsync(
        IReadOnlyList<string> purls, CancellationToken ct = default) =>
        (await TryQueryBatchAsync(purls, ct)).Results;

    /// <summary>
    /// Same batch query as <see cref="QueryBatchAsync"/>, but reports whether OSV was actually
    /// reached (<see cref="OsvBatchQueryResult.Reached"/> false on a network failure, or any
    /// non-2xx — including the synthetic 429 returned after retry exhaustion — or a 2xx body with no
    /// <c>results</c> array). Those are exactly
    /// the failure modes <see cref="QueryBatchAsync"/> swallows into a full-length list of empty
    /// results, which is otherwise indistinguishable from a genuinely clean batch.
    /// </summary>
    public async Task<OsvBatchQueryResult> TryQueryBatchAsync(
        IReadOnlyList<string> purls, CancellationToken ct = default)
    {
        var queries = purls.Select(p => new { package = new { purl = p } }).ToList();
        string requestBody = JsonSerializer.Serialize(new { queries }, JsonOpts);

        HttpResponseMessage response;
        try
        {
            response = await PostWithRetryAsync("querybatch", requestBody, ct);
        }
        catch (Exception ex) when (IsTransportFailure(ex, ct))
        {
            _logger.LogWarning(ex, "OSV querybatch fetch failed: {ExceptionType}", ex.GetType().Name);
            return Unreached(purls);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("OSV querybatch returned {Status}", response.StatusCode);
                return Unreached(purls);
            }

            string json = await response.Content.ReadAsStringAsync(ct);
            var batchResult = JsonSerializer.Deserialize<OsvBatchResponse>(json, JsonOpts);

            // A body with no results array answers no purl at all; read as reached, every purl
            // in the batch would be recorded screened and clean.
            if (batchResult?.Results is null)
            {
                _logger.LogWarning("OSV querybatch returned a body with no results for {Count} purl(s)", purls.Count);
                return Unreached(purls);
            }

            var perPurlRaw = batchResult.Results
                .Select(r => r.Vulns?.ToList() ?? new List<OsvVulnRaw>())
                .ToList();

            // A result carrying next_page_token holds only its first page. Each such purl is
            // re-queried through the paged single query, which returns the complete hydrated
            // list; the batch has one Reached flag, so a chain that cannot be completed makes
            // the whole batch unreached rather than serving that purl truncated.
            var (pagedReached, pagedResults) = await QueryPagedResultsAsync(
                batchResult.Results, purls, perPurlRaw, ct);
            if (!pagedReached)
            {
                return Unreached(purls);
            }

            var idsToHydrate = IdsToHydrate(perPurlRaw);

            // Each id gets one GET /vulns/{id} per batch (Distinct() above). A record is kept; an id
            // OSV answers 404/400 for is reached-unknown (a withdrawn or rejected record) and is
            // dropped, as TryGetAdvisoryAsync defines it; anything unreached stays stripped.
            var hydrated = new ConcurrentDictionary<string, OsvAdvisory>();
            var unknown = new ConcurrentDictionary<string, bool>();
            using var sem = new SemaphoreSlim(HydrationConcurrency);

            await Task.WhenAll(idsToHydrate.Select(async id =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    var lookup = await TryGetAdvisoryAsync(id, ct);
                    if (lookup.Advisory is not null)
                    {
                        hydrated[id] = lookup.Advisory;
                    }
                    else if (lookup.Reached)
                    {
                        unknown[id] = true;
                    }
                }
                finally { sem.Release(); }
            }));

            // Build per-PURL advisory lists. Use hydrated where available; fall back to
            // stripped (IsHydrated=false), which tells a caller that purl's answer is incomplete.
            var results = perPurlRaw.Select((list, i) => pagedResults.TryGetValue(i, out var full)
                ? full
                : list
                    .Where(raw => !unknown.ContainsKey(raw.Id ?? ""))
                    .Select(raw => hydrated.TryGetValue(raw.Id ?? "", out var h)
                        ? h
                        : ParseAdvisory(raw, isHydrated: false))
                    .ToList()).ToList();

            await ResolveStrippedThroughFullQueryAsync(purls, results, ct);

            return new OsvBatchQueryResult(results, Reached: true);
        } // using (response)
    }

    private List<string> IdsToHydrate(List<List<OsvVulnRaw>> perPurlRaw)
    {
        // Dedup IDs across the entire batch — the same advisory often shows up under many PURLs.
        var uniqueIds = perPurlRaw
            .SelectMany(list => list)
            .Select(v => v.Id)
            .Where(id => !string.IsNullOrEmpty(id))
            .Select(id => id!)
            .Distinct()
            .ToList();

        // Cap per-call hydration; overflow IDs fall back to non-hydrated records.
        if (uniqueIds.Count <= MaxHydrationsPerBatch)
        {
            return uniqueIds;
        }

        _logger.LogWarning(
            "OSV hydration capped at {Cap} of {Total} unique advisory IDs in this batch",
            MaxHydrationsPerBatch, uniqueIds.Count);
        return uniqueIds.Take(MaxHydrationsPerBatch).ToList();
    }

    // A purl still holding a stripped record (an id past MaxHydrationsPerBatch, or a hydration that
    // did not reach OSV) is re-queried through the paged, hydrated single query, which answers it in
    // full. The cap takes the same ids in the same order on every pass, so without this an
    // overflowing purl would never resolve. Bounded per batch, and stopped at the first unreached
    // re-query: the source is then failing, and the remaining purls keep their stripped records,
    // which callers treat as an incomplete answer.
    private async Task ResolveStrippedThroughFullQueryAsync(
        IReadOnlyList<string> purls, List<List<OsvAdvisory>> results, CancellationToken ct)
    {
        int requeried = 0;
        int answered = Math.Min(results.Count, purls.Count);
        for (int i = 0; i < answered && requeried < MaxFullQueryFallbacksPerBatch; i++)
        {
            if (results[i].TrueForAll(a => a.IsHydrated))
            {
                continue;
            }

            requeried++;
            OsvQueryResult full;
            try
            {
                full = await TryQueryAsync(purls[i], ct);
            }
            catch (Exception ex) when (IsTransportFailure(ex, ct) || ex is not OperationCanceledException)
            {
                // A body that does not parse, or any other failure, is no answer: the batch keeps
                // what it has and the purl stays incomplete.
                _logger.LogWarning(ex, "OSV re-query for {Purl} failed: {ExceptionType}", purls[i], ex.GetType().Name);
                return;
            }

            if (!full.Reached)
            {
                _logger.LogWarning(
                    "OSV re-query for {Purl} was not reached; purls with unhydrated advisories are left incomplete",
                    purls[i]);
                return;
            }

            results[i] = full.Advisories;
        }
    }

    // Queries each purl whose batch result carries next_page_token again, through the paged single
    // query, and clears that purl's first page from perPurlRaw. Reached is false when a chain cannot
    // be completed. A mis-sized answer is tolerated here as the callers tolerate it: a surplus slot
    // has no purl to query.
    private async Task<(bool Reached, Dictionary<int, List<OsvAdvisory>> Paged)> QueryPagedResultsAsync(
        List<OsvQueryResponse> answeredResults, IReadOnlyList<string> purls, List<List<OsvVulnRaw>> perPurlRaw,
        CancellationToken ct)
    {
        var pagedResults = new Dictionary<int, List<OsvAdvisory>>();
        int answered = Math.Min(answeredResults.Count, purls.Count);
        for (int i = 0; i < answered; i++)
        {
            if (string.IsNullOrEmpty(answeredResults[i].NextPageToken))
            {
                continue;
            }

            var full = await TryQueryAsync(purls[i], ct);
            if (!full.Reached)
            {
                return (false, pagedResults);
            }
            pagedResults[i] = full.Advisories;
            perPurlRaw[i] = [];
        }

        return (true, pagedResults);
    }

    // The full-length all-empty result every swallowed failure mode produces, tagged unreached so
    // callers can tell it apart from a genuinely clean batch.
    private static OsvBatchQueryResult Unreached(IReadOnlyList<string> purls) =>
        new(purls.Select(_ => new List<OsvAdvisory>()).ToList(), Reached: false);

    /// <summary>
    /// No-behavior-change override: the live osv.dev API resolves a <c>pkg:rpm/...</c> purl
    /// against its distro feeds server-side (Rocky Linux, AlmaLinux, Red Hat, …) with no
    /// RPM-specific logic needed on this end, so remote coverage is exactly the static
    /// <see cref="OsvFeedCoverage.HasAdvisoryFeed"/> gate for every ecosystem, RPM included —
    /// unlike <c>LocalOsvSource</c>, there is no dump to have loaded with or without distro
    /// feeds. Explicit here (rather than relying on <see cref="IOsvSource"/>'s identical default)
    /// so the "remote is unaffected by this fix" decision is documented at the implementation
    /// that actually makes it true, not left implicit.
    /// </summary>
    public Task<bool> HasCoverageFor(string? ecosystem) =>
        Task.FromResult(OsvFeedCoverage.HasAdvisoryFeed(ecosystem));

    /// <summary>
    /// GET /vulns/{id}. A 404 or 400 (an id OSV does not hold, or one it rejects as malformed) is
    /// reached with no advisory. Everything else that is not a usable record is unreached: a 429
    /// that outlasts the retries, any other non-success status, a transport failure, and a 200
    /// whose body is empty or does not parse. "Unknown" is reserved for OSV saying so, because a
    /// caller may drop an unknown id, while an unreached one is retried.
    /// </summary>
    public async Task<OsvIdLookupResult> TryGetAdvisoryAsync(string id, CancellationToken ct = default)
    {
        try
        {
            using var response = await GetWithRetryAsync($"vulns/{Uri.EscapeDataString(id)}", ct);
            if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest)
            {
                return new OsvIdLookupResult(null, Reached: true);
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("OSV vulns/{Id} returned {Status}", id, response.StatusCode);
                return new OsvIdLookupResult(null, Reached: false);
            }

            string json = await response.Content.ReadAsStringAsync(ct);
            try
            {
                var raw = JsonSerializer.Deserialize<OsvVulnRaw>(json, JsonOpts);
                if (raw is null || string.IsNullOrEmpty(raw.Id))
                {
                    _logger.LogWarning("OSV vulns/{Id} returned a body with no OSV record", id);
                    return new OsvIdLookupResult(null, Reached: false);
                }

                return new OsvIdLookupResult(ParseAdvisory(raw, isHydrated: true, rawJson: json), Reached: true);
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "OSV vulns/{Id} returned a body that is not an OSV record", id);
                return new OsvIdLookupResult(null, Reached: false);
            }
        }
        catch (Exception ex) when (IsTransportFailure(ex, ct) || ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "OSV vulns/{Id} fetch failed", id);
            return new OsvIdLookupResult(null, Reached: false);
        }
    }

    // A transport failure, including the HttpClient timeout, which surfaces as a
    // TaskCanceledException while the caller's token is still live. A caller-initiated
    // cancellation is not one: it propagates.
    private static bool IsTransportFailure(Exception ex, CancellationToken ct) =>
        ex is HttpRequestException
        || (ex is OperationCanceledException && !ct.IsCancellationRequested);

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
        int delay = OsvRetryInitialDelayMs;

        for (int attempt = 0; attempt < OsvRetryMaxAttempts; attempt++)
        {
            // HttpRequestMessage is not reusable; build a fresh one each attempt.
            var response = await http.SendAsync(requestFactory(), ct);

            if (response.StatusCode != HttpStatusCode.TooManyRequests)
            {
                return response;
            }

            // Read Retry-After before disposing the response.
            string? retryAfterHeader = response.Headers.TryGetValues("Retry-After", out var vals)
                ? vals.FirstOrDefault() : null;
            response.Dispose();

            if (retryAfterHeader is not null && int.TryParse(retryAfterHeader, out int retrySeconds))
            {
                delay = retrySeconds * OsvRetryInitialDelayMs;
            }

            _logger.LogWarning("OSV rate-limited; retrying in {Delay}ms (attempt {Attempt}/3)", delay, attempt + 1);
            // now-ok: back-off between live HTTP attempts against a rate-limiting upstream —
            // the pause has to be real elapsed time for the server's window to reopen, and no
            // caller observes it as a deadline.
            try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { break; }
            delay = Math.Min(delay * OsvRetryBackoffMultiplier, OsvRetryMaxDelayMs);
        }

        // Return a synthetic 429 after exhausting retries.
        return new HttpResponseMessage(HttpStatusCode.TooManyRequests);
    }

    private static OsvAdvisory ParseAdvisory(OsvVulnRaw raw, bool isHydrated, string? rawJson = null)
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

        // Extract CVSS score and severity text from the severity array — prefers whichever
        // entry actually parses, highest CVSS version first, over the array's listing order.
        string? severity;
        double? cvssScore;
        (cvssScore, severity) = OsvScoring.SelectCvssBaseScore(
            raw.Severity?.Select(s => (s.Type, s.Score)));

        // Fall back to database_specific.severity for severity text
        if (severity is null && raw.DatabaseSpecific?.TryGetValue("severity", out object? dbSev) == true)
        {
            severity = dbSev?.ToString();
        }

        return new OsvAdvisory(
            Id: raw.Id ?? "",
            Aliases: raw.Aliases?.ToArray() ?? [],
            Summary: raw.Summary,
            Severity: OsvScoring.NormalizeSeverity(severity),
            CvssScore: cvssScore,
            AffectedPackages: affectedPackages,
            Published: raw.Published,
            Modified: raw.Modified,
            IsHydrated: isHydrated,
            RawJson: rawJson);
    }

    // CVSS scoring + severity normalisation moved to OsvScoring (shared with LocalOsvSource).

    // ── Raw OSV JSON shapes ───────────────────────────────────────────────────

    private sealed record OsvQueryResponse(List<OsvVulnRaw>? Vulns, string? NextPageToken);

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
/// <see cref="RawJson"/> carries the full advisory JSON for persistence; it is populated only
/// on hydrated records and is null on the /querybatch stub path.
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
    bool IsHydrated,
    string? RawJson = null);

/// <summary>
/// One entry from an OSV advisory's <c>affected[]</c> array — a specific package
/// (identified by PURL, ecosystem, and name) together with the versions affected.
/// </summary>
public sealed record OsvAffectedPackage(
    string? Purl,
    string? Ecosystem,
    string? Name,
    string[] Versions);
