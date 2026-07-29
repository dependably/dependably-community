using System.IO.Compression;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Serves <c>npm audit</c>'s bulk-advisories endpoint by projecting the registry's OSV-backed
/// advisory data into npm's wire format.
///
/// Tenancy: this endpoint reads no tenant-scoped data at all. The request carries the caller's
/// own dependency tree (names + versions) and the answer is a pure function of that input and
/// the global OSV advisory set — it never consults the registry's package inventory, so it
/// cannot be used as a cross-tenant package-existence oracle. The only org-scoped read is the
/// <c>AnonymousPull</c> settings lookup that gates every other npm read path.
///
/// Fan-out: one OSV query per (name, version) pair, issued through
/// <see cref="IOsvSource.TryQueryBatchAsync"/> (which dedupes advisory hydration across the batch).
/// The request is capped on every axis before any query is issued — see the Max* constants.
///
/// Never fabricates an all-clear: the endpoint answers 503 whenever it cannot vouch for a complete
/// report — an unreached source, a short result set, or advisories that could not be hydrated. The
/// batch API's plain contract is swallow-and-return-empty on every failure mode, so an outage
/// answers with a full-length list of empty results that reads exactly like a clean tree; only
/// <see cref="OsvBatchQueryResult.Reached"/> tells the two apart.
/// </summary>
public sealed class NpmAuditHandler(
    OrgRepository orgs,
    TokenRepository tokens,
    IOsvSource osv,
    ILogger<NpmAuditHandler> logger)
{
    /// <summary>
    /// Ceiling on (name, version) pairs per request. Matches OSV's documented <c>/querybatch</c>
    /// limit of 1000 queries, so a request that passes this check maps onto exactly one upstream
    /// batch call rather than an unbounded fan-out of them.
    /// </summary>
    private const int MaxQueriesPerRequest = 1000;

    /// <summary>Ceiling on distinct package names per request.</summary>
    private const int MaxPackagesPerRequest = 500;

    /// <summary>Ceiling on distinct versions for any one package.</summary>
    private const int MaxVersionsPerPackage = 100;

    /// <summary>
    /// Ceiling on the decompressed request body. A 1000-pair payload is roughly 30 KB, so this is
    /// generous for any legitimate tree while bounding a gzip bomb: the body is read through a
    /// counting cap, not decompressed wholesale and measured afterwards.
    /// </summary>
    private const int MaxBodyBytes = 4 * 1024 * 1024;

    /// <summary>Ceilings on individual identifier lengths, applied before a purl is built.</summary>
    private const int MaxNameLength = 214; // npm's own package-name limit
    private const int MaxVersionLength = 256;

    private static readonly JsonSerializerOptions ResponseJsonOptions = new()
    {
        // Every property is pinned with [JsonPropertyName]; dictionary keys are package names and
        // must pass through verbatim (npm re-queries its tree by the exact key it receives), so no
        // naming policy is set on either axis. Explicit options rather than the framework default.
        PropertyNamingPolicy = null,
        DictionaryKeyPolicy = null,
    };

    private static readonly JsonSerializerOptions RequestJsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
    };

    /// <summary>
    /// POST /-/npm/v1/security/advisories/bulk. Request body is
    /// <c>{"&lt;name&gt;": ["1.0.0", ...], ...}</c>; the response is the same shape keyed by
    /// package name, with only the packages that have advisories present — a clean package is
    /// omitted entirely rather than returned with an empty array, matching registry.npmjs.org.
    /// </summary>
    public async Task<IActionResult> BulkAdvisoriesAsync(
        HttpContext httpContext, string orgId, CancellationToken ct)
    {
        var settings = await orgs.GetSettingsAsync(orgId, ct);
        var token = await httpContext.Request.ResolveTokenAsync(tokens, orgId, ct);

        if (!settings!.AnonymousPull && token is null)
        {
            httpContext.Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return new UnauthorizedResult();
        }

        var (body, readError) = await ReadRequestBodyAsync(httpContext, ct);
        if (readError is not null)
        {
            return readError;
        }

        Dictionary<string, string[]>? requested;
        try
        {
            requested = JsonSerializer.Deserialize<Dictionary<string, string[]>>(body!, RequestJsonOptions);
        }
        catch (JsonException)
        {
            return Problem(StatusCodes.Status400BadRequest,
                "Body must be a JSON object mapping package names to arrays of version strings.");
        }

        if (requested is null || requested.Count == 0)
        {
            // npm skips the call entirely when it has nothing to audit; an empty object is still
            // a well-formed question whose answer is "no advisories".
            return new JsonResult(new Dictionary<string, List<NpmAuditAdvisory>>(), ResponseJsonOptions);
        }

        var (pairs, limitError) = BuildQueryPlan(requested);

        return limitError is not null ? limitError
            : pairs.Count == 0
                ? new JsonResult(new Dictionary<string, List<NpmAuditAdvisory>>(), ResponseJsonOptions)
                : await QueryAndProjectAsync(pairs, ct);
    }

    // Flattens the request into the (name, version) pairs to query, enforcing every cap.
    // Malformed entries are skipped rather than failing the whole request: npm audit is advisory,
    // and one odd tree node should not blind the caller to the rest of the report.
    private static (List<QueryPair> Pairs, IActionResult? Error) BuildQueryPlan(
        Dictionary<string, string[]> requested)
    {
        if (requested.Count > MaxPackagesPerRequest)
        {
            return ([], TooLarge(
                $"Request names {requested.Count} packages; this registry audits at most " +
                $"{MaxPackagesPerRequest} per request."));
        }

        var pairs = new List<QueryPair>();

        foreach (var (name, versions) in requested)
        {
            if (!IsUsableName(name) || versions is null || versions.Length == 0)
            {
                continue;
            }

            if (versions.Length > MaxVersionsPerPackage)
            {
                return ([], TooLarge(
                    $"Package '{name}' names {versions.Length} versions; this registry audits at " +
                    $"most {MaxVersionsPerPackage} versions per package."));
            }

            foreach (string version in versions.Distinct(StringComparer.Ordinal))
            {
                if (!IsUsableVersion(version))
                {
                    continue;
                }

                if (pairs.Count >= MaxQueriesPerRequest)
                {
                    return ([], TooLarge(
                        $"Request exceeds the {MaxQueriesPerRequest} package-version limit this " +
                        "registry audits per request."));
                }

                pairs.Add(new QueryPair(name, version));
            }
        }

        return (pairs, null);
    }

    // Issues the batch query and folds the per-pair results into npm's per-package shape.
    private async Task<IActionResult> QueryAndProjectAsync(List<QueryPair> pairs, CancellationToken ct)
    {
        var purls = pairs.Select(p => PurlNormalizer.Npm(p.Name, p.Version)).ToList();

        var (batch, fetchError) = await FetchReachedBatchAsync(purls, pairs.Count, ct);
        if (fetchError is not null)
        {
            return fetchError;
        }

        var results = batch!.Results;

        // The batch contract is one result list per input purl, in order. A short list would
        // silently answer "clean" for the unmatched tail, so refuse rather than under-report.
        if (results.Count != pairs.Count)
        {
            logger.LogWarning(
                "npm bulk audit: advisory source returned {Results} result sets for {Queries} queries; refusing to report a partial answer",
                results.Count, pairs.Count);
            return Unavailable("The vulnerability advisory source returned an incomplete result set.");
        }

        var (byPackage, unprojectable) = AccumulateByPackage(pairs, results);

        // Only packages with advisories appear; a clean package is absent, not empty-array'd.
        var payload = byPackage.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.Values
                .Select(a => NpmAdvisoryProjection.Project(
                    a.Advisory, a.Detail, kvp.Key, a.AffectedVersions))
                .ToList(),
            StringComparer.Ordinal);

        // Refuse rather than serve a report known to be missing advisories. Projecting the records
        // instead would have to invent a severity for an advisory whose detail never arrived, and
        // the only honest choice (info) sits below npm's default audit-level — so a possibly
        // critical finding would render as a footnote and pass CI. A 503 fails loudly instead:
        // npm degrades it to "audit unavailable" rather than "found 0 vulnerabilities".
        if (unprojectable > 0)
        {
            logger.LogWarning(
                "npm bulk audit: {Unprojectable} advisory records could not be projected; refusing to report a knowingly incomplete answer",
                unprojectable);
            return Unavailable(
                "The vulnerability advisory source returned advisories that could not be resolved " +
                "in full; the audit report would be incomplete.");
        }

        logger.LogDebug(
            "npm bulk audit: {Queries} package-versions queried, {Affected} packages with advisories",
            pairs.Count, payload.Count);

        return new JsonResult(payload, ResponseJsonOptions);
    }

    // Issues the OSV batch query and refuses (rather than reports a false all-clear) when the
    // source could not be queried at all or was not reached.
    private async Task<(OsvBatchQueryResult? Batch, IActionResult? Error)> FetchReachedBatchAsync(
        List<string> purls, int queryCount, CancellationToken ct)
    {
        OsvBatchQueryResult batch;
        try
        {
            // TryQueryBatchAsync, not QueryBatchAsync: the batch contract is swallow-and-return-
            // empty on every failure mode (network error, non-2xx, rate-limit exhaustion, a
            // missing local dump directory), so a plain query answers an outage with a
            // full-length list of empty results that is indistinguishable from a clean tree.
            // Reporting that as "no advisories" is the one failure this endpoint must never have.
            batch = await osv.TryQueryBatchAsync(purls, ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "npm bulk audit: advisory source query failed: {ExceptionType}",
                ex.GetType().Name);
            return (null, Unavailable("The vulnerability advisory source is currently unavailable."));
        }

        if (!batch.Reached)
        {
            logger.LogWarning(
                "npm bulk audit: advisory source was not reached for {Queries} queries; refusing to report an all-clear",
                queryCount);
            return (null, Unavailable("The vulnerability advisory source is currently unavailable."));
        }

        return (batch, null);
    }

    // Accumulates per package name: advisory id -> (advisory, detail, versions proven affected).
    // Also counts records that matched but carry nothing projectable (no hydrated detail, or no
    // id) so the caller can refuse a knowingly incomplete report rather than silently drop them.
    private static (Dictionary<string, Dictionary<string, AdvisoryAccumulator>> ByPackage, int Unprojectable) AccumulateByPackage(
        List<QueryPair> pairs, List<List<OsvAdvisory>> results)
    {
        var byPackage = new Dictionary<string, Dictionary<string, AdvisoryAccumulator>>(StringComparer.Ordinal);
        int unprojectable = 0;

        for (int i = 0; i < pairs.Count; i++)
        {
            var (name, version) = (pairs[i].Name, pairs[i].Version);

            foreach (var advisory in results[i])
            {
                // Two ways a record a reached source affirmatively matched to this purl can carry
                // nothing projectable: its detail never arrived (the per-batch hydration cap, or a
                // failed GET /vulns/{id}), or it has no id to report at all (a malformed advisory —
                // the OSV schema mandates id, and the local index builds keys without gating on
                // it). Silently skipping either would report the package clean — the same
                // fabricated all-clear as answering an outage with an empty report, only narrower.
                // Count both and refuse below.
                if (!advisory.IsHydrated || string.IsNullOrEmpty(advisory.Id))
                {
                    unprojectable++;
                    continue;
                }

                var detail = NpmAdvisoryProjection.TryParseDetail(advisory.RawJson);
                if (!NpmAdvisoryProjection.Affects(detail, name, version))
                {
                    continue;
                }

                if (!byPackage.TryGetValue(name, out var perAdvisory))
                {
                    perAdvisory = new Dictionary<string, AdvisoryAccumulator>(StringComparer.Ordinal);
                    byPackage[name] = perAdvisory;
                }

                if (!perAdvisory.TryGetValue(advisory.Id, out var acc))
                {
                    acc = new AdvisoryAccumulator(advisory, detail, []);
                    perAdvisory[advisory.Id] = acc;
                }

                acc.AffectedVersions.Add(version);
            }
        }

        return (byPackage, unprojectable);
    }

    /// <summary>
    /// Reads the request body, transparently decompressing it when npm sends
    /// <c>Content-Encoding: gzip</c> — which arborist does on every audit request
    /// (npm-registry-fetch sets the header and gzips the payload). ASP.NET Core does not
    /// decompress request bodies by default, so without this the endpoint would reject every
    /// real npm client. The read is capped at <see cref="MaxBodyBytes"/> as it streams, so a
    /// small gzip bomb cannot expand into memory.
    /// </summary>
    private static async Task<(byte[]? Body, IActionResult? Error)> ReadRequestBodyAsync(
        HttpContext httpContext, CancellationToken ct)
    {
        string encoding = httpContext.Request.Headers.ContentEncoding.ToString();
        bool isGzip = encoding.Contains("gzip", StringComparison.OrdinalIgnoreCase);

        if (!isGzip && encoding.Length > 0
            && !encoding.Equals("identity", StringComparison.OrdinalIgnoreCase))
        {
            return (null, Problem(StatusCodes.Status415UnsupportedMediaType,
                $"Unsupported Content-Encoding '{encoding}'; use gzip or an uncompressed body."));
        }

        var source = httpContext.Request.Body;
        GZipStream? gzip = null;
        try
        {
            if (isGzip)
            {
                gzip = new GZipStream(source, CompressionMode.Decompress);
                source = gzip;
            }

            using var buffer = new MemoryStream();
            byte[] chunk = new byte[8192];
            int read;
            while ((read = await source.ReadAsync(chunk, ct)) > 0)
            {
                if (buffer.Length + read > MaxBodyBytes)
                {
                    return (null, TooLarge(
                        $"Audit request body exceeds the {MaxBodyBytes / (1024 * 1024)} MiB limit."));
                }

                buffer.Write(chunk, 0, read);
            }

            return (buffer.ToArray(), null);
        }
        catch (InvalidDataException)
        {
            return (null, Problem(StatusCodes.Status400BadRequest,
                "Request body is not valid gzip data."));
        }
        finally
        {
            if (gzip is not null)
            {
                await gzip.DisposeAsync();
            }
        }
    }

    private static bool IsUsableName(string name) =>
        !string.IsNullOrWhiteSpace(name)
        && name.Length <= MaxNameLength
        && !name.Any(char.IsControl);

    private static bool IsUsableVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version)
        && version.Length <= MaxVersionLength
        && !version.Any(char.IsControl);

    private static IActionResult TooLarge(string detail) =>
        Problem(StatusCodes.Status413PayloadTooLarge, detail);

    // Every path where the registry cannot vouch for a complete answer. npm treats a non-2xx audit
    // response as a soft warning and continues the install, so this degrades to "audit
    // unavailable" — never to "found 0 vulnerabilities".
    private static IActionResult Unavailable(string detail) =>
        Problem(StatusCodes.Status503ServiceUnavailable, detail);

    // ObjectResult + ProblemDetails so NpmErrorEnvelopeAttribute adds npm's `error` key.
    private static ObjectResult Problem(int status, string detail) =>
        new(new ProblemDetails
        {
            Status = status,
            Title = TitleFor(status),
            Detail = detail,
        })
        { StatusCode = status };

    private static string TitleFor(int status) => status switch
    {
        StatusCodes.Status400BadRequest => "Bad Request",
        StatusCodes.Status413PayloadTooLarge => "Payload Too Large",
        StatusCodes.Status415UnsupportedMediaType => "Unsupported Media Type",
        StatusCodes.Status503ServiceUnavailable => "Service Unavailable",
        _ => "Error",
    };

    private sealed record QueryPair(string Name, string Version);

    // Mutable accumulator: one advisory can be reported against several requested versions of the
    // same package, and the set of matched versions is what backs the vulnerable_versions fallback.
    private sealed record AdvisoryAccumulator(
        OsvAdvisory Advisory, OsvDetail? Detail, List<string> AffectedVersions);
}
