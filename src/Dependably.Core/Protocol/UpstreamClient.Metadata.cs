using System.Text.Json;
using Dependably.Infrastructure.Observability;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Protocol;

/// <summary>Uncached and single-flight-cached metadata-fetch path for
/// <see cref="UpstreamClient"/> (simple index pages, registration JSON, npm packuments, …), plus
/// the shared capped-body-read helper.</summary>
public sealed partial class UpstreamClient
{
    /// <summary>
    /// Fetches metadata without caching (simple index, registration JSON, etc.).
    /// </summary>
    public async Task<HttpResponseMessage> GetMetadataAsync(
        string url, string? authorizationHeader = null, CancellationToken ct = default)
    {
        // Air-gapped: also block uncached metadata fetches. Simple-index pages and npm
        // packuments are derived locally from the registry's own state in air-gap mode.
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(url);
        }

        if (!await _urlValidator.IsAllowedAsync(url, orgId: null, ct))
        {
            throw new SsrfBlockedException(url);
        }

        var client = _httpClientFactory.CreateClient("upstream");
        return await UnwrapSsrfAsync(() => SendMetadataRequestAsync(client, url, authorizationHeader, accept: null, ct, HttpCompletionOption.ResponseContentRead));
    }

    // Builds and sends a GET for a metadata document, attaching the per-upstream Authorization
    // header (Bearer/Basic) when configured. A fresh HttpRequestMessage is required because a
    // header on the shared "upstream" HttpClient would leak across tenants. An explicit Accept
    // header selects a content-negotiated variant (npm's abbreviated packument); when null, no
    // Accept is sent and the upstream serves its default document.
    private static async Task<HttpResponseMessage> SendMetadataRequestAsync(
        HttpClient client, string url, string? authorizationHeader, string? accept, CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseHeadersRead)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (authorizationHeader is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        if (accept is not null)
        {
            request.Headers.TryAddWithoutValidation("Accept", accept);
        }

        return await client.SendAsync(request, completionOption, ct);
    }

    /// <summary>
    /// Single-flighted metadata fetch. Returns a buffered response shareable across
    /// concurrent callers — only one upstream HTTP request runs per URL at a time, even
    /// when N CI runners hit a cold-start coordinate simultaneously. Returned value is
    /// immutable; callers inspect <see cref="UpstreamMetadataResponse.StatusCode"/> and
    /// read the buffered body directly (the old <see cref="GetMetadataAsync"/> path
    /// returned an <see cref="HttpResponseMessage"/> whose stream could only be consumed
    /// once, which is why the controllers couldn't share fetches).
    /// </summary>
    public Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(
        string url, string? authorizationHeader = null, CancellationToken ct = default)
        => GetOrFetchMetadataAsync(url, MaxMetadataResponseBytes, authorizationHeader, accept: null, ct);

    /// <summary>
    /// Variant of <see cref="GetOrFetchMetadataAsync(string, string, CancellationToken)"/> with an
    /// explicit body cap. Callers that buffer artifact bytes through this path (npm tarballs,
    /// NuGet flatcontainer, Maven fetch-then-hash, PyPI unknown-sha cold start) pass
    /// <see cref="MaxUpstreamResponseBytes"/>; metadata callers use the default overload.
    /// Throws <see cref="UpstreamResponseTooLargeException"/> when the body exceeds the cap.
    /// </summary>
    public Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(
        string url, long maxBytes, string? authorizationHeader = null, CancellationToken ct = default)
        => GetOrFetchMetadataAsync(url, maxBytes, authorizationHeader, accept: null, ct);

    /// <summary>
    /// Variant with an explicit Accept header for upstreams that content-negotiate different
    /// documents at one URL (npm's full vs abbreviated packument — see
    /// <see cref="NpmPackumentFetcher"/>). The Accept value participates in the single-flight
    /// and TTL-cache keys, so two variants of the same URL never share a fetch or an entry.
    /// </summary>
    public async Task<UpstreamMetadataResponse> GetOrFetchMetadataAsync(
        string url, long maxBytes, string? authorizationHeader, string? accept, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(url);
        }

        // The TTL-cache key carries the per-upstream credential hash and the Accept variant. The
        // cache is a shared singleton across every org, so keying on URL alone would let one
        // tenant's authenticated private-registry body satisfy another tenant's request for the
        // same URL under different (or no) credentials — a cross-tenant disclosure. Hashing the
        // Authorization header the same way the single-flight key does gives anonymous public
        // registries one shared entry while isolating authenticated upstreams per credential. The
        // Accept variant is folded in for the same reason as the in-flight key: a cached full body
        // must never satisfy an abbreviated request (or vice versa) under content negotiation.
        string cacheKey = url + "\nauth:" + AuthHeaderHash(authorizationHeader)
            + (accept is null ? "" : "\naccept:" + accept);

        // A fresh cached entry short-circuits before any SSRF pre-check or upstream call — the
        // whole point of the cache. Stale entries fall through to a single-flight refresh below
        // and are only served if that refresh fails transiently.
        bool cacheEnabled = _metadataCache is { Enabled: true };
        if (cacheEnabled && _metadataCache!.TryGet(cacheKey) is { Fresh: true } hit)
        {
            return hit.Response;
        }

        bool allowed = await _urlValidator.IsAllowedAsync(url, orgId: null, ct);
        if (!allowed)
        {
            throw new SsrfBlockedException(url);
        }

        try
        {
            if (cacheEnabled)
            {
                // The cached path records its own edge outcome at the source of truth: only it
                // can tell a genuine upstream 2xx apart from a stale entry served because the
                // master was unreachable — both surface here as an identical 2xx response.
                return await GetOrFetchMetadataCachedAsync(url, cacheKey, maxBytes, authorizationHeader, accept, ct);
            }

            var result = await SingleFlightMetadataAsync(url, maxBytes, authorizationHeader, accept, ct);

            // The master answered — a 2xx or a 404 both prove reachability. A returned 5xx
            // (surfaced without throwing) is an upstream failure, not a reachable response.
            RecordEdgeMetadataOutcome(reachable: !IsTransientStatus(result.StatusCode));
            return result;
        }
        catch (OperationCanceledException)
        {
            // Caller cancellation is not a master-reachability signal.
            throw;
        }
        catch (Exception ex) when (IsTransientMetadataFailure(ex))
        {
            RecordEdgeMetadataOutcome(reachable: false);
            throw;
        }
    }

    // Feeds a metadata-fetch outcome into the edge master-reachability tracker; a null tracker
    // (omitted in tests or callers that don't wire it) makes this a cheap no-op.
    private void RecordEdgeMetadataOutcome(bool reachable)
    {
        if (_edgeStatus is null)
        {
            return;
        }

        if (reachable)
        {
            _edgeStatus.RecordSuccess();
        }
        else
        {
            _edgeStatus.RecordFailure();
        }
    }

    // Runs the single-flight refresh through the cache: stores a 2xx positively, a 404
    // negatively, and — on a transient upstream failure (network/timeout/5xx) — serves a stale
    // positive entry within the max-stale window rather than propagating the failure.
    //
    // Records the edge master-reachability outcome for every path that RETURNS a response,
    // because it is the only place that knows the true outcome: a stale-served 2xx (or the
    // LogServedStale-logged 5xx fallback) means the master was UNREACHABLE even though the caller
    // sees a 2xx, so it must record a failure — otherwise a steady outage while stale metadata is
    // served looks like a healthy link. Exactly one outcome is recorded per fetch: a genuine
    // 2xx/404 = success, a stale-serve = failure. A transient failure with no stale entry to
    // serve rethrows and is recorded once by the caller's catch, not here.
    private async Task<UpstreamMetadataResponse> GetOrFetchMetadataCachedAsync(
        string url, string cacheKey, long maxBytes, string? authorizationHeader, string? accept, CancellationToken ct)
    {
        var cache = _metadataCache!;
        UpstreamMetadataResponse response;
        try
        {
            response = await SingleFlightMetadataAsync(url, maxBytes, authorizationHeader, accept, ct);
        }
        catch (Exception ex) when (IsTransientMetadataFailure(ex))
        {
            var stale = cache.ShouldServeStale(cacheKey);
            if (stale is not null)
            {
                // Serving stale means the master could not be reached — record the failure even
                // though the caller receives a usable 2xx from the cache.
                RecordEdgeMetadataOutcome(reachable: false);
                MetadataResponseCache.LogServedStale(_logger, url, ex, upstreamStatus: null);
                return stale;
            }

            // No stale entry to fall back on: let the transient failure propagate. The caller's
            // catch records the failure outcome, so this path must not record it here.
            throw;
        }

        if (response.IsSuccessStatusCode)
        {
            cache.StorePositive(cacheKey, response);
        }
        else if (response.StatusCode == (int)System.Net.HttpStatusCode.NotFound)
        {
            cache.StoreNegative(cacheKey, response);
        }
        else if (IsTransientStatus(response.StatusCode) && cache.ShouldServeStale(cacheKey) is UpstreamMetadataResponse stale)
        {
            // A 5xx that isn't itself an exception: prefer a stale-but-good answer over relaying
            // the upstream's transient failure. Never cache the 5xx itself. The master was
            // unreachable, so record a failure even though a stale 2xx is returned.
            RecordEdgeMetadataOutcome(reachable: false);
            MetadataResponseCache.LogServedStale(_logger, url, cause: null, upstreamStatus: response.StatusCode);
            return stale;
        }

        // A genuine upstream answer reached us: 2xx/404 proves reachability, a non-stale-served
        // 5xx is still an upstream failure.
        RecordEdgeMetadataOutcome(reachable: !IsTransientStatus(response.StatusCode));
        return response;
    }

    // Coalesces concurrent callers for the same URL into one upstream fetch (the existing
    // single-flight machinery), independent of whether a TTL cache wraps it.
    private async Task<UpstreamMetadataResponse> SingleFlightMetadataAsync(
        string url, long maxBytes, string? authorizationHeader, string? accept, CancellationToken ct)
    {
        // Key on URL + maxBytes + a hash of the Authorization header + the Accept variant so
        // joiners never inherit a different caller's body cap, credentials, or negotiated
        // document: two callers with different caps (e.g. a 32 MB metadata cap vs the 600 MB
        // artifact cap), different per-org upstream tokens, or different Accept variants for
        // the same URL never share a fetch; genuinely identical requests still collapse to one.
        string inflightKey = url + "\n" + maxBytes + "\n" + AuthHeaderHash(authorizationHeader) + "\n" + (accept ?? "");

        // CancellationToken.None: a disconnect from the first caller must not fault the
        // shared Lazy and cancel every other waiter (mirrors the blob-fetch convention).
        var lazy = _metadataInflight.GetOrAdd(inflightKey, _ => new Lazy<Task<UpstreamMetadataResponse>>(
            () => FetchMetadataBufferedAsync(url, maxBytes, authorizationHeader, accept, CancellationToken.None)));
        ScheduleInflightRemoval(_metadataInflight, inflightKey, lazy);

        return await lazy.Value.WaitAsync(ct);
    }

    // A thrown failure is transient (serve-stale-eligible) when it is a network/timeout/
    // too-large condition — not a pre-flight policy block (SSRF, air-gap) and not a caller
    // cancellation. SsrfBlockedException and AirGappedException surface as themselves; a caller
    // cancellation (ct) is the caller's own concern, not an upstream failure.
    private static bool IsTransientMetadataFailure(Exception ex) => ex switch
    {
        SsrfBlockedException => false,
        AirGappedException => false,
        OperationCanceledException => false,
        UpstreamResponseTooLargeException => true,
        HttpRequestException => true,
        IOException => true,
        _ => false,
    };

    // The full 5xx range (not just the named HttpStatusCode members) counts as a transient
    // upstream failure eligible for stale-serve.
    private const int ServerErrorRangeStart = (int)System.Net.HttpStatusCode.InternalServerError;
    private const int ServerErrorRangeEnd = 599;

    private static bool IsTransientStatus(int status) =>
        status is >= ServerErrorRangeStart and <= ServerErrorRangeEnd;

    private async Task<UpstreamMetadataResponse> FetchMetadataBufferedAsync(
        string url, long maxBytes, string? authorizationHeader, string? accept, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient("upstream");
        // ResponseHeadersRead is load-bearing: the default (ResponseContentRead) would have
        // HttpClient buffer the whole body before the cap check, defeating it.
        using var response = await UnwrapSsrfAsync(
            () => SendMetadataRequestAsync(client, url, authorizationHeader, accept, ct));
        byte[] body = await ReadBodyCappedAsync(response, maxBytes, url, ct);
        string? contentType = response.Content.Headers.ContentType?.ToString();
        return new UpstreamMetadataResponse(
            (int)response.StatusCode,
            response.IsSuccessStatusCode,
            contentType,
            body);
    }

    /// <summary>
    /// Buffers an upstream response body with a hard byte cap. The single place buffered
    /// upstream reads are allowed to materialise bytes: fails fast when the declared
    /// Content-Length already exceeds the cap (mirroring the streaming path), then copies
    /// the body through a counted loop so chunked or auto-decompressed transfers — where
    /// Content-Length is absent or describes the compressed size — cannot inflate past the
    /// cap into managed memory. Throws <see cref="UpstreamResponseTooLargeException"/> when
    /// the cap is crossed.
    /// </summary>
    public static async Task<byte[]> ReadBodyCappedAsync(
        HttpResponseMessage response, long maxBytes, string url, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new UpstreamResponseTooLargeException(url, maxBytes);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(ct);

        // Pre-size the buffer from a trustworthy Content-Length so a body near the cap does not
        // drive the MemoryStream through ~13 doubling reallocations (each copying the whole
        // buffer). A missing, zero, or over-cap Content-Length (chunked / auto-decompressed
        // transfers) falls back to the default growth strategy — the counted loop below still
        // enforces the hard cap regardless of the declared length.
        long? declared = response.Content.Headers.ContentLength;
        int initialCapacity = declared is > 0 && declared <= maxBytes ? (int)declared.Value : 0;
        using var buffered = initialCapacity > 0 ? new MemoryStream(initialCapacity) : new MemoryStream();
        byte[] buffer = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (buffered.Length + read > maxBytes)
            {
                throw new UpstreamResponseTooLargeException(url, maxBytes);
            }

            buffered.Write(buffer, 0, read);
        }

        // When the pre-sized buffer filled exactly (Content-Length matched the actual body),
        // GetBuffer() already holds a right-sized array — return it directly instead of paying
        // for a second full-size copy via ToArray(), which would double the transient peak at
        // the 600 MB artifact cap. Any mismatch (chunked, truncated, or grown past capacity)
        // falls back to ToArray() so the returned array is never over-allocated.
        byte[] exact = buffered.GetBuffer();
        return exact.Length == buffered.Length ? exact : buffered.ToArray();
    }
}
