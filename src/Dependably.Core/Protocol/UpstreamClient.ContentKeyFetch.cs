using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Observability;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Protocol;

/// <summary>Content-addressed proxy fetch path for <see cref="UpstreamClient"/> — streams an
/// upstream artefact whose SHA-256 is not known before download straight to the content-keyed
/// blob store, hashing inline.</summary>
public sealed partial class UpstreamClient
{
    /// <summary>
    /// Streaming proxy fetch for artifacts whose SHA-256 is not known before the download
    /// (npm tarballs, NuGet flatcontainer). Streams upstream → local temp file (hashing
    /// inline) → stores under <see cref="BlobKeys.Proxy(string)"/> using the computed
    /// SHA-256 → returns the <see cref="UpstreamFetchResult"/> with the content-addressed
    /// key, SHA-256 hex, and byte count. Memory usage is bounded by the staging buffer
    /// regardless of artifact size. Skips the upload when the blob already exists in the
    /// store (idempotent). Uses the same thundering-herd dedup as
    /// <see cref="GetOrFetchStreamAsync"/> — concurrent first-fetches of the same URL
    /// share one upstream call.
    /// </summary>
    public async Task<UpstreamFetchResult> FetchAndCacheByUrlAsync(
        string upstreamUrl,
        ChecksumSpec? checksumSpec,
        string ecosystem,
        string? orgId = null,
        string? authorizationHeader = null,
        CancellationToken ct = default)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException(upstreamUrl);
        }

        // Dedup concurrent fetches by URL + a hash of the Authorization header. Keying on the
        // header (not just the URL) means two callers presenting different credentials — or
        // different per-tenant upstream tokens for the same URL — never ride the same fetch;
        // genuinely identical requests (same URL, same credentials) still collapse to one. The
        // shared work item writes the blob and returns the content-addressed key; each caller
        // receives the same UpstreamFetchResult and can independently open the cached blob.
        // CancellationToken.None prevents a single caller disconnect from faulting the shared
        // Lazy and cancelling all other waiters.
        string inflightKey = upstreamUrl + "\n" + AuthHeaderHash(authorizationHeader);
        var lazy = _urlInflight.GetOrAdd(inflightKey, _ => new Lazy<Task<UpstreamFetchResult>>(
            () => FetchAndStageToContentKeyAsync(upstreamUrl, checksumSpec, ecosystem, orgId, authorizationHeader, CancellationToken.None)));
        ScheduleInflightRemoval(_urlInflight, inflightKey, lazy);

        using var activity = DependablyActivitySource.Source.StartActivity(
            "proxy.fetch", ActivityKind.Client);
        activity?.SetTag("dependably.ecosystem", ecosystem);
        activity?.SetTag("dependably.operation", "proxy.fetch");
        activity?.SetTag("dependably.tier", "cache");

        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        string outcome = "success";

        DependablyMeter.UpstreamSingleFlightJoins.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        try
        {
            return await lazy.Value.WaitAsync(ct);
        }
        catch (ChecksumException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "checksum mismatch");
            throw;
        }
        catch (UpstreamResponseTooLargeException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream response too large");
            throw;
        }
        catch (AirGappedException)
        {
            outcome = "blocked";
            activity?.SetStatus(ActivityStatusCode.Error, "air-gapped");
            throw;
        }
        catch (StagingDiskFullException)
        {
            outcome = "staging_disk_full";
            activity?.SetStatus(ActivityStatusCode.Error, "staging disk full");
            throw;
        }
        catch (UpstreamFetchFailedException ex) when (ex.Refused)
        {
            outcome = "upstream_refused";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream refused (auth/policy)");
            throw;
        }
        catch (UpstreamFetchFailedException)
        {
            outcome = "upstream_error";
            activity?.SetStatus(ActivityStatusCode.Error, "upstream fetch failed");
            throw;
        }
        catch (Exception ex)
        {
            outcome = "server_error";
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            _logger.LogWarning(
                ex,
                "Upstream fetch failed: {ExceptionType} for {Ecosystem} from {UpstreamUrl} after {Duration:F0}ms trace={TraceId}",
                ex.GetType().Name,
                ecosystem,
                upstreamUrl,
                stopwatch.Elapsed.TotalMilliseconds,
                Activity.Current?.TraceId.ToString());
            throw;
        }
        finally
        {
            activity?.SetTag("dependably.outcome", outcome);
            RecordEdgeOutcome(outcome);
        }
    }

    /// <summary>
    /// Hash-and-stage MISS path for the no-pre-known-SHA case (npm, NuGet). Streams
    /// upstream → temp file → verifies optional checksum → writes the blob under
    /// <see cref="BlobKeys.Proxy(string)"/> (the content-addressed key derived from the
    /// inline-computed SHA-256) → returns the result. Skips the blob-store write when
    /// the content-addressed key already exists (concurrent callers that lost the race
    /// to the same artifact content). The shared single-flight work item behind _urlInflight —
    /// owns the UpstreamInflightFetches gauge and UpstreamFetchDuration histogram so both
    /// instruments count real upstream operations, not per-caller waits.
    /// </summary>
    private async Task<UpstreamFetchResult> FetchAndStageToContentKeyAsync(
        string url, ChecksumSpec? spec, string ecosystem, string? orgId, string? authorizationHeader, CancellationToken ct)
    {
        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
        var stopwatch = Stopwatch.StartNew();
        string outcome = "success";
        DependablyMeter.UpstreamInflightFetches.Add(1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
        try
        {
            return await FetchAndStageToContentKeyCoreAsync(url, spec, ecosystem, orgId, authorizationHeader, ct);
        }
        catch (ChecksumException) { outcome = "upstream_error"; throw; }
        catch (UpstreamResponseTooLargeException) { outcome = "upstream_error"; throw; }
        catch (StagingDiskFullException) { outcome = "staging_disk_full"; throw; }
        catch (UpstreamFetchFailedException) { outcome = "upstream_error"; throw; }
        catch (Exception) { outcome = "server_error"; throw; }
        finally
        {
            DependablyMeter.UpstreamInflightFetches.Add(-1, new KeyValuePair<string, object?>("ecosystem", ecosystem));
            DependablyMeter.UpstreamFetchDuration.Record(
                stopwatch.Elapsed.TotalSeconds,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", outcome));
        }
    }

    private async Task<UpstreamFetchResult> FetchAndStageToContentKeyCoreAsync(
        string url, ChecksumSpec? spec, string ecosystem, string? orgId, string? authorizationHeader, CancellationToken ct)
    {
        if (!await _urlValidator.IsAllowedAsync(url, orgId, ct))
        {
            throw new SsrfBlockedException(url);
        }

        // Phase 1 — absolute floor before the HTTP GET (mirrors FetchAndStageCoreAsync).
        EnsureStagingDiskFloorBeforeFetch();

        var client = _httpClientFactory.CreateClient("upstream");
        // Retry loop for transient upstream failures; same contract as FetchAndStageAsync.
        // Non-transient failures (e.g. 404) propagate as HttpRequestException so the
        // controller's multi-base loop can try the next upstream registry.
        using var response = await FetchWithRetryAsync(
            client, url, orgId, authorizationHeader, containmentBase: null, ct);

        // Phase 2 — dynamic floor based on Content-Length, checked after response headers arrive.
        EnsureStagingDiskFloorForContentLength(response.Content.Headers.ContentLength);

        long reservedBytes = ReserveStagingBytes(response.Content.Headers.ContentLength);
        try
        {
            if (response.Content.Headers.ContentLength > MaxUpstreamResponseBytes)
            {
                // audit-attribution-ok: single-flight dedup — this fetch may be shared by several
                // concurrent inbound requests for the same URL (see the class docs), so there is
                // no one caller's IP to attribute the shared upstream outcome to.
                await _audit.LogAsync("upstream_response_too_large", orgId: orgId, ecosystem: ecosystem,
                    detail: JsonSerializer.Serialize(
                        new { url, content_length = response.Content.Headers.ContentLength }, EventJsonOptions.Detail),
                    ct: ct);
                throw new UpstreamResponseTooLargeException(url, MaxUpstreamResponseBytes);
            }

            return await StreamHashAndStoreByContentKeyAsync(response, spec, url, ecosystem, orgId, ct);
        }
        finally
        {
            ReleaseStagingBytes(reservedBytes);
        }
    }

    // Streams the upstream response body to a temp file, computes SHA-256 inline, verifies
    // any supplied checksum, stores under the content-addressed BlobKeys.Proxy key, and
    // returns the result. Cleans up the temp file unconditionally. Separated from
    // FetchAndStageToContentKeyAsync to keep each method under the S138 line ceiling.
    private async Task<UpstreamFetchResult> StreamHashAndStoreByContentKeyAsync(
        HttpResponseMessage response, ChecksumSpec? spec,
        string url, string ecosystem, string? orgId, CancellationToken ct)
    {
        string tempPath = Path.Combine(_stagingPath, $"dependably-stage-{Guid.NewGuid():N}.tmp");
        string sha256Hex = string.Empty;
        long sizeBytes = 0;

        try
        {
            await using (var responseStream = await response.Content.ReadAsStreamAsync(ct))
            {
                var fileStream = new FileStream(
                    tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    bufferSize: 81920, useAsync: true);
                await using var staging = new HashingFileStream(fileStream, MaxUpstreamResponseBytes);
                try
                {
                    await responseStream.CopyToAsync(staging, ct);
                }
                catch (UpstreamResponseTooLargeException)
                {
                    // audit-attribution-ok: single-flight dedup — this fetch may be shared by
                    // several concurrent inbound requests for the same URL (see the class docs),
                    // so there is no one caller's IP to attribute the shared upstream outcome to.
                    await _audit.LogAsync(
                        "upstream_response_too_large", orgId: orgId, ecosystem: ecosystem,
                        detail: JsonSerializer.Serialize(
                            new { url, bytes_read = staging.BytesWritten }, EventJsonOptions.Detail),
                        ct: ct);
                    throw new UpstreamResponseTooLargeException(url, MaxUpstreamResponseBytes);
                }
                sha256Hex = staging.GetSha256Hex();
                sizeBytes = staging.BytesWritten;
            }

            if (spec is not null && !await VerifyChecksumAsync(
                    new VerifyChecksumRequest(tempPath, sha256Hex, spec, url, ecosystem, orgId, null), ct))
            {
                throw new ChecksumException($"Upstream checksum mismatch for {url}");
            }

            // Store under the content-addressed key derived from the computed SHA-256.
            // Idempotent: concurrent callers that hashed the same content skip the write, and
            // that dedup is also why the quota gate guards only a genuinely new blob — bytes
            // already resident under this key grow the cache plane by nothing. The tenant is
            // still charged for them once it records access, because org_storage_bytes counts a
            // cache_artifact against every tenant holding tenant_artifact_access on it, so the
            // next fill this tenant attempts weighs them.
            string blobKey = BlobKeys.Proxy(sha256Hex);
            bool newBlob = !await _blobs.ExistsAsync(blobKey, ct);
            if (newBlob)
            {
                // Enforce the tenant's storage ceiling before the new bytes land in the blob
                // store — the same per-org quota hosted publish and OCI push enforce. Held until
                // the write completes so concurrent fills weigh these not-yet-recorded bytes.
                using var quota = await ReserveTenantCacheQuotaAsync(orgId, sizeBytes, ct);

                await using var verified = new FileStream(
                    tempPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    bufferSize: 81920, useAsync: true);
                await _blobs.PutAsync(blobKey, verified, ct);
            }

            DependablyMeter.CacheLookups.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem),
                new KeyValuePair<string, object?>("outcome", "miss"));
            SnapshotCounters.IncrementCacheMiss();
            SnapshotCounters.IncrementProxyFetch();

            return new UpstreamFetchResult(
                sha256Hex, sizeBytes, blobKey, LastModified: response.Content.Headers.LastModified);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to delete staging temp file {TempPath}: {ExceptionType}",
                    tempPath, ex.GetType().Name);
            }
        }
    }
}
