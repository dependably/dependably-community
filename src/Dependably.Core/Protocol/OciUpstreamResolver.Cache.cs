using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Storage;
using Microsoft.Extensions.Options;

namespace Dependably.Protocol;

/// <summary>
/// Cache lookup, upstream fetch, and the cache-write path — everything between "this resolver
/// decided to go upstream" and "the bytes are recorded and servable".
/// </summary>
public sealed partial class OciUpstreamResolver
{
    // ── Cache lookup helpers ───────────────────────────────────────────────────

    private async Task<OciManifestResult?> TryGetCachedManifestByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is already tenant-scoped.
        var (MediaType, SizeBytes, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        if (BlobKey is null)
        {
            return null;
        }

        var stream = await _blobs.Cache.GetAsync(BlobKey, ct);
        if (stream is null)
        {
            return null; // evicted — fall through to upstream
        }

        return new OciManifestResult(stream, MediaType ?? "application/octet-stream", digest, SizeBytes);
    }

    private async Task<OciManifestResult?> TryGetCachedTagManifestAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var (Digest, LastRevalidated) = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });

        if (Digest is null)
        {
            return null;
        }

        if (IsTagEntryFresh(LastRevalidated))
        {
            return await TryGetCachedManifestByDigestAsync(orgId, Digest, ct);
        }

        // Stale or missing — fall through to upstream.
        return null;
    }

    // ── Upstream fetch + cache-write helpers ──────────────────────────────────

    private async Task<OciManifestResult?> FetchAndCacheManifestAsync(
        OciUpstreamRegistryOptions upstream,
        string orgId,
        string repository,
        string reference,
        CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
        var manifest = await TryFetchManifestAsync(orgId, upstream, repository, reference, url, ct);
        return manifest is null ? null : await CacheAndReturnManifestAsync(upstream, orgId, repository, reference, manifest, ct);
    }

    private async Task<FetchedManifest?> TryFetchManifestAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string reference,
        string url, CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        // A non-success status (e.g. Docker Hub returns 401 — not 404 — for a
        // nonexistent/unauthorized repository even after the token retry) must surface
        // as a clean OCI MANIFEST_UNKNOWN 404 from the controller, not an unhandled
        // HttpRequestException → 500. Mirror the blob/tags paths: log and return null.
        string logContext = $"OCI manifest {repository}:{reference} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, ManifestAcceptTypes, upstream, repository, "pull", logContext, ct);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        byte[] bytes;
        try
        {
            // Manifests are small JSON documents (the spec recommends ≤ 4 MB); cap the buffered
            // read so a hostile upstream cannot materialise an arbitrarily large body in memory.
            bytes = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            _logger.LogWarning(ex,
                "OCI manifest {Repository}:{Reference} from {Host} exceeded the metadata cap; refusing.",
                repository, reference, upstream.Host);
            return null;
        }
        string digest = ResolveDigest(resp, repository, reference, bytes, out string? sha256Hex);

        // For by-digest references the caller already knows which digest to expect.
        // Verify the computed digest matches before caching — if upstream returns bytes
        // that hash to a different digest the fetch fails closed (no cache write, no DB
        // row) rather than serving attacker-controlled content under the requested key.
        if (OciCoordinatesParser.IsValidDigest(reference) &&
            !string.Equals(digest, reference, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "OCI manifest digest mismatch for {Repository}/{Reference}: computed {Computed} does not match requested digest",
                repository, reference, digest);
            return null;
        }

        return new FetchedManifest(bytes, mediaType, digest, sha256Hex);
    }

    private string ResolveDigest(
        HttpResponseMessage resp, string repository, string reference, byte[] bytes, out string sha256Hex)
    {
        byte[] sha256Bytes = SHA256.HashData(bytes);
        sha256Hex = Convert.ToHexString(sha256Bytes).ToLowerInvariant();
        string digest = "sha256:" + sha256Hex;

        // The content-addressed identity is the SHA-256 of the exact bytes cached and served, so
        // a by-digest fetch always returns bytes that hash to the requested digest (the OCI
        // Distribution Spec invariant). If upstream's Docker-Content-Digest disagrees, treat it
        // as an upstream integrity anomaly and keep the computed value — never adopt an
        // unverified header as the stored digest identity.
        if (resp.Headers.TryGetValues("Docker-Content-Digest", out var dcdValues))
        {
            string? upstreamDigest = dcdValues.FirstOrDefault();
            if (!string.IsNullOrEmpty(upstreamDigest) && upstreamDigest != digest)
            {
                _logger.LogWarning(
                    "OCI {Repository}/{Reference}: upstream Docker-Content-Digest {Upstream} differs from computed {Computed}; using computed",
                    repository, reference, upstreamDigest, digest);
            }
        }
        return digest;
    }

    private async Task<OciManifestResult> CacheAndReturnManifestAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string reference,
        FetchedManifest m, CancellationToken ct)
    {
        string blobKey = BlobKeys.OciBlob("sha256", m.Sha256Hex);

        // Write manifest bytes into the proxy cache tier.
        await _blobs.Cache.PutAsync(blobKey, new MemoryStream(m.Bytes), ct);

        await using var conn = await _db.OpenAsync(ct);

        // xtenant: (digest, org_id) PK is tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy', @now)
            ON CONFLICT(digest, org_id) DO UPDATE SET
                upstream_checked_at = @now
            """,
            new
            {
                digest = m.Digest,
                orgId,
                mediaType = m.MediaType,
                sizeBytes = (long)m.Bytes.Length,
                blobKey,
                now = UtcTimestamp.Now(_time),
            });

        // Capture the image license from the config label onto this manifest row. Runs outside the
        // tag branch so by-digest child manifests of a pulled index are covered too. Best-effort.
        await _licenseRecorder.RecordManifestAsync(orgId, m.Digest, m.Bytes, ct);

        // Record what this manifest references, so eviction can tell a shared layer from an
        // orphaned one. Outside the tag branch for the same reason as the license capture: an
        // index's by-digest children are manifests in their own right and each has a closure.
        // A body that does not parse records nothing, leaving the manifest un-evictable — the
        // conservative direction, and the same posture the read path takes on a malformed body.
        if (OciManifestParser.ParseReferences(m.Bytes) is { } refs)
        {
            await _referenceGraph.RecordAsync(orgId, m.Digest, refs.Digests, ct);
        }

        // Upsert tag → digest when the reference is a tag (not a digest). The manifest body was
        // written above, preserving the body-before-tag write ordering.
        if (!OciCoordinatesParser.IsValidDigest(reference))
        {
            await RepointTagAsync(upstream, orgId, repository, reference, m, ct);
        }

        _logger.LogInformation(
            "OCI manifest proxy {Repository}/{Reference} → {Digest} ({Bytes} B) from {Host}",
            repository, reference, m.Digest, m.Bytes.Length, upstream.Host);

        return new OciManifestResult(new MemoryStream(m.Bytes), m.MediaType, m.Digest, m.Bytes.Length);
    }

    /// <summary>
    /// Repoints (or first-records) a tag at a manifest whose body is already durably cached —
    /// every caller runs after the body write, keeping the body-before-tag ordering — and
    /// surfaces the pull in the shared package catalogue. Clears any pending observation: the
    /// repoint IS the promotion (or a confirmation of the same digest), so nothing is pending
    /// afterwards. Also records the tag → digest answer in the shared observation cache, since
    /// a digest-verified body is at least as authoritative as an upstream HEAD.
    /// </summary>
    private async Task RepointTagAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        FetchedManifest m, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
            VALUES (@orgId, @repo, @tag, @digest, @now, @now)
            ON CONFLICT(org_id, repository, tag) DO UPDATE SET
                digest          = excluded.digest,
                updated_at      = excluded.updated_at,
                last_revalidated = excluded.last_revalidated,
                pending_digest = NULL,
                pending_first_seen_at = NULL
            """,
            new { orgId, repo = repository, tag, digest = m.Digest, now = UtcTimestamp.Now(_time) });

        StoreTagObservation(upstream, repository, tag, m.Digest, m.MediaType, m.Bytes.Length);

        // Surface the pulled image in the shared package catalogue the dashboards +
        // Packages page read from. OCI otherwise lives only in oci_blobs/oci_tags and
        // counts as zero everywhere. Only tag pulls are catalogued (the user-facing
        // unit); by-digest sub-manifest fetches the daemon issues afterwards are not.
        string blobKey = BlobKeys.OciBlob("sha256", m.Sha256Hex);
        string manifestUrl = $"https://{upstream.Host}/v2/{repository}/manifests/{tag}";
        await RecordCatalogVersionAsync(
            orgId,
            new OciCatalogEntry(repository, tag, m.Digest, m.Sha256Hex, (long)m.Bytes.Length, blobKey, manifestUrl),
            ct);
    }

    private sealed record FetchedManifest(byte[] Bytes, string MediaType, string Digest, string Sha256Hex);

    private readonly record struct OciCatalogEntry(
        string Repository, string Tag, string Digest, string Sha256Hex, long SizeBytes, string BlobKey,
        string? UpstreamUrl);

    /// <summary>
    /// Records the pulled image in the shared package catalogue: a <c>packages</c> row (so the
    /// Packages page and its detail route resolve the repository name) plus a global-plane
    /// <c>cache_artifact</c> / <c>tenant_artifact_access</c> row pair — the same shared cache
    /// plane every other proxy ecosystem uses — rather than a <c>package_versions</c> row. The
    /// manifest digest is the content-addressed version identity; the resolving tag is captured
    /// in the PURL qualifier. Only manifest pulls land a row here — one per pullable image,
    /// matching a <c>docker pull</c> 1:1; layers and config blobs stay in <c>oci_blobs</c> as
    /// pure byte storage with no cache-plane entry.
    ///
    /// Best-effort: the caller (<see cref="CacheAndReturnManifestAsync"/>) awaits this before
    /// returning the manifest to the client, so an unhandled exception here would 500 a pull
    /// whose bytes are already durably cached (blob store + <c>oci_blobs</c> row, both written
    /// before this call). <see cref="CacheAccessRecorder.RecordAccessAsync"/> already swallows
    /// its own failures and <see cref="PackageRepository.GetOrCreateAsync"/> resolves races via
    /// <c>ON CONFLICT DO NOTHING</c> + re-read, but <see cref="CacheArtifactRepository.UpdateGlobalFactsAsync"/>
    /// and the <c>GetOrCreateAsync</c> call itself are plain Dapper calls that still throw on a
    /// transient fault (SQLITE_BUSY, a dropped connection) — caught here so cataloguing can never
    /// fail the pull.
    /// </summary>
    private async Task RecordCatalogVersionAsync(string orgId, OciCatalogEntry entry, CancellationToken ct)
    {
        try
        {
            // purl_name == repository so the Packages-page detail route (/packages/oci/{name})
            // resolves; isProxy=true marks the package as upstream-backed.
            await _packages.GetOrCreateAsync(orgId, "oci", entry.Repository, entry.Repository, isProxy: true, ct);
            string purl = PurlNormalizer.Oci(entry.Repository, entry.Digest, entry.Tag);

            // Name is entry.Repository, matching the purl_name GetOrCreateAsync just wrote onto
            // the packages row above — the cross-plane version-count join in PackageRepository
            // keys on ca.name = p.purl_name. BlobKey is left as the oci/{algo}/{hex} store key
            // rather than routed through BlobKeys.Proxy, which throws on a non-64-hex key.
            string? cacheArtifactId = await _cacheRecorder.RecordAccessAsync(
                new CacheAccess(
                    orgId, "oci", entry.Repository, entry.Digest, ManifestCacheFilename,
                    entry.Sha256Hex, entry.SizeBytes, entry.BlobKey, entry.UpstreamUrl,
                    // The manifest was pulled and digested on this request. The coordinate is the
                    // digest itself, so two orgs resolving one coordinate to different bytes is
                    // not expressible here — the binding is recorded for uniformity, not defence.
                    CacheAccessOrigin.FirstFetch),
                ct);

            if (cacheArtifactId is not null)
            {
                await _cacheArtifacts.UpdateGlobalFactsAsync(
                    cacheArtifactId,
                    purl: purl,
                    checksumSha1: null,
                    publishedAt: null,
                    deprecated: null,
                    hasInstallScript: false,
                    installScriptKind: null,
                    provenanceStatus: null,
                    provenanceSigner: null,
                    upstreamIntegrityValue: null,
                    upstreamIntegrityAlgorithm: null,
                    ct: ct);
            }

            // The manifest's license was stamped onto oci_blobs before this row existed; project it
            // onto the row now so every license reader sees it through the shared table.
            await _licenseRecorder.ProjectLicenseToCatalogAsync(orgId, entry.Digest, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} cataloguing OCI version {Repository}@{Digest}; pull unaffected. BlobKey={BlobKey} TraceId={TraceId}",
                ex.GetType().Name, entry.Repository, entry.Digest, entry.BlobKey,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
        }
    }

    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<OciBlobFetchMetadata?> FetchAndCacheBlobAsync(
        string orgId,
        OciUpstreamRegistryOptions upstream,
        string repository,
        string digest,
        string blobKey,
        CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        string logContext = $"OCI blob {digest} upstream {upstream.Host}";

        // Expected hex for post-download verification.
        string[] digestParts = digest.Split(':', DigestSplitParts);
        string expectedHex = digestParts.Length == DigestSplitParts ? digestParts[1].ToLowerInvariant() : "";

        // ResponseHeadersRead → don't buffer response in memory; stream body directly to blob store.
        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, ["application/octet-stream"], upstream, repository, "pull", logContext, ct,
            completionOption: HttpCompletionOption.ResponseHeadersRead);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        long bytesWritten;

        // Cheap fail-fast on a declared Content-Length before streaming a single byte, mirroring
        // every other ecosystem's upstream-fetch path (UpstreamClient.FetchAndStageCoreAsync).
        // OciDigestVerifyStream below still enforces the same cap for chunked transfers that
        // arrive with no Content-Length header at all.
        long maxBlobBytes = _options.Value.MaxBlobProxyBytes;
        if (resp.Content.Headers.ContentLength > maxBlobBytes)
        {
            _logger.LogWarning(
                "OCI blob {Repository}/{Digest} from {Host} declared Content-Length {ContentLength} exceeding the {MaxBytes}-byte blob proxy cap; refusing.",
                repository, digest, upstream.Host, resp.Content.Headers.ContentLength, maxBlobBytes);
            throw new OciBlobTooLargeException(
                digest, upstream.Host, maxBlobBytes, resp.Content.Headers.ContentLength);
        }

        // Verify-then-commit: stream upstream bytes into an ephemeral staging key so
        // the content-addressed blobKey is never written until the digest is confirmed.
        // A concurrent cache-first reader (FetchBlobAsync) checks blobKey directly;
        // because blobKey is only populated after a successful verification here, a
        // cache-first branch can only ever serve verified bytes.
        string stagingKey = BlobKeys.OciStaging(Guid.NewGuid().ToString("N"));

        try
        {
            await using var contentStream = await resp.Content.ReadAsStreamAsync(ct);
            await using var verifyStream = new OciDigestVerifyStream(contentStream, maxBlobBytes);

            await _blobs.Cache.PutAsync(stagingKey, verifyStream, ct);
            bytesWritten = verifyStream.BytesWritten;

            string computedDigest = verifyStream.ComputedDigest;
            if (!string.Equals(computedDigest, $"sha256:{expectedHex}", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "OCI blob digest mismatch for {Repository}/{Digest}: expected sha256:{Expected}, computed {Computed}",
                    repository, digest, expectedHex, computedDigest);
                await _blobs.Cache.DeleteAsync(stagingKey, ct);
                throw new OciBlobDigestMismatchException(digest, upstream.Host, computedDigest);
            }
        }
        catch (UpstreamResponseTooLargeException)
        {
            // Delete-on-refuse: a coordinate-addressed staging entry left behind here would be a
            // permanent bypass of this cap for every future request that races the same digest.
            _logger.LogWarning(
                "OCI blob {Repository}/{Digest} from {Host} exceeded the {MaxBytes}-byte blob proxy cap mid-stream; refusing.",
                repository, digest, upstream.Host, maxBlobBytes);
            await _blobs.Cache.DeleteAsync(stagingKey, ct);

            // Rethrown as the OCI-plane refusal rather than surfaced as a null: a chunked
            // upstream reaches the cap here with no declared length to have caught it above, and
            // the caller cannot tell that case from a miss unless it is told.
            throw new OciBlobTooLargeException(digest, upstream.Host, maxBlobBytes, declaredBytes: null);
        }

        // Digest verified — promote staging entry to the content-addressed key, then
        // clean up the staging slot so it never persists beyond this request.
        var stagedStream = await _blobs.Cache.GetAsync(stagingKey, ct);
        if (stagedStream is not null)
        {
            await _blobs.Cache.PutAsync(blobKey, stagedStream, ct);
        }

        await _blobs.Cache.DeleteAsync(stagingKey, ct);

        // Persist DB row for this org.
        bool inserted = await EnsureBlobDbRowAsync(orgId, digest, mediaType, bytesWritten, blobKey, ct);
        if (inserted)
        {
            // First insert of this blob for the org: reverse-lookup any manifest awaiting its
            // config license. Runs under the same single-flight token as the surrounding fetch.
            await _licenseRecorder.RecordConfigBlobArrivalAsync(orgId, digest, blobKey, ct);
        }

        _logger.LogInformation(
            "OCI blob proxy {Repository}/{Digest} ({Bytes} B) from {Host}",
            repository, digest, bytesWritten, upstream.Host);

        // Return only metadata — each waiter opens its own stream independently in
        // FetchBlobAsync, so the single shared result never carries a shared stream.
        return new OciBlobFetchMetadata(blobKey, mediaType);
    }

    // Decides whether a bare hit on the shared content-addressed blob store may be served to
    // orgId. The store is content-addressed with no org segment, so in the default
    // single-store deployment (cache == registry) one tenant's bytes — private uploads AND
    // proxy-cached layers pulled through an authenticated upstream — resolve under the same key
    // as anyone else's; a raw store hit is never proof of authorization on its own. Entitlement
    // holds only when the caller's own org already has an oci_blobs row for the digest: its own
    // upload, or a proxy fetch it already performed (and so already authenticated) itself.
    //
    // Deliberately no cross-org exception for proxy-origin rows: a repository name is
    // caller-supplied and an upstream with an empty prefix matches every repository, so "the
    // caller has some configured upstream" proves nothing about whether that upstream's
    // credentials can actually reach this digest — it lets a caller who guesses a digest (they
    // leak routinely via SBOMs, CI logs, pinned references) read another org's private layer
    // without ever presenting that org's upstream credentials. A non-owning org falls through to
    // its own real, org-scoped upstream fetch below, which re-authenticates and re-verifies the
    // digest — the only trustworthy proof the caller is entitled to the bytes. The single-flight
    // dedup on that path is keyed on (org, blob key), so a caller racing another org's in-flight
    // pull of the same digest still makes its own authenticated request rather than awaiting,
    // and inheriting the result of, a fetch made with another tenant's credentials.
    private async Task<bool> CanServeSharedBlobAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped — the same predicate the blob HEAD path
        // (TryGetCachedBlobMetadataByDigestAsync) answers existence with, so GET and HEAD cannot
        // disagree about which org may see a digest.
        int owned = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(1) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        return owned > 0;
    }

    // Returns true when a NEW row was inserted (ON CONFLICT DO NOTHING → 0 rows on an existing
    // row). Callers use the flag to run the config-blob license reverse-lookup ONLY on a genuine
    // first insert, so a warm blob GET — which runs this on every request — pays nothing extra.
    private async Task<bool> EnsureBlobDbRowAsync(
        string orgId, string digest, string mediaType, long sizeBytes, string blobKey, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        int rows = await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy', @now)
            ON CONFLICT(digest, org_id) DO NOTHING
            """,
            new { digest, orgId, mediaType, sizeBytes, blobKey, now = UtcTimestamp.Now(_time) });
        return rows > 0;
    }

    // In-flight identity for a blob fetch. The org is part of the identity because the fetch it
    // guards runs with one org's upstream and credentials, and its result may only be handed to
    // callers of that org.
    private readonly record struct OciBlobInflightKey(string OrgId, string BlobKey);
}
