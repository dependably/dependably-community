using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

// Manifest read (local cache + upstream proxy), referrers (OCI 1.1), delete, and push handlers.
// Split out of OciController.cs (partial class) to keep any single file under the 1000-line cap;
// see that file for the dispatchers, shared auth helpers, and the OciControllerServices bundle.
public sealed partial class OciController
{
    private async Task<IActionResult> ServeManifestAsync(
        string name, string reference, bool headOnly, CancellationToken ct)
    {
        // allowPushProbe: docker/BuildKit resolve a manifest reference (HEAD, falling back to
        // GET on registries that don't answer HEAD reliably) both to decide whether a tag
        // already points at the digest being pushed and to read back a just-pushed manifest —
        // a normal part of the push protocol that a publish-only token must still be able to do.
        var auth = await AuthorizePullAsync(ct, allowPushProbe: true);
        if (auth.Unauthorized is not null)
        {
            return auth.Unauthorized;
        }

        var coords = OciCoordinatesParser.Parse(name, reference);
        if (coords is null)
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID,
                "Invalid repository or reference.");
        }

        string orgId = CurrentTenantId();

        // Local cache first; on a miss (unknown reference or evicted blob), fall through
        // to the upstream proxy.
        var local = await TryServeLocalManifestAsync(orgId, name, coords, headOnly, auth.Token, ct);
        return local ?? await ServeUpstreamManifestAsync(orgId, name, reference, coords.IsDigest, headOnly, auth.Token, ct);
    }

    /// <summary>
    /// Serves a manifest from the local DB / blob store. Returns <c>null</c> when the
    /// manifest is not available locally (unresolved tag, no blob record, or the blob has
    /// been evicted from the store), signalling the caller to fall through to upstream.
    /// </summary>
    // The OCI plane now carries license fact columns (config_digest / license_spdx /
    // license_checked_at on oci_blobs), and this serve path enforces the license arm only. When
    // the manifest row has a captured SPDX expression and the tenant's license_enforcement_mode is
    // 'block', the download is denied via BlockGateService's license arm (same activity row, meter,
    // and quarantine review as every other license block). Both serve paths evaluate the arm: the
    // upstream path stamps the image from its config label and then evaluates the stamp it just
    // wrote, so a manifest reaching this org for the first time — including a mutable tag that has
    // repointed to a digest never held here — is enforced on that same request rather than on the
    // next one.
    //
    // The remaining supply-chain arms (deprecated / revoked / vuln-score / provenance /
    // manual-block / install-script) stay deliberately excluded: OCI images are not run through the
    // OSV scan or the manual-block endpoint that populate the cache_artifact fact columns the other
    // arms read, and the OCI plane carries none of them. Layer-blob GETs are not gated — the
    // manifest is the pull entry point, so blocking it stops the pull. Access is otherwise governed
    // by the auth / anonymous-pull gate above.
    private async Task<IActionResult?> TryServeLocalManifestAsync(
        string orgId, string name, OciCoordinates coords, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        // Resolve tag → digest first (returns the reference unchanged if it's already a digest).
        var localRef = await ResolveDigestAsync(orgId, coords, ct);
        if (localRef.Digest is not { } resolved)
        {
            return null;
        }

        // xtenant: (digest, org_id) PK is tenant-scoped.
        await using var conn = await _svc.Db.OpenAsync(ct);
        // Dapper binds @digest/@orgId as parameters; SQL string is a constant literal.
        var (MediaType, SizeBytes, BlobKey, Origin, LicenseSpdx) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin, string? LicenseSpdx)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin, license_spdx AS LicenseSpdx " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest = resolved, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        // A proxied tag is a mutable reference: the upstream may have repointed it since it was
        // cached, so it may be served from here only while its oci_tags entry is inside
        // Oci:ManifestTagTtl. Past that, report a miss and let the caller revalidate upstream.
        //
        // This check has to live here rather than in OciUpstreamResolver alone. This method runs
        // first and answers from local state, so the resolver's own TTL check is reached only
        // once this one has already declined — without this line a cached tag is pinned to its
        // first-pulled digest for the life of the blob and the TTL never runs at all.
        //
        // Which tags it applies to is the tag's own stamp, not the blob row's origin — see
        // IsTagDueForUpstreamRevalidation. A pushed manifest keeps origin = 'proxy' whenever the
        // same bytes were proxied first, so origin would send a hosted tag upstream.
        if (!coords.IsDigest && _svc.Upstream.IsTagDueForUpstreamRevalidation(localRef.LastRevalidated))
        {
            return null;
        }

        // License-arm enforcement: when this manifest carries a captured SPDX expression and the
        // tenant enforces licenses in 'block' mode, deny both GET and HEAD before serving.
        if (await EvaluateLicenseBlockAsync(orgId, $"pkg:oci/{name}@{resolved}", LicenseSpdx, token, ct) is { } blocked)
        {
            return blocked;
        }

        if (headOnly)
        {
            // HEAD: confirm the blob is still present without opening a stream.
            bool exists = await BlobTierFor(Origin).ExistsAsync(BlobKey, ct);
            if (!exists)
            {
                // Blob evicted — fall through to upstream.
                return null;
            }

            SetManifestHeaders(resolved, SizeBytes, MediaType, "HIT", coords.IsDigest);
            return Ok();
        }

        var stream = await BlobTierFor(Origin).GetAsync(BlobKey, ct);
        if (stream is null)
        {
            // Blob evicted from store — fall through to upstream.
            return null;
        }

        SetManifestHeaders(resolved, SizeBytes, MediaType, "HIT", coords.IsDigest);

        // "download" is the canonical fetch event across ecosystems (npm/PyPI/NuGet)
        // and the only one the Audit page filter knows; the PURL digest distinguishes
        // a manifest pull from a layer pull, so a dedicated event name isn't needed.
        //
        // OCI is deliberately omitted from the package_versions.download_count counter:
        // one `docker pull` fans out into a manifest GET plus N layer-blob GETs (which
        // would multi-count a single pull), and the bare digest PURL logged here doesn't
        // match the version row's canonical PURL (which carries ?repository_url=…&tag=…).
        // OCI download volume is still tracked org-wide via these activity rows.
        await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{resolved}", "download",
            actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(stream, MediaType!);
    }

    /// <summary>
    /// Reads the SPDX expression stamped on a manifest's <c>oci_blobs</c> row, or null when the
    /// row carries none (no label on the image, or the config blob had not landed when the
    /// recorder ran). Null is the empty-licence case OCI passes through, not a block.
    /// </summary>
    private async Task<string?> ReadStampedLicenseAsync(string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT license_spdx FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
    }

    /// <summary>
    /// Fetches a manifest through the upstream proxy on a local cache miss; the resolver
    /// caches it so subsequent requests are served locally. On HEAD, only the manifest
    /// metadata (digest, size, media type) is fetched — no body is downloaded.
    /// </summary>
    private async Task<IActionResult> ServeUpstreamManifestAsync(
        string orgId, string name, string reference, bool isDigest, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        if (headOnly)
        {
            // HEAD: fetch only response headers from upstream to avoid downloading the full
            // manifest body. The resolver issues a HEAD request; the response headers carry
            // Docker-Content-Digest and Content-Length which are sufficient to satisfy the
            // OCI spec HEAD contract.
            OciManifestMetadata? meta;
            try
            {
                meta = await _svc.Upstream.FetchManifestMetadataAsync(orgId, name, reference, isDigest, ct);
            }
            catch (AirGappedException)
            {
                return AirGappedManifestMiss(name, reference);
            }
            catch (Exception ex) when (IsUpstreamFailure(ex, ct))
            {
                return await ServeStaleOrUpstreamErrorAsync(orgId, name, reference, isDigest, headOnly: true, token, ex, ct);
            }

            if (meta is null)
            {
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                    $"Manifest unknown: {reference}");
            }

            // HEAD answers the licence arm exactly as GET does. A HEAD that revalidates a stale
            // tag resolves the same repointed digest a GET would, so letting it answer 200 while
            // GET answers 403 would tell a client probing before a pull that a blocked image is
            // available. Only a digest already stamped here can be judged — an upstream HEAD
            // downloads no config blob — and an unstamped digest is the empty-licence case OCI
            // passes through, the same answer it gets on the GET path.
            if (await EvaluateLicenseBlockAsync(
                    orgId, $"pkg:oci/{name}@{meta.Digest}",
                    await ReadStampedLicenseAsync(orgId, meta.Digest, ct), token, ct) is { } headBlocked)
            {
                return headBlocked;
            }

            SetManifestHeaders(meta.Digest, meta.SizeBytes, meta.MediaType, "MISS", isDigest);
            return Ok();
        }

        OciManifestResult? upstreamResult;
        try
        {
            upstreamResult = await _svc.Upstream.FetchManifestAsync(orgId, name, reference, isDigest, ct);
        }
        catch (AirGappedException)
        {
            return AirGappedManifestMiss(name, reference);
        }
        catch (Exception ex) when (IsUpstreamFailure(ex, ct))
        {
            return await ServeStaleOrUpstreamErrorAsync(orgId, name, reference, isDigest, headOnly: false, token, ex, ct);
        }

        if (upstreamResult is null)
        {
            return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                $"Manifest unknown: {reference}");
        }

        // The fetch above catalogued the manifest and stamped its license facts
        // (FetchAndCacheManifestAsync → OciImageLicenseRecorder.RecordManifestAsync), so the
        // licence arm can be answered for these bytes now rather than on the next request.
        //
        // Evaluating it here is what keeps a mutable tag from buying a free pull on every
        // repoint: a repointed tag resolves to a digest this org has never held, which is a
        // guaranteed miss, and deferring the decision would serve the new image unenforced each
        // time it changed. A label-less image still stamps NULL and still passes — OCI keeps the
        // empty-licence pass-through, so this denies only an expression the tenant blocks.
        string? upstreamLicense = await ReadStampedLicenseAsync(orgId, upstreamResult.Digest, ct);
        if (await EvaluateLicenseBlockAsync(
                orgId, $"pkg:oci/{name}@{upstreamResult.Digest}", upstreamLicense, token, ct) is { } blocked)
        {
            await upstreamResult.Content.DisposeAsync();
            return blocked;
        }

        SetManifestHeaders(upstreamResult.Digest, upstreamResult.SizeBytes, upstreamResult.MediaType, "MISS", isDigest);
        await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{upstreamResult.Digest}", "download",
            actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(upstreamResult.Content, upstreamResult.MediaType);
    }

    /// <summary>
    /// The answer for a manifest that is not held locally on an air-gapped instance.
    ///
    /// <para>
    /// Without this, <see cref="AirGappedException"/> escapes to <c>AirGappedExceptionMiddleware</c>
    /// and the client is told 503 — "temporarily unavailable, try again". On an air-gapped instance
    /// that is never true: there is no upstream by policy, so the manifest will not appear however
    /// long the client waits. An OCI client reading 503 retries; reading 404 it reports the image as
    /// absent, which is both correct and the signal the operator needs ("this image was never
    /// mirrored"). The Distribution Spec has exactly one status for "this registry does not have
    /// that", and air-gap does not make it a different question.
    /// </para>
    ///
    /// <para>
    /// The message names air-gap so the 404 is still diagnosable — the operator learns why the
    /// registry could not go and look, without the status lying to the client about it.
    /// </para>
    /// </summary>
    private static ObjectResult AirGappedManifestMiss(string name, string reference) =>
        OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
            $"Manifest unknown: {reference}. This instance is air-gapped, so {name} was not "
            + "fetched from an upstream registry; only locally held images are available.");

    /// <summary>
    /// The answer when the upstream failed while a tag needed revalidation: the last accepted
    /// digest, served for as long as the bounded stale grace allows, then 502.
    ///
    /// <para>
    /// The bound is what makes serving stale safe: without it, an upstream outage would
    /// silently extend the TTL to forever. The grace window is anchored at the moment the entry
    /// became stale (<c>last_revalidated + ManifestTagTtl</c>) and a failed revalidation never
    /// refreshes <c>last_revalidated</c>, so repeated failures cannot slide the deadline — see
    /// <see cref="OciUpstreamResolver.IsWithinStaleGrace"/>. Digest references never serve
    /// stale: they are content-addressed, so there is no "previously accepted" mapping to fall
    /// back to — a digest miss with a dead upstream is simply unreachable content.
    /// </para>
    /// </summary>
#pragma warning disable S107 // Threads the request coordinates plus the failure through to the stale decision
    private async Task<IActionResult> ServeStaleOrUpstreamErrorAsync(
        string orgId, string name, string reference, bool isDigest, bool headOnly,
        TokenRecord? token, Exception ex, CancellationToken ct)
#pragma warning restore S107
    {
        if (!isDigest)
        {
            var stale = await TryServeStaleTagManifestAsync(orgId, name, reference, headOnly, token, ct);
            if (stale is not null)
            {
                _logger.LogWarning(
                    "OCI upstream unavailable while revalidating {Repository}:{Reference} ({ExceptionType}); "
                    + "served last accepted digest within Oci:ManifestTagStaleGrace.",
                    name, reference, ex.GetType().Name);
                return stale;
            }
        }

        return UpstreamUnreachable(ex, name, reference);
    }

    /// <summary>
    /// Serves the tag's last accepted digest from local state despite its TTL having expired,
    /// or returns null when stale serving is not possible: no accepted mapping, grace window
    /// exhausted, or the manifest blob evicted. The licence arm still runs — an image the
    /// policy blocks does not become servable by being stale — and every stale serve is
    /// audited (the download activity row carries a stale-serve detail) and marked
    /// <c>X-Cache: STALE</c>, an additive header value alongside the existing HIT/MISS.
    /// </summary>
    private async Task<IActionResult?> TryServeStaleTagManifestAsync(
        string orgId, string name, string tag, bool headOnly, TokenRecord? token, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var (Digest, LastRevalidated) = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = name, tag });

        // A NULL stamp is a hosted tag (already served locally, never reaches here) or a row
        // with no revalidation evidence — neither has a grace window to measure from.
        if (Digest is null || LastRevalidated is null || !_svc.Upstream.IsWithinStaleGrace(LastRevalidated))
        {
            return null;
        }

        // xtenant: (digest, org_id) PK is tenant-scoped.
        var (MediaType, SizeBytes, BlobKey, Origin, LicenseSpdx) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey, string? Origin, string? LicenseSpdx)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey, origin AS Origin, license_spdx AS LicenseSpdx " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest = Digest, orgId });
        if (BlobKey is null)
        {
            return null;
        }

        if (await EvaluateLicenseBlockAsync(orgId, $"pkg:oci/{name}@{Digest}", LicenseSpdx, token, ct) is { } blocked)
        {
            return blocked;
        }

        if (headOnly)
        {
            if (!await BlobTierFor(Origin).ExistsAsync(BlobKey, ct))
            {
                return null;
            }

            SetManifestHeaders(Digest, SizeBytes, MediaType, "STALE", isDigest: false);
            return Ok();
        }

        var stream = await BlobTierFor(Origin).GetAsync(BlobKey, ct);
        if (stream is null)
        {
            return null;
        }

        SetManifestHeaders(Digest, SizeBytes, MediaType, "STALE", isDigest: false);
        await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{Digest}", "download",
            actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel,
            detail: "stale serve: upstream unavailable during tag revalidation; last accepted digest served within Oci:ManifestTagStaleGrace",
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return File(stream, MediaType!);
    }

    /// <summary>
    /// Sets the manifest response headers shared by the local-cache and upstream paths.
    /// Digest-addressed manifests are content-addressed and immutable; tag-addressed
    /// manifests may be updated, so they get a short TTL only.
    /// </summary>
    private void SetManifestHeaders(string digest, long sizeBytes, string? mediaType, string cacheStatus, bool isDigest)
    {
        Response.Headers["Docker-Content-Digest"] = digest;
        Response.Headers["Content-Length"] = sizeBytes.ToString();
        Response.Headers["X-Cache"] = cacheStatus;
        Response.ContentType = mediaType;
        if (isDigest)
        {
            Response.Headers.ETag = $"\"{digest}\"";
            Response.Headers.CacheControl = "private, max-age=31536000, immutable";
        }
        else
        {
            Response.Headers.CacheControl = "private, max-age=60";
        }
    }


    // OCI image index media type used for referrers API responses (OCI 1.1).
    private const string OciImageIndexMediaType = "application/vnd.oci.image.index.v1+json";

    /// <summary>
    /// GET /v2/{name}/referrers/{digest} — OCI 1.1 Referrers API.
    ///
    /// Returns an OCI image index listing all manifests in this org's repository whose
    /// subject.digest matches the requested digest. Supports optional artifactType filter
    /// via the ?artifactType= query parameter.
    ///
    /// Implementation scans stored manifest blobs for this repository and parses each for
    /// a subject field — acceptable at community scale where repository sizes are bounded.
    /// The scan is capped at 10,000 manifests to bound parse time on large repos.
    /// </summary>
    private async Task<IActionResult> ListReferrersAsync(string name, string digest, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null)
        {
            return auth.Unauthorized;
        }

        if (!OciCoordinatesParser.IsValidRepositoryName(name))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");
        }

        if (!OciCoordinatesParser.IsValidDigest(digest))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.DIGEST_INVALID, "Invalid digest format.");
        }

        string? artifactTypeFilter = Request.Query["artifactType"].FirstOrDefault();
        string orgId = CurrentTenantId();

        // Fetch all manifest digests for this repository from the org's oci_tags table to
        // identify candidates, then scan the manifest blobs for subject.digest matches.
        // xtenant: org_id filters ensure only this tenant's manifests are examined.
        await using var conn = await _svc.Db.OpenAsync(ct);
        // Collect distinct manifest digests associated with this repository (via tags).
        // Cap at OciReferrersScanCap to bound scan time; repositories with more manifests than
        // this cap return an incomplete referrers list, which is valid per the OCI 1.1 spec
        // (clients follow pagination, but here we return a single page with what we have).
        // rawsql: ORDER BY + LIMIT on a constant; not user input.
        var candidateDigests = (await conn.QueryAsync<string>(
            "SELECT DISTINCT digest FROM oci_tags WHERE org_id = @orgId AND repository = @repo LIMIT " + (OciReferrersScanCap + 1),
            new { orgId, repo = name })).ToList();
        if (candidateDigests.Count > OciReferrersScanCap)
        {
            candidateDigests.RemoveAt(candidateDigests.Count - 1);
            // name is a repository route segment; Serilog structured logging sanitises it.
            _logger.LogWarning(
                "OCI referrers scan for {Repository} hit the 10,000-manifest cap; response may be incomplete.",
                name);
        }

        var descriptors = await ScanManifestsForReferrersAsync(
            orgId, conn, candidateDigests, digest, artifactTypeFilter, ct);

        if (!string.IsNullOrEmpty(artifactTypeFilter))
        {
            Response.Headers["OCI-Filters-Applied"] = "artifactType";
        }

        Response.ContentType = OciImageIndexMediaType;
        var index = new
        {
            schemaVersion = 2,
            mediaType = OciImageIndexMediaType,
            manifests = descriptors.Select(d => new
            {
                mediaType = d.MediaType,
                digest = d.Digest,
                size = d.SizeBytes,
                artifactType = d.ArtifactType,
                annotations = d.Annotations,
            }).ToArray(),
        };
        return new JsonResult(index);
    }

    // Scans candidate manifest digests for entries whose subject.digest matches the target
    // digest, applying the optional artifactType filter. Returns the matching referrer descriptors.
    private async Task<List<OciReferrerDescriptor>> ScanManifestsForReferrersAsync(
        string orgId, System.Data.Common.DbConnection conn, List<string> candidateDigests,
        string targetDigest, string? artifactTypeFilter, CancellationToken ct)
    {
        var descriptors = new List<OciReferrerDescriptor>();
        foreach (string candidateDigest in candidateDigests)
        {
            // xtenant: (digest, org_id) PK is tenant-scoped.
            var (MediaType, SizeBytes, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
                "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
                "FROM oci_blobs WHERE digest = @d AND org_id = @orgId",
                new { d = candidateDigest, orgId });

            if (BlobKey is null)
            {
                continue;
            }

            // Read and parse the manifest blob to check for a subject.digest match.
            var tier = BlobTierFor("uploaded"); // referrers only apply to locally pushed manifests
            var stream = await tier.GetAsync(BlobKey, ct);
            if (stream is null)
            {
                continue;
            }

            byte[] bytes;
            await using (stream)
            {
                using var ms = new MemoryStream();
                await stream.CopyToAsync(ms, ct);
                bytes = ms.ToArray();
            }

            var referrer = OciReferrerParser.TryParseReferrer(
                bytes, candidateDigest, MediaType ?? OciImageIndexMediaType, SizeBytes, targetDigest);
            if (referrer is null)
            {
                continue;
            }

            if (!string.IsNullOrEmpty(artifactTypeFilter) &&
                !string.Equals(referrer.ArtifactType, artifactTypeFilter, StringComparison.Ordinal))
            {
                continue;
            }

            descriptors.Add(referrer);
        }
        return descriptors;
    }

    /// <summary>
    /// DELETE /v2/{name}/manifests/{reference} — protocol-level manifest delete.
    ///
    /// Digest form: removes the manifest oci_blobs record and all oci_tags rows pointing
    /// to that digest within this org, then deletes the blob from the Registry tier only
    /// for uploaded manifests. The lookup matches the digest regardless of origin (a pushed
    /// manifest can carry origin='proxy' through content-addressed dedup), so digest-
    /// addressed delete works for any locally catalogued manifest. Shared cache blobs are
    /// never deleted (other tenants may reference the same content-addressed key; GC is the
    /// right mechanism for unreferenced cache blobs).
    ///
    /// Tag form: removes only the tag record (untag only — spec-compliant behaviour for
    /// tag deletion). The manifest blob and its digest-addressed record remain intact.
    ///
    /// Requires yank:oci capability — the same gate as the management-API delete.
    /// </summary>
    private async Task<IActionResult> HandleManifestDeleteAsync(string name, string reference, CancellationToken ct)
    {
        var (token, error) = await AuthorizeYankAsync(ct);
        if (error is not null)
        {
            return error;
        }

        var coords = OciCoordinatesParser.Parse(name, reference);
        if (coords is null)
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository or reference.");
        }

        string orgId = CurrentTenantId();
        await using var conn = await _svc.Db.OpenAsync(ct);

        if (coords.IsDigest)
        {
            // Digest delete: find the blob record for this org regardless of origin, remove
            // all tags pointing to it, then remove the blob record. Origin is not filtered:
            // OCI blobs are content-addressed, so a pushed manifest whose digest was first
            // seen via the proxy keeps origin='proxy' (the upsert never rewrites origin) —
            // filtering on origin='uploaded' here made delete-by-digest 404 for those
            // round-trippable manifests. Physical deletion is still gated on origin below.
            // xtenant: (digest, org_id) PK ensures this is scoped to the caller's org.
            var (blobKey, origin) = await conn.QuerySingleOrDefaultAsync<(string? BlobKey, string? Origin)>(
                "SELECT blob_key AS BlobKey, origin AS Origin FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
                new { digest = reference, orgId });

            if (blobKey is null)
            {
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                    $"Manifest unknown: {reference}");
            }

            // Remove all tags in this org's repository pointing to this digest.
            // xtenant: org_id filter ensures cross-org isolation.
            await conn.ExecuteAsync(
                "DELETE FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND digest = @digest",
                new { orgId, repo = name, digest = reference });

            // Remove the manifest blob record for this org.
            // xtenant: (digest, org_id) PK.
            await conn.ExecuteAsync(
                "DELETE FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
                new { digest = reference, orgId });

            // A manifest casts one of two catalogue shadows depending on how it entered this org's
            // repository: a tag push lands a package_versions row (OciUploadService's
            // RecordCatalogVersionAsync); a proxy pull lands a cache_artifact/tenant_artifact_access
            // pair (OciUpstreamResolver's). oci_blobs.origin never flips once set, so it cannot
            // reliably tell us which shadow (if either) exists for this digest — both cleanups run
            // unconditionally and are no-ops when their shadow was never cast. Leaving either behind
            // is the "permanent UI zombie" this delete exists to close: ListServeableVersionsAsync
            // and artifact_inventory read both catalogues, so an un-deleted shadow keeps surfacing
            // the digest as a version forever, since OCI carries no eviction sweep to reclaim it.
            //
            // Order matters for the parent packages row's GC guard
            // (PackageRepository.DeletePackageIfEmptyAsync), which refuses to delete while either a
            // package_versions row or a tenant_artifact_access row still references it: the
            // tenant_artifact_access drop runs first, then the package_versions drop, so by the time
            // the GC check runs neither shadow can still be holding the parent row open.
            var pkg = await _svc.Packages.GetByPurlNameAsync(orgId, "oci", name, ct);

            // Drops this org's visibility into the shared cache_artifact row, if a proxy pull ever
            // cast one for this digest; the shared row (and the manifest blob it references) is left
            // alone, matching the no-reclaim policy every other OCI cache-plane path follows.
            await _svc.TenantArtifactAccess.RemoveAccessForCoordinateAsync(orgId, "oci", name, reference, ct);

            if (pkg is not null)
            {
                var ver = await _svc.Packages.GetVersionAsync(pkg.Id, reference, ct);
                if (ver is not null)
                {
                    await _svc.Packages.DeleteVersionAsync(ver.Id, ct);
                }

                // GC the parent row whenever this delete leaves it with no remaining shadow on
                // either catalogue — a proxy-only manifest never had a package_versions row to
                // delete above, so this check must run regardless of whether the branch above did.
                await _svc.Packages.DeletePackageIfEmptyAsync(pkg.Id, ct);
            }

            // Physical delete applies only to Registry-tier (uploaded) blobs. Proxy blobs
            // live in the Cache tier and are content-addressed, shared across tenants — blob
            // GC reclaims unreferenced cache entries, so we never delete them here.
            if (origin == "uploaded")
            {
                // Refcount-guarded: two orgs pushing the same digest share one physical blob, so
                // the file goes only when this org's row was the last reference. The count and the
                // delete are serialised against a concurrent finalize of the same key inside the
                // deleter — the management-API yank takes the same path.
                await _svc.OrphanBlobs.DeleteIfUnreferencedAsync(blobKey, ct);
            }

            await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{reference}", "delete",
                actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

            return NoContent();
        }
        else
        {
            // Tag delete: remove only the tag record. Manifest blob and its digest record
            // remain intact so digest-addressed pulls still work (spec: tag deletion
            // removes the name→digest mapping, not the manifest content).
            // xtenant: (org_id, repository, tag) PK.
            int deleted = await conn.ExecuteAsync(
                "DELETE FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
                new { orgId, repo = name, tag = reference });

            if (deleted == 0)
            {
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_UNKNOWN,
                    $"Tag unknown: {reference}");
            }

            await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}:{reference}", "delete",
                actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

            return NoContent();
        }
    }

    private async Task<IActionResult> HandleManifestPutAsync(string name, string reference, CancellationToken ct)
    {
        var (Token, Error) = await AuthorizePushAsync(ct);
        if (Error is not null)
        {
            return Error;
        }

        var coords = OciCoordinatesParser.Parse(name, reference);
        if (coords is null)
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository or reference.");
        }

        string? mediaType = NormalizeManifestMediaType(Request.ContentType);
        if (!OciManifestParser.IsAcceptedMediaType(mediaType))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.MANIFEST_INVALID,
                "Unsupported or missing manifest media type.");
        }

        string orgId = CurrentTenantId();

        // Name-level publish authorization. Keys on the authenticated token principal (never the
        // request path), so a token holding only publish:oci cannot seize a repository a different
        // principal already owns. Enforced at manifest PUT — the point a tag/name is published.
        // No-op unless PUBLISH_NAME_BINDING=on.
        var namePrincipal = Dependably.Infrastructure.NamePrincipal.FromToken(Token);
        var nameError = await AuthorizeManifestNameAsync(orgId, name, namePrincipal, ct);
        if (nameError is not null)
        {
            return nameError;
        }

        var (bytes, bufferError) = await BufferManifestBodyAsync(ct);
        if (bufferError is not null)
        {
            return bufferError;
        }

        // Defence in depth: a tenant OCI limit tighter than 4 MiB still rejects here.
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        long limit = await _svc.Orgs.GetUploadLimitAsync(settings, "oci", ct);
        if (bytes!.Length > limit)
        {
            return OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.SIZE_INVALID,
                $"Manifest exceeds the oci upload limit of {limit} bytes.");
        }

        var result = await _svc.Uploads.StoreManifestAsync(orgId, name, reference, bytes, mediaType!, ct);
        return await RespondToManifestPutAsync(orgId, name, Token, namePrincipal, result, ct);
    }

    // Strips any trailing ";charset=..." (or similar) parameter suffix from a Content-Type value.
    private static string? NormalizeManifestMediaType(string? contentType)
    {
        if (contentType is null)
        {
            return null;
        }

        int semi = contentType.IndexOf(';');
        return semi >= 0 ? contentType[..semi].Trim() : contentType;
    }

    private async Task<IActionResult?> AuthorizeManifestNameAsync(
        string orgId, string name, Dependably.Infrastructure.NamePrincipal? namePrincipal, CancellationToken ct) =>
        _svc.NameBinding is { } nameGate
            && !await nameGate.IsPublishAuthorizedAsync(orgId, "oci", name, namePrincipal, ct)
            ? OciError(StatusCodes.Status403Forbidden, OciErrorCode.DENIED,
                $"Publishing to '{name}' is not permitted: the repository is owned by a different " +
                "principal in this org and you hold no publish grant for it.")
            : null;

    /// <summary>
    /// Caps the manifest body BEFORE buffering it. Wrapping <c>Request.Body</c> in a
    /// <see cref="LimitedReadStream"/> means a hostile chunked (or over-large declared) body is
    /// aborted at 4 MiB instead of being copied into a growing <see cref="MemoryStream"/> that
    /// could reach ~2 GiB (plus the <c>ToArray</c> copy) before any size check ran. Pre-sizes the
    /// buffer from Content-Length when it is present and within the cap so a well-formed manifest
    /// allocates exactly once.
    /// </summary>
    private async Task<(byte[]? Bytes, IActionResult? Error)> BufferManifestBodyAsync(CancellationToken ct)
    {
        long? declared = Request.ContentLength;
        int initialCapacity = declared is > 0 and <= OciManifestMaxBytes ? (int)declared.Value : 0;
        try
        {
            await using var ms = initialCapacity > 0 ? new MemoryStream(initialCapacity) : new MemoryStream();
            await using var limited = new LimitedReadStream(Request.Body, OciManifestMaxBytes, "OCI manifest body");
            await limited.CopyToAsync(ms, ct);
            return (ms.ToArray(), null);
        }
        catch (InvalidDataException)
        {
            return (null, OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.MANIFEST_INVALID,
                $"Manifest exceeds the {OciManifestMaxBytes}-byte limit."));
        }
    }

    private async Task<IActionResult> RespondToManifestPutAsync(
        string orgId, string name, TokenRecord? token, Dependably.Infrastructure.NamePrincipal? namePrincipal,
        OciManifestStoreResult result, CancellationToken ct)
    {
        switch (result.Status)
        {
            case OciManifestStatus.Ok:
                // Record first-publisher ownership now that the manifest is durably stored.
                if (_svc.NameBinding is { } ownerGate)
                {
                    await ownerGate.RecordOwnershipAsync(orgId, "oci", name, namePrincipal, ct);
                }
                await _svc.Audit.LogActivityAsync(orgId, "oci", $"pkg:oci/{name}@{result.Digest}", "push",
                    actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
                Response.Headers.Location = $"/v2/{name}/manifests/{result.Digest}";
                Response.Headers["Docker-Content-Digest"] = result.Digest!;
                return StatusCode(StatusCodes.Status201Created);
            case OciManifestStatus.MissingBlob:
                return OciError(StatusCodes.Status404NotFound, OciErrorCode.MANIFEST_BLOB_UNKNOWN,
                    $"Referenced blob not present: {result.MissingDigest}");
            case OciManifestStatus.QuotaExceeded:
                return OciError(StatusCodes.Status413RequestEntityTooLarge, OciErrorCode.SIZE_INVALID,
                    "Tenant storage quota would be exceeded by this manifest push.");
            default:
                return OciError(StatusCodes.Status400BadRequest, OciErrorCode.MANIFEST_INVALID,
                    "Manifest is not valid JSON or has no recognizable structure.");
        }
    }
}
