using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Maven 2/3 repository surface — local serving and upstream proxy. Implements the file-tree
/// contract Gradle / Maven clients expect — every artifact lives at
/// <c>/{groupId-as-path}/{artifactId}/{version}/{artifactId}-{version}[-{classifier}].{extension}</c>
/// — plus the <c>maven-metadata.xml</c> documents that drive version resolution and
/// SNAPSHOT lookup.
///
/// Proxy: on a local cache miss the controller falls through to the configured upstream
/// (default Maven Central). Locally published artifacts always win over upstream — dependency
/// confusion protection per spec §11. GroupId prefixes reserved in the shared
/// <c>reserved_namespace</c> table (ecosystem 'maven') never consult upstream.
///
/// Maven differs from npm/PyPI/NuGet in that a single coordinate can carry multiple files
/// (JAR + POM + sources JAR + javadoc + checksum sidecars). The <c>package_versions</c>
/// row stays one-per-version; <c>maven_version_files</c> tracks the per-file blob mapping
/// so a GET for any filename suffix resolves to the right blob.
/// </summary>
// Maven sidecar checksums require MD5 and SHA-1 for client compatibility — not used for
// security decisions, just to match what mvn / gradle expect.
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "SCS0006",
    Justification = "MD5/SHA-1 used only for Maven sidecar compatibility, not authentication.")]
[ApiController]
public sealed class MavenController : OrgScopedControllerBase
{
    private readonly MavenControllerServices _svc;

    public MavenController(MavenControllerServices svc) => _svc = svc;

    /// <summary>GET /maven/{**path} — artifact, sidecar, or metadata download.</summary>
    [HttpGet("/maven/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Download(string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return NotFound();
        }

        var coords = MavenPathParser.Parse(path);
        if (coords is null)
        {
            return BadRequest("Invalid Maven path.");
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);

        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        return coords.IsMetadata ? await ServeMetadataAsync(orgId, coords, ct) : await ServeArtifactAsync(orgId, coords, settings, token, ct);
    }

    /// <summary>HEAD /maven/{**path} — existence check.</summary>
    [HttpHead("/maven/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Head(string path, CancellationToken ct)
    {
        // Reuse the GET implementation, then drop the body. Stays consistent with the
        // existing-not-existing answer the client cares about; the small extra work to
        // compute checksum sidecars on-the-fly is fine on the HEAD path.
        var result = await Download(path, ct);
        if (result is FileContentResult fc)
        {
            return new ContentResult { StatusCode = 200, ContentType = fc.ContentType };
        }

        if (result is FileStreamResult fs)
        {
            fs.FileStream.Dispose();
            return new ContentResult { StatusCode = 200, ContentType = fs.ContentType };
        }
        return result;
    }

    /// <summary>PUT /maven/{**path} — publish an artifact, sidecar, or metadata file.</summary>
    [HttpPut("/maven/{**path}")]
    [Authorize(AuthenticationSchemes = "Bearer," + Dependably.Security.TokenAuthenticationDefaults.Scheme)]
    [RequireCapability(Capabilities.PublishMaven)]
    [EnableRateLimiting("push")]
    [RequestSizeLimit(500 * 1024 * 1024)]
    public async Task<IActionResult> Publish(string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return BadRequest();
        }

        var coords = MavenPathParser.Parse(path);
        if (coords is null)
        {
            return BadRequest("Invalid Maven path.");
        }

        if (coords.Version is null && !coords.IsMetadata)
        {
            return BadRequest("Maven artifact publishes require a version segment.");
        }

        string orgId = CurrentTenantId();
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);
        if (token is null || token.OrgId != orgId)
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"dependably\"";
            return Unauthorized();
        }

        // Path-traversal / control-character defence: reject anything PathSafeValidator
        // wouldn't let into a blob key. Maven's slashed group form lands as path
        // segments so we validate each one separately.
        foreach (string seg in path.Split('/'))
        {
            var r = PathSafeValidator.Validate(seg, "path");
            if (!r.IsValid)
            {
                return BadRequest(r.Message);
            }
        }

        // Buffer the request body. Maven uploads are typically small — JARs a few MB,
        // POMs a few KB. The 500 MB ceiling above is the absolute cap.
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms, ct);
        byte[] bytes = ms.ToArray();

        // Per-tenant Maven cap → instance Maven cap → instance global cap → reject.
        long? sizeCap = await ResolveSizeCapAsync(orgId, ct);
        if (sizeCap is { } cap && bytes.LongLength > cap)
        {
            return StatusCode(413, $"Maven upload exceeds size limit ({cap} bytes).");
        }

        // Metadata uploads (maven-metadata.xml) are deploy-time bookkeeping the client
        // computes locally. We accept and discard — the metadata we serve is generated
        // server-side from package_versions / maven_version_files so trusting client
        // input here would let a misbehaving client poison the index for everyone.
        return coords.IsMetadata ? StatusCode(201) : await StoreFileAsync(orgId, coords!, bytes, token, ct);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task<IActionResult> ServeArtifactAsync(
        string orgId, MavenCoordinates coords, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        // Sidecar lookup: the controller resolves to the primary artifact's row in
        // maven_version_files; the sidecar's bytes are computed from the stored
        // checksum_* columns. This means we don't have to store sidecars as their own
        // blobs and the answer stays consistent even when the client uploaded only the
        // primary file.
        string primaryFilename = coords.IsChecksumSidecar
            ? MavenPathParser.PrimaryFilename(coords.Filename)
            : coords.Filename;

        await using var conn = await _svc.Db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<MavenFileRow>(
            """
            SELECT mvf.id AS Id, mvf.package_version_id AS PackageVersionId,
                   mvf.filename AS Filename,
                   mvf.extension AS Extension, mvf.blob_key AS BlobKey,
                   mvf.checksum_sha256 AS ChecksumSha256,
                   mvf.checksum_sha1 AS ChecksumSha1, mvf.checksum_md5 AS ChecksumMd5,
                   pv.purl AS Purl, pv.manual_block_state AS ManualBlockState,
                   pv.vuln_checked_at AS VulnCheckedAt, pv.published_at AS PublishedAt,
                   pv.deprecated AS Deprecated
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven'
              AND p.purl_name = @purlName
              AND pv.version = @version
              AND mvf.filename = @filename
            LIMIT 1
            """,
            new
            {
                orgId,
                purlName = coords.PackageName,
                version = coords.Version,
                filename = primaryFilename,
            });

        // ── Cache hit: serve from local blob store ─────────────────────────────
        if (row is not null)
        {
            // Vulnerability / manual-block gate runs before we serve cached bytes —
            // including the checksum sidecar, so a blocked artifact's hashes don't leak
            // either. Mirrors the inline gate PyPI/npm/NuGet run on their cache-hit paths.
            if (await _svc.BlockGate.EvaluateAsync(
                    new BlockGateRequest(orgId, "maven", row.Purl, row.PackageVersionId,
                        row.ManualBlockState, row.VulnCheckedAt,
                        token?.UserId, settings?.MaxOsvScoreTolerance ?? 10.0,
                        HttpContext.GetNormalizedRemoteIp(),
                        MinReleaseAgeHours: settings?.MinReleaseAgeHours,
                        PublishedAt: row.PublishedAt,
                        ActorKind: token?.ActorKind,
                        Deprecated: row.Deprecated,
                        BlockDeprecatedMode: settings?.BlockDeprecated,
                        BlockMaliciousMode: settings?.BlockMalicious,
                        BlockKevMode: settings?.BlockKev,
                        MaxEpssTolerance: settings?.MaxEpssTolerance), ct)
                == BlockDecision.Blocked)
            {
                return StatusCode(403);
            }

            Response.Headers["X-Cache"] = "HIT";

            return coords.IsChecksumSidecar
                ? await ServeChecksumSidecarAsync(coords, row, ct)
                : await ServePrimaryFromCacheAsync(orgId, coords, token?.UserId, row, ct);
        }

        // ── Cache miss: proxy upstream ──────────────────────────────────
        return await ProxyFetchAndCacheAsync(orgId, coords, settings, token, ct);
    }

    private async Task<IActionResult> ServeChecksumSidecarAsync(
        MavenCoordinates coords, MavenFileRow row, CancellationToken ct)
    {
        string? hex = coords.ChecksumAlgorithm switch
        {
            "sha512" => null, // not stored; computed on the fly below
            "sha256" => row.ChecksumSha256,
            "sha1" => row.ChecksumSha1,
            "md5" => row.ChecksumMd5,
            _ => null,
        };
        if (hex is null && coords.ChecksumAlgorithm is { } algo)
        {
            // Compute from the primary artifact's bytes — costs one blob read; cached
            // results would be nice but live in a follow-up if it shows up in profiles.
            var blob = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(row.BlobKey), ct);
            if (blob is null)
            {
                return NotFound();
            }

            hex = await ComputeChecksumAsync(blob, algo, ct);
        }

        return hex is null
            ? NotFound()
            : new ContentResult
            {
                Content = hex,
                ContentType = "text/plain",
                StatusCode = 200,
            };
    }

    private async Task<IActionResult> ServePrimaryFromCacheAsync(
        string orgId, MavenCoordinates coords, string? actorId, MavenFileRow row, CancellationToken ct)
    {
        var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(row.BlobKey), ct);
        if (stream is null)
        {
            return NotFound();
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version ?? "unknown");
        if (row.ChecksumSha256 is not null)
        {
            Response.Headers.ETag = $"\"sha256:{row.ChecksumSha256}\"";
            Response.Headers.CacheControl = coords.IsSnapshot
                ? "private, max-age=60"
                : "private, max-age=31536000, immutable";
        }
        await _svc.Audit.LogActivityAsync(
            orgId, "maven", purl,
            "download", actorId,
            sourceIp: HttpContext.GetNormalizedRemoteIp(),
            ct: ct);
        await _svc.Packages.IncrementDownloadCountByPurlAsync(purl, ct);

        return File(stream, ContentTypeFor(coords.Extension), coords.Filename);
    }

    /// <summary>
    /// Handles a Maven artifact cache miss by fetching from the org's configured upstream
    /// registries in priority order (first reachable wins); an empty list disables proxying.
    /// Dep-confusion protection: reserved groupId prefixes and
    /// SNAPSHOT versions never consult upstream.
    /// </summary>
    private async Task<IActionResult> ProxyFetchAndCacheAsync(
        string orgId, MavenCoordinates coords, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        // No upstream service registered — treat as local-only.
        if (_svc.Upstream is null)
        {
            return NotFound();
        }

        // Resolve the org's priority-ordered upstream registries. Empty ⇒ proxying disabled.
        var bases = await _svc.Registries.ResolveAsync(orgId, "maven", ct);
        if (bases.Count == 0)
        {
            return NotFound();
        }

        // Dep-confusion guard: locally-reserved prefixes never go upstream.
        if (await _svc.ReservedNamespaces.IsReservedAsync(orgId, "maven", coords.GroupId, ct))
        {
            return NotFound();
        }

        // Snapshot proxying is out of scope for v1.
        if (coords.IsSnapshot)
        {
            return NotFound();
        }

        // For sidecar requests on a proxied primary: if the primary isn't cached yet,
        // we don't try to proxy the sidecar independently — let the client retry the
        // primary first, then the sidecar will be served from stored checksum columns.
        // The recursive-primary-fetch approach described in the ticket is deferred — the
        // common client pattern of requesting primary before sidecar makes this safe.
        if (coords.IsChecksumSidecar)
        {
            return NotFound();
        }

        // Build the upstream path: convert groupId dots to slashes for the URL.
        string groupPath = coords.GroupId.Replace('.', '/');
        string upstreamPath = $"{groupPath}/{coords.ArtifactId}/{coords.Version}/{coords.Filename}";

        string? purlForLog = coords.Version is not null
            ? PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version)
            : null;

        // Walk the configured upstreams in priority order; the first that yields the
        // artifact wins. A single configured registry behaves identically to before.
        MavenArtifactFetchResult? result = null;
        foreach (string upstreamBase in bases)
        {
            try
            {
                result = await _svc.Upstream.FetchArtifactAsync(
                    upstreamBase, upstreamPath, ct, orgId: orgId, purl: purlForLog);
            }
            catch (ChecksumException)
            {
                return StatusCode(502);
            }

            if (result is not null)
            {
                break;
            }
        }

        if (result is null)
        {
            return NotFound();
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version!);

        // Run the shared proxy pipeline: record the package_versions row, synchronously
        // scan OSV, and evaluate the block gate so a vulnerable artifact is refused on the
        // very first fetch — the same record→scan→gate sequence PyPI/npm/NuGet use. The
        // blob already lives at result.BlobKey (UpstreamClient hash-and-staged it during
        // FetchArtifactAsync); OpenAsync is only consulted for licence extraction or a
        // non-sha256 re-verify, neither of which Maven requests, so it stays unused here.
        var blob = new BlobHandle(result.BlobKey, result.Sha256, result.Bytes.LongLength,
            async openCt => await _svc.Blobs.GetAsync(BlobKeys.StoreKey(result.BlobKey), openCt)
                ?? (Stream)new MemoryStream(result.Bytes, writable: false));

        var fetch = await _svc.ProxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: orgId, Ecosystem: "maven",
            PackageName: coords.PackageName, PurlName: coords.PackageName,
            Version: coords.Version!, Purl: purl, File: coords.Filename, Blob: blob,
            ExtractLicenses: null,
            UserId: token?.UserId,
            ActorKind: token?.ActorKind,
            SourceIp: HttpContext.GetNormalizedRemoteIp(),
            MaxOsvScoreTolerance: settings?.MaxOsvScoreTolerance ?? 10.0,
            CacheAccess: null,
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            Sha1Hex: result.Sha1,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            MaxEpssTolerance: settings?.MaxEpssTolerance), ct);

        if (fetch.Decision == BlockDecision.Blocked)
        {
            return StatusCode(403);
        }

        // The shared pipeline owns package_versions + the first_fetch activity; Maven owns
        // its per-file mapping. Record it only when the gate allowed the artifact — a
        // refused version never gets a serve-row, and a later attempt re-fetches + re-gates.
        if (fetch.VersionId is not null)
        {
            await RecordMavenFileAsync(fetch.VersionId, coords, result, ct);
        }

        Response.Headers["X-Cache"] = "MISS";
        return File(result.Bytes, ContentTypeFor(coords.Extension), coords.Filename);
    }

    /// <summary>
    /// Records the <c>maven_version_files</c> row for a proxied artifact against the
    /// <c>package_versions</c> id the shared proxy pipeline already created. Idempotent on
    /// (package_version_id, filename) so a second file of the same coordinate — or a
    /// concurrent first-fetch — doesn't collide.
    /// </summary>
    private async Task RecordMavenFileAsync(
        string versionId, MavenCoordinates coords, MavenArtifactFetchResult result, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);

        // xtenant: maven_version_files FK chain: package_version_id → package_versions → packages.org_id.
        // versionId came from ProxyFetchService's GetOrCreate(orgId,...) chain, so it is tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                    @sha256, @sha1, @md5, 'proxy')
            ON CONFLICT(package_version_id, filename) DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                filename = coords.Filename,
                classifier = coords.Classifier,
                extension = coords.Extension ?? "",
                blobKey = result.BlobKey,
                sizeBytes = (long)result.Bytes.Length,
                sha256 = result.Sha256,
                sha1 = result.Sha1,
                md5 = result.Md5,
            });
    }

    private async Task<IActionResult> ServeMetadataAsync(
        string orgId, MavenCoordinates coords, CancellationToken ct)
    {
        await using var conn = await _svc.Db.OpenAsync(ct);
        var localVersions = (await conn.QueryAsync<string>(
            """
            SELECT pv.version
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven' AND p.purl_name = @purlName
            ORDER BY pv.created_at ASC
            """,
            new { orgId, purlName = coords.PackageName })).ToList();

        // Merge upstream versions unless this groupId is reserved. An empty registry list
        // (proxying disabled for maven) leaves mergedVersions local-only.
        var mergedVersions = localVersions;
        var bases = await _svc.Registries.ResolveAsync(orgId, "maven", ct);
        if (_svc.Upstream is not null &&
            bases.Count > 0 &&
            !await _svc.ReservedNamespaces.IsReservedAsync(orgId, "maven", coords.GroupId, ct))
        {
            string groupPath = coords.GroupId.Replace('.', '/');
            string artifactPath = $"{groupPath}/{coords.ArtifactId}";

            // Walk upstreams in priority order; the first that returns versions wins.
            foreach (string upstreamBase in bases)
            {
                var upstreamVersions = await _svc.Upstream.FetchUpstreamVersionsAsync(upstreamBase, artifactPath, ct);
                if (upstreamVersions is { Count: > 0 })
                {
                    // Union: local wins on collision; preserve order (local first, then upstream-only additions).
                    var localSet = new HashSet<string>(localVersions, StringComparer.OrdinalIgnoreCase);
                    mergedVersions = [.. localVersions, .. upstreamVersions.Where(v => !localSet.Contains(v))];
                    break;
                }
            }
        }

        if (mergedVersions.Count == 0)
        {
            return NotFound();
        }

        if (coords.IsChecksumSidecar)
        {
            string xml = MavenMetadataBuilder.Build(coords.GroupId, coords.ArtifactId, mergedVersions);
            string hex = ComputeHex(coords.ChecksumAlgorithm!, Encoding.UTF8.GetBytes(xml));
            return new ContentResult
            {
                Content = hex,
                ContentType = "text/plain",
                StatusCode = 200,
            };
        }

        string body = MavenMetadataBuilder.Build(coords.GroupId, coords.ArtifactId, mergedVersions);
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
        string metaETag = ComputeETagFromBytes(bodyBytes);
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == metaETag)
        {
            Response.Headers.ETag = metaETag;
            return StatusCode(304);
        }
        Response.Headers.ETag = metaETag;
        // Proxy-merged responses may include upstream versions; short TTL so changes propagate.
        // Local-only (no upstream configured) responses are stable; longer TTL is appropriate.
        Response.Headers.CacheControl = (_svc.Upstream is not null && bases.Count > 0)
            ? "private, max-age=60"
            : "private, max-age=300";
        return Content(body, "application/xml", Encoding.UTF8);
    }

    private async Task<IActionResult> StoreFileAsync(
        string orgId, MavenCoordinates coords, byte[] bytes, TokenRecord token, CancellationToken ct)
    {
        // Sidecar checksums: clients upload them next to the primary. We don't store the
        // sidecar bytes — we accept, validate that the hex matches what we'd compute,
        // and discard. This keeps sidecars consistent with the primary artifact in the
        // happy case and rejects a deliberately mismatched upload.
        if (coords.IsChecksumSidecar)
        {
            return await ValidateAndAcknowledgeSidecarAsync(orgId, coords, bytes, ct);
        }

        string purl = PurlNormalizer.Maven(coords.GroupId, coords.ArtifactId, coords.Version!);
        string sha256Hex = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        // deepcode ignore InsecureHash: Maven repo spec requires .sha1/.md5 sidecar files for
        // mvn/gradle client compatibility — these are not used for security decisions.
        string sha1Hex = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
        // deepcode ignore InsecureHash: Maven repo spec requires .md5 sidecar files.
        string md5Hex = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();

        string blobKey = BlobKeys.Hosted(
            orgId, "maven",
            coords.PackageName.Replace(':', '/'),  // groupId/artifactId in the blob path
            coords.Version!,
            coords.Filename);

        // PackageRepository.GetOrCreateAsync + manual package_versions / maven_version_files
        // because Maven's multi-file shape doesn't fit IPackagePublishService's
        // one-blob-one-version contract. The package_versions row is shared across all
        // files of a version; maven_version_files carries the per-file mapping.
        var pkg = await _svc.Packages.GetOrCreateAsync(orgId, "maven", coords.PackageName, coords.PackageName, isProxy: false, ct);

        await _svc.Blobs.PutAsync(blobKey, new MemoryStream(bytes), ct);

        await using var conn = await _svc.Db.OpenAsync(ct);

        // xtenant: pkg.Id came from GetOrCreateAsync(orgId, ...), so this lookup is keyed
        // by a tenant-scoped FK target. package_versions joins through packages.org_id.
        // Get-or-create the package_versions row.
        var (Id, _) = await conn.QuerySingleOrDefaultAsync<(string Id, string BlobKey)>(
            "SELECT id AS Id, blob_key AS BlobKey FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = pkg.Id, version = coords.Version });

        string versionId;
        if (Id is null)
        {
            versionId = Guid.NewGuid().ToString("N");
            // xtenant: package_id was just obtained via GetOrCreateAsync(orgId,...), so the
            // FK to packages(id) carries the tenant binding. Inserting against that id is
            // implicitly tenant-scoped.
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, checksum_sha1, origin)
                VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes, @sha256, @sha1, 'uploaded')
                """,
                new
                {
                    id = versionId,
                    pkgId = pkg.Id,
                    version = coords.Version,
                    purl,
                    blobKey,
                    filename = coords.Filename,
                    sizeBytes = (long)bytes.Length,
                    sha256 = sha256Hex,
                    sha1 = sha1Hex,
                });
        }
        else
        {
            versionId = Id;
        }

        // xtenant: maven_version_files FKs into package_versions(id), which FKs into
        // packages(id) — the org_id is reachable transitively. The package_version_id
        // we're inserting against came from a tenant-scoped GetOrCreateAsync chain above.
        // Insert / replace maven_version_files row. ON CONFLICT(package_version_id, filename)
        // overwrites so a republished file gets the new hash.
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pvId, @filename, @classifier, @extension, @blobKey, @sizeBytes,
                    @sha256, @sha1, @md5, 'uploaded')
            ON CONFLICT(package_version_id, filename) DO UPDATE SET
                blob_key = @blobKey,
                size_bytes = @sizeBytes,
                checksum_sha256 = @sha256,
                checksum_sha1 = @sha1,
                checksum_md5 = @md5
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                filename = coords.Filename,
                classifier = coords.Classifier,
                extension = coords.Extension ?? "",
                blobKey,
                sizeBytes = (long)bytes.Length,
                sha256 = sha256Hex,
                sha1 = sha1Hex,
                md5 = md5Hex,
            });

        await _svc.Audit.LogActivityAsync(orgId, "maven", purl, "push",
            actorId: token.UserId, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        Response.Headers["X-Dependably-PURL"] = purl;
        return StatusCode(201);
    }

    private async Task<IActionResult> ValidateAndAcknowledgeSidecarAsync(
        string orgId, MavenCoordinates coords, byte[] bytes, CancellationToken ct)
    {
        // We don't persist sidecar bytes — they're a function of the primary file's
        // content, which we already store. But we DO sanity-check the hex matches our
        // record so a mismatched sidecar can't pollute the index.
        string primaryFilename = MavenPathParser.PrimaryFilename(coords.Filename);
        await using var conn = await _svc.Db.OpenAsync(ct);
        var (Sha256, Sha1, Md5) = await conn.QuerySingleOrDefaultAsync<(string Sha256, string? Sha1, string? Md5)>(
            """
            SELECT mvf.checksum_sha256 AS Sha256, mvf.checksum_sha1 AS Sha1, mvf.checksum_md5 AS Md5
            FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'maven'
              AND p.purl_name = @purlName AND pv.version = @version
              AND mvf.filename = @filename
            LIMIT 1
            """,
            new
            {
                orgId,
                purlName = coords.PackageName,
                version = coords.Version,
                filename = primaryFilename,
            });

        if (Sha256 is null)
        {
            // No primary yet — Maven clients usually upload the primary first, but we
            // accept the sidecar order-of-arrival anyway. The next primary upload will
            // compute and store the real checksum; this sidecar is informational only.
            return StatusCode(201);
        }

        string uploadedHex = Encoding.UTF8.GetString(bytes).Trim().ToLowerInvariant();
        // Some Maven clients prefix or suffix the hex with garbage; pull out the first
        // continuous hex run.
        string hex = ExtractHex(uploadedHex);
        string? expected = coords.ChecksumAlgorithm switch
        {
            "sha256" => Sha256,
            "sha1" => Sha1,
            "md5" => Md5,
            _ => null,
        };
        return expected is not null && !string.Equals(hex, expected, StringComparison.OrdinalIgnoreCase)
            ? BadRequest("Maven checksum sidecar mismatch.")
            : StatusCode(201);
    }

    private async Task<long?> ResolveSizeCapAsync(string orgId, CancellationToken ct)
    {
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        if (settings is null)
        {
            return null;
        }

        // Read max_upload_bytes_maven dynamically because the column was added after the
        // strongly-typed OrgSettings model, which doesn't surface it yet.
        await using var conn = await _svc.Db.OpenAsync(ct);
        long? orgMaven = await conn.ExecuteScalarAsync<long?>(
            "SELECT max_upload_bytes_maven FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        return orgMaven ?? settings.MaxUploadBytes;
    }

    private static async Task<string?> ComputeChecksumAsync(Stream stream, string algorithm, CancellationToken ct)
    {
        using HashAlgorithm hasher = algorithm switch
        {
            "sha512" => SHA512.Create(),
            "sha256" => SHA256.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "sha1" => SHA1.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "md5" => MD5.Create(),
            _ => SHA256.Create(),
        };
        await using (stream.ConfigureAwait(false))
        {
            byte[] hash = await hasher.ComputeHashAsync(stream, ct);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }

    private static string ComputeHex(string algorithm, byte[] bytes)
    {
        using HashAlgorithm hasher = algorithm switch
        {
            "sha512" => SHA512.Create(),
            "sha256" => SHA256.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "sha1" => SHA1.Create(),
            // deepcode ignore InsecureHash: Maven sidecar spec — see class-level SuppressMessage.
            "md5" => MD5.Create(),
            _ => SHA256.Create(),
        };
        return Convert.ToHexString(hasher.ComputeHash(bytes)).ToLowerInvariant();
    }

    private static string ExtractHex(string input)
    {
        var sb = new StringBuilder();
        foreach (char c in input)
        {
            if (Uri.IsHexDigit(c))
            {
                sb.Append(c);
            }
            else if (sb.Length > 0)
            {
                break;
            }
        }
        return sb.ToString();
    }

    private static string ComputeETagFromBytes(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..16].ToLowerInvariant() + "\"";
    }

    private static string ContentTypeFor(string? extension) => extension switch
    {
        "jar" or "war" or "ear" or "aar" => "application/java-archive",
        "pom" or "xml" => "application/xml",
        "module" => "application/json",
        _ => "application/octet-stream",
    };

    private sealed record MavenFileRow(
        string Id,
        string PackageVersionId,
        string Filename,
        string Extension,
        string BlobKey,
        string? ChecksumSha256,
        string? ChecksumSha1,
        string? ChecksumMd5,
        string Purl,
        string? ManualBlockState,
        DateTimeOffset? VulnCheckedAt,
        DateTimeOffset? PublishedAt,
        string? Deprecated);
}

/// <summary>Scoped DI bundle for the Maven controller — mirrors the npm/PyPI shape.</summary>
public sealed record MavenControllerServices(
    PackageRepository Packages,
    TokenRepository Tokens,
    AuditRepository Audit,
    OrgRepository Orgs,
    IBlobStore Blobs,
    IMetadataStore Db,
    MavenUpstreamFetcher Upstream,
    IConfiguration Config,
    ProxyFetchService ProxyFetch,
    BlockGateService BlockGate,
    ReservedNamespaceService ReservedNamespaces,
    UpstreamRegistryResolver Registries);
