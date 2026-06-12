using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;

namespace Dependably.Protocol;

// Staging file paths in this service are never user-controlled: the file name is
// "oci-upload-{guid}" (a server-generated GUID) under the operator-configured PROXY_STAGING_PATH
// root, and the path is round-tripped through the DB keyed by (upload_id, org_id). The analyzer's
// interprocedural taint from the controller's route/tenant inputs is a false positive — those
// inputs never reach the constructed file name. Disable the path-traversal warning file-wide.
#pragma warning disable SCS0018

/// <summary>
/// Write side of the OCI Distribution Spec: blob upload sessions and manifest storage for
/// <c>docker push</c>. The read side (<see cref="OciUpstreamResolver"/> + the controller's
/// cache lookups) serves everything this writes back, with no read-path changes — pushed
/// content lands in <c>oci_blobs</c>/<c>oci_tags</c> with <c>origin='uploaded'</c> on the
/// Registry tier (durable, never auto-evicted), exactly where the read path looks.
///
/// Hash-and-stage: blob bytes stream to a local staging file under <c>PROXY_STAGING_PATH</c>
/// (chunked pushes append across multiple PATCH requests), are SHA-256 verified against the
/// client-supplied digest on finalize, then copied into the blob store. Staging is local even
/// for S3/Azure backends, so chunked sessions assume a single serving node — acceptable for
/// the single-instance deployment; a multi-replica deployment would need sticky sessions or
/// shared staging.
/// </summary>
public sealed class OciUploadService
{
    private readonly IMetadataStore _db;
    private readonly TieredBlobStorage _blobs;
    private readonly PackageRepository _packages;
    private readonly string _stagingPath;
    private readonly ILogger<OciUploadService> _logger;

    public OciUploadService(
        IMetadataStore db,
        TieredBlobStorage blobs,
        IConfiguration configuration,
        ILogger<OciUploadService> logger)
    {
        _db = db;
        _blobs = blobs;
        // PackageRepository is a stateless Dapper wrapper over the same IMetadataStore, built
        // here (not injected) so this Singleton doesn't capture a Scoped repository.
        _packages = new PackageRepository(db);
        _logger = logger;

        string? configured = configuration["PROXY_STAGING_PATH"];
        _stagingPath = string.IsNullOrWhiteSpace(configured) ? Path.GetTempPath() : configured;
        // deepcode ignore PT: PROXY_STAGING_PATH is set by the operator deploying the container.
        try
        {
            Directory.CreateDirectory(_stagingPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(
                "Failed to create PROXY_STAGING_PATH directory {StagingPath}: {ExceptionType}",
                _stagingPath, ex.GetType().Name);
        }
    }

    // ── Upload sessions ─────────────────────────────────────────────────────────

    /// <summary>Opens a new upload session and returns it (received bytes = 0).</summary>
    public async Task<OciUploadSession> StartUploadAsync(string orgId, string repository, CancellationToken ct)
    {
        string uploadId = Guid.NewGuid().ToString("N");
        string stagingFile = StagingFileFor(uploadId);
        // Create-and-close the (empty) staging file so PATCH-less monolithic PUTs and chunked
        // PATCHes share one append target.
        // deepcode ignore PT: staging file name is "oci-upload-{server-GUID}" under the operator-configured staging root — no user input reaches the path.
        await File.Create(stagingFile).DisposeAsync();

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (upload_id, org_id) PK binds the session to the opening tenant.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_uploads (upload_id, org_id, repository, staging_path, received_bytes)
            VALUES (@uploadId, @orgId, @repository, @stagingPath, 0)
            """,
            new { uploadId, orgId, repository, stagingPath = stagingFile });
        return new OciUploadSession(uploadId, repository, stagingFile, 0);
    }

    /// <summary>Returns the session for (org, uploadId), or null when it doesn't exist.</summary>
    public async Task<OciUploadSession?> GetSessionAsync(string orgId, string uploadId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (upload_id, org_id) PK is tenant-scoped.
        return await conn.QuerySingleOrDefaultAsync<OciUploadSession?>(
            "SELECT upload_id AS UploadId, repository AS Repository, staging_path AS StagingPath, " +
            "received_bytes AS ReceivedBytes FROM oci_uploads WHERE upload_id = @uploadId AND org_id = @orgId",
            new { uploadId, orgId });
    }

    /// <summary>
    /// Appends a chunk to an open session and returns the new running byte total. The staging
    /// file's length is the source of truth for the total.
    /// </summary>
    public async Task<long> AppendChunkAsync(
        string orgId, OciUploadSession session, Stream chunk, CancellationToken ct)
    {
        // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path round-tripped through the DB; not user-controlled.
        await using (var fs = new FileStream(session.StagingPath, FileMode.Append, FileAccess.Write))
        {
            await chunk.CopyToAsync(fs, ct);
        }

        // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path; not user-controlled.
        long total = new FileInfo(session.StagingPath).Length;
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (upload_id, org_id) PK is tenant-scoped.
        await conn.ExecuteAsync(
            "UPDATE oci_uploads SET received_bytes = @total WHERE upload_id = @uploadId AND org_id = @orgId",
            new { total, uploadId = session.UploadId, orgId });
        return total;
    }

    /// <summary>
    /// Finalizes a blob upload: verifies the staged bytes hash to <paramref name="digest"/>,
    /// copies them into the Registry tier, and records the <c>oci_blobs</c> row. Deletes the
    /// session (and staging file) on every terminal outcome.
    /// </summary>
    public async Task<OciBlobFinalizeResult> FinalizeBlobAsync(
        string orgId, OciUploadSession session, string digest, CancellationToken ct)
    {
        string[] parts = digest.Split(':', 2);
        if (parts.Length != 2 || !parts[0].Equals("sha256", StringComparison.Ordinal))
        {
            await CleanupSessionAsync(orgId, session, ct);
            return OciBlobFinalizeResult.BadDigest;
        }
        string expectedHex = parts[1].ToLowerInvariant();

        string computedHex;
        // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path; not user-controlled.
        await using (var verify = new FileStream(session.StagingPath, FileMode.Open, FileAccess.Read))
        {
            computedHex = await ChecksumVerifier.ComputeSha256HexAsync(verify, ct);
        }
        if (!string.Equals(computedHex, expectedHex, StringComparison.Ordinal))
        {
            await CleanupSessionAsync(orgId, session, ct);
            return OciBlobFinalizeResult.DigestMismatch;
        }

        string blobKey = BlobKeys.OciBlob("sha256", computedHex);
        long sizeBytes;
        if (!await _blobs.Registry.ExistsAsync(blobKey, ct))
        {
            // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path; not user-controlled.
            await using var src = new FileStream(session.StagingPath, FileMode.Open, FileAccess.Read);
            await _blobs.Registry.PutAsync(blobKey, src, ct);
        }
        // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path; not user-controlled.
        sizeBytes = new FileInfo(session.StagingPath).Length;

        await UpsertBlobRowAsync(orgId, $"sha256:{computedHex}", "application/octet-stream", sizeBytes, blobKey, ct);
        await CleanupSessionAsync(orgId, session, ct);

        _logger.LogInformation(
            "OCI blob push {Repository}/sha256:{Digest} ({Bytes} B)", session.Repository, computedHex, sizeBytes);
        return OciBlobFinalizeResult.Ok($"sha256:{computedHex}", sizeBytes);
    }

    /// <summary>Deletes a session's DB row and staging file. Safe to call more than once.</summary>
    public async Task AbortUploadAsync(string orgId, OciUploadSession session, CancellationToken ct)
        => await CleanupSessionAsync(orgId, session, ct);

    // ── Manifests ───────────────────────────────────────────────────────────────

    /// <summary>True when a blob/manifest with <paramref name="digest"/> exists for the org.</summary>
    public async Task<bool> BlobExistsAsync(string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(1) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId }) > 0;
    }

    /// <summary>
    /// Stores a pushed manifest: validates JSON + referenced-blob existence, persists the
    /// manifest as its own blob, and (when <paramref name="reference"/> is a tag) repoints the
    /// tag and catalogues the image. OCI tags are mutable by spec, so a tag re-push always
    /// succeeds and repoints — there is no immutable-version conflict as with npm/NuGet.
    /// </summary>
    public async Task<OciManifestStoreResult> StoreManifestAsync(
        string orgId, string repository, string reference, byte[] bytes, string mediaType, CancellationToken ct)
    {
        var refs = OciManifestParser.ParseReferences(bytes);
        if (refs is null)
        {
            return OciManifestStoreResult.Invalid;
        }

        foreach (string d in refs.Digests)
        {
            if (!await BlobExistsAsync(orgId, d, ct))
            {
                return OciManifestStoreResult.MissingBlob(d);
            }
        }

        string hex = ChecksumVerifier.ComputeSha256Hex(bytes);
        string digest = $"sha256:{hex}";
        string blobKey = BlobKeys.OciBlob("sha256", hex);

        if (!await _blobs.Registry.ExistsAsync(blobKey, ct))
        {
            await _blobs.Registry.PutAsync(blobKey, new MemoryStream(bytes), ct);
        }

        await UpsertBlobRowAsync(orgId, digest, mediaType, bytes.Length, blobKey, ct, updateMediaType: true);

        // Repoint the tag and surface the image in the shared catalogue (only tag pushes are
        // catalogued — by-digest manifest pushes, e.g. an index's children, are not the
        // user-facing unit). Mirrors the proxy path's cataloguing with origin='uploaded'.
        bool isTag = !OciCoordinatesParser.IsValidDigest(reference) && OciCoordinatesParser.IsValidTag(reference);
        if (isTag)
        {
            await UpsertTagAsync(orgId, repository, reference, digest, ct);
            await RecordCatalogVersionAsync(
                new OciCatalogEntry(orgId, repository, reference, digest, hex, bytes.Length, blobKey), ct);
        }

        _logger.LogInformation(
            "OCI manifest push {Repository}/{Reference} → {Digest} ({Bytes} B)",
            repository, reference, digest, bytes.Length);
        return OciManifestStoreResult.Ok(digest);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private string StagingFileFor(string uploadId) => Path.Combine(_stagingPath, $"oci-upload-{uploadId}");

    private async Task UpsertBlobRowAsync(
        string orgId, string digest, string mediaType, long sizeBytes, string blobKey,
        CancellationToken ct, bool updateMediaType = false)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Two fully-literal statements selected by a bool — no SQL string is built from data, so
        // the ON CONFLICT action can't be a SQL-injection vector. A manifest push must adopt the
        // real manifest media type even if the digest was first seen as a generic layer blob; a
        // layer push keeps whatever is already recorded.
        // xtenant: (digest, org_id) PK is tenant-scoped.
        const string insert =
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at) " +
            "VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'uploaded', " +
            "strftime('%Y-%m-%dT%H:%M:%SZ','now')) ON CONFLICT(digest, org_id) ";
        string sql = updateMediaType
            ? insert + "DO UPDATE SET media_type = excluded.media_type, size_bytes = excluded.size_bytes"
            : insert + "DO NOTHING";
        await conn.ExecuteAsync(sql, new { digest, orgId, mediaType, sizeBytes, blobKey });
    }

    private async Task UpsertTagAsync(
        string orgId, string repository, string tag, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // last_revalidated is left NULL: an uploaded tag is authoritative locally and is never
        // revalidated against an upstream (it isn't a proxy mapping).
        // xtenant: (org_id, repository, tag) PK is tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at)
            VALUES (@orgId, @repo, @tag, @digest, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            ON CONFLICT(org_id, repository, tag) DO UPDATE SET
                digest     = excluded.digest,
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                last_revalidated = NULL
            """,
            new { orgId, repo = repository, tag, digest });
    }

    /// <summary>
    /// Records the pushed image in the shared package catalogue (<c>packages</c> /
    /// <c>package_versions</c>) so overview counts and the Packages page see it like every
    /// other ecosystem. Best-effort and idempotent — a unique-constraint hit (re-push of the
    /// same tag→digest, or many-tags-to-one-digest) is the expected case and swallowed; any
    /// other failure is logged but never propagated, since the push has already succeeded.
    /// </summary>
    /// <summary>Identity of a pushed image tag, as recorded in the shared package catalogue.</summary>
    private readonly record struct OciCatalogEntry(
        string OrgId, string Repository, string Tag, string Digest, string Sha256Hex,
        long SizeBytes, string BlobKey);

    private async Task RecordCatalogVersionAsync(OciCatalogEntry entry, CancellationToken ct)
    {
        try
        {
            var pkg = await _packages.GetOrCreateAsync(
                entry.OrgId, "oci", entry.Repository, entry.Repository, isProxy: false, ct);
            string purl = PurlNormalizer.Oci(entry.Repository, entry.Digest, entry.Tag);
            await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, entry.Digest, purl, entry.BlobKey, entry.SizeBytes,
                    entry.Sha256Hex, FirstFetch: false, Origin: "uploaded"),
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (ex is not Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 19 })
            {
                _logger.LogWarning(
                    "{ExceptionType} cataloguing pushed OCI version {Repository}@{Digest}; push unaffected. BlobKey={BlobKey} TraceId={TraceId}",
                    ex.GetType().Name, entry.Repository, entry.Digest, entry.BlobKey,
                    System.Diagnostics.Activity.Current?.TraceId.ToString());
            }
        }
    }

    private async Task CleanupSessionAsync(string orgId, OciUploadSession session, CancellationToken ct)
    {
        try
        {
            // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path; not user-controlled.
            if (File.Exists(session.StagingPath))
            {
                File.Delete(session.StagingPath);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Failed to delete OCI staging file {StagingPath}: {ExceptionType}",
                session.StagingPath, ex.GetType().Name);
        }

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (upload_id, org_id) PK is tenant-scoped.
        await conn.ExecuteAsync(
            "DELETE FROM oci_uploads WHERE upload_id = @uploadId AND org_id = @orgId",
            new { uploadId = session.UploadId, orgId });
    }
}

/// <summary>An open OCI upload session.</summary>
public sealed record OciUploadSession(string UploadId, string Repository, string StagingPath, long ReceivedBytes);

/// <summary>Outcome of a blob-upload finalize.</summary>
public sealed record OciBlobFinalizeResult(OciFinalizeStatus Status, string? Digest = null, long SizeBytes = 0)
{
    public static readonly OciBlobFinalizeResult BadDigest = new(OciFinalizeStatus.BadDigest);
    public static readonly OciBlobFinalizeResult DigestMismatch = new(OciFinalizeStatus.DigestMismatch);
    public static OciBlobFinalizeResult Ok(string digest, long size) => new(OciFinalizeStatus.Ok, digest, size);
}

public enum OciFinalizeStatus { Ok, BadDigest, DigestMismatch }

/// <summary>Outcome of a manifest push.</summary>
public sealed record OciManifestStoreResult(OciManifestStatus Status, string? Digest = null, string? MissingDigest = null)
{
    public static readonly OciManifestStoreResult Invalid = new(OciManifestStatus.Invalid);
    public static OciManifestStoreResult MissingBlob(string digest) => new(OciManifestStatus.MissingBlob, MissingDigest: digest);
    public static OciManifestStoreResult Ok(string digest) => new(OciManifestStatus.Ok, Digest: digest);
}

public enum OciManifestStatus { Ok, Invalid, MissingBlob }
