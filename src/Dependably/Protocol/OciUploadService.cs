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
///
/// Resource-safety on the push path:
///   - Disk floor: <see cref="StartUploadAsync"/> and <see cref="AppendChunkAsync"/> both
///     call <see cref="IStagingDiskInfo.GetAvailableBytes"/> before touching the staging file.
///     Below the operator-configured floor they throw <see cref="StagingDiskFullException"/>,
///     which <c>StagingDiskFullExceptionMiddleware</c> maps to HTTP 507.
///   - Per-tenant cap: <see cref="StartUploadAsync"/> counts open sessions for the org and
///     rejects the request with <see cref="OciSessionCapExceededException"/> when at or over
///     the limit (instance setting <c>max_concurrent_oci_uploads_per_tenant</c>).
///   - TTL janitor: <see cref="OciStagingJanitorService"/> sweeps abandoned sessions and
///     orphaned staging temp files on a configurable cron schedule.
/// </summary>
public sealed class OciUploadService
{
    // SQLite SQLITE_CONSTRAINT error code (unique constraint violation on insert).
    private const int SqliteConstraintErrorCode = 19;

    private readonly IMetadataStore _db;
    private readonly TieredBlobStorage _blobs;
    private readonly PackageRepository _packages;
    private readonly OrgRepository _orgs;
    private readonly IStagingDiskInfo _stagingDiskInfo;
    private readonly long _stagingDiskFloorBytes;
    private readonly string _stagingPath;
    private readonly ILogger<OciUploadService> _logger;

    /// <summary>
    /// Injected dependencies for <see cref="OciUploadService"/>. Bundles the eight DI services
    /// so the constructor stays within the parameter-count gate (S107).
    /// </summary>
    public sealed record Dependencies(
        IMetadataStore Db,
        TieredBlobStorage Blobs,
        OrgRepository Orgs,
        IStagingDiskInfo StagingDiskInfo,
        StagingOptions StagingOptions,
        IConfiguration Configuration,
        ILogger<OciUploadService> Logger,
        TimeProvider Time);

    public OciUploadService(Dependencies deps)
    {
        _db = deps.Db;
        _blobs = deps.Blobs;
        _orgs = deps.Orgs;
        _stagingDiskInfo = deps.StagingDiskInfo;
        _stagingDiskFloorBytes = deps.StagingOptions.FloorBytes;
        // PackageRepository is a stateless Dapper wrapper over the same IMetadataStore, built
        // here (not injected) so this Singleton doesn't capture a Scoped repository.
        _packages = new PackageRepository(deps.Db, time: deps.Time);
        _logger = deps.Logger;

        string? configured = deps.Configuration["PROXY_STAGING_PATH"];
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

    /// <summary>
    /// Opens a new upload session and returns it (received bytes = 0).
    /// Enforces:
    ///   1. Disk floor — throws <see cref="StagingDiskFullException"/> when free space is
    ///      below the operator-configured floor.
    ///   2. Per-tenant session cap — throws <see cref="OciSessionCapExceededException"/>
    ///      when the tenant already has <c>max_concurrent_oci_uploads_per_tenant</c> open
    ///      sessions. The count and insert happen in separate statements so a small window
    ///      exists for concurrent races; a tight cap (default 32) bounds the blast radius.
    /// </summary>
    public async Task<OciUploadSession> StartUploadAsync(string orgId, string repository, CancellationToken ct)
    {
        EnsureStagingDiskFloor();

        int cap = await _orgs.GetMaxConcurrentOciUploadsPerTenantAsync(ct);
        long active = await _orgs.GetActiveOciUploadCountAsync(orgId, ct);
        if (active >= cap)
        {
            throw new OciSessionCapExceededException(orgId, (int)active, cap);
        }

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
    /// file's length is the source of truth for the total. Enforces the disk floor before each
    /// write — throws <see cref="StagingDiskFullException"/> when free space is critically low.
    /// </summary>
    public async Task<long> AppendChunkAsync(
        string orgId, OciUploadSession session, Stream chunk, CancellationToken ct)
    {
        EnsureStagingDiskFloor();

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
    /// Checks the staging disk floor. Throws <see cref="StagingDiskFullException"/> when free
    /// space is below the floor; also throws (failing closed) when the disk-read itself fails.
    /// A configured floor of 0 disables the check entirely (operator opt-out).
    /// </summary>
    private void EnsureStagingDiskFloor()
    {
        if (_stagingDiskFloorBytes <= 0)
        {
            return;
        }

        try
        {
            long available = _stagingDiskInfo.GetAvailableBytes();
            if (available < _stagingDiskFloorBytes)
            {
                throw new StagingDiskFullException(available, _stagingDiskFloorBytes);
            }
        }
        catch (StagingDiskFullException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not read staging disk space before OCI upload operation: {ExceptionType}",
                ex.GetType().Name);
            throw new StagingDiskFullException(0, _stagingDiskFloorBytes); // fail closed
        }
    }

    /// <summary>
    /// Finalizes a blob upload: verifies the staged bytes hash to <paramref name="digest"/>,
    /// checks the tenant's aggregate storage quota, copies bytes into the Registry tier, and
    /// records the <c>oci_blobs</c> row. Deletes the session (and staging file) on every
    /// terminal outcome. Returns <see cref="OciFinalizeStatus.QuotaExceeded"/> when the blob
    /// would push the tenant over its storage ceiling; the caller returns 413.
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

        // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path; not user-controlled.
        long sizeBytes = new FileInfo(session.StagingPath).Length;
        string blobKey = BlobKeys.OciBlob("sha256", computedHex);

        // Quota reservation: blobs that already exist in the Registry tier do not consume
        // additional tenant quota (content-addressed storage — same bytes already counted).
        // Only reserve for new blobs to avoid double-counting when two tenants push identical
        // layers. Reserve before any write so the counter stays accurate on failure.
        bool newBlob = !await _blobs.Registry.ExistsAsync(blobKey, ct);
        long? quota = newBlob ? await _orgs.GetEffectiveStorageQuotaAsync(orgId, ct) : null;
        bool reserved = false;
        if (newBlob && quota is not null)
        {
            if (!await _orgs.TryReserveStorageAsync(orgId, sizeBytes, quota, ct))
            {
                await CleanupSessionAsync(orgId, session, ct);
                return OciBlobFinalizeResult.QuotaExceeded;
            }
            reserved = true;
        }

        try
        {
            if (newBlob)
            {
                // deepcode ignore PT: StagingPath is the server-generated "oci-upload-{GUID}" path; not user-controlled.
                await using var src = new FileStream(session.StagingPath, FileMode.Open, FileAccess.Read);
                await _blobs.Registry.PutAsync(blobKey, src, ct);
            }

            await UpsertBlobRowAsync(orgId, $"sha256:{computedHex}", "application/octet-stream", sizeBytes, blobKey, ct);
            await CleanupSessionAsync(orgId, session, ct);

            _logger.LogInformation(
                "OCI blob push {Repository}/sha256:{Digest} ({Bytes} B)", session.Repository, computedHex, sizeBytes);
            return OciBlobFinalizeResult.Ok($"sha256:{computedHex}", sizeBytes);
        }
        catch
        {
            // Release the reservation so the quota counter stays accurate when the blob put
            // or metadata upsert fails. Fire-and-forget: a release failure leaves the counter
            // high (conservative — more likely to 413 on retry), which is safer than low.
            if (reserved)
            {
                try { await _orgs.ReleaseStorageAsync(orgId, sizeBytes, CancellationToken.None); }
                catch (Exception releaseEx)
                {
                    _logger.LogError(releaseEx,
                        "Quota counter release failed for org {OrgId} after OCI blob finalize failure; " +
                        "counter may be high until next publish. BlobKey={BlobKey} TraceId={TraceId}",
                        orgId, blobKey,
                        System.Diagnostics.Activity.Current?.TraceId.ToString());
                }
            }
            await CleanupSessionAsync(orgId, session, CancellationToken.None);
            throw;
        }
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
    /// Stores a pushed manifest: validates JSON + referenced-blob existence, checks the
    /// tenant's aggregate storage quota, persists the manifest as its own blob, and (when
    /// <paramref name="reference"/> is a tag) repoints the tag and catalogues the image. OCI
    /// tags are mutable by spec, so a tag re-push always succeeds and repoints — there is no
    /// immutable-version conflict as with npm/NuGet. Returns
    /// <see cref="OciManifestStatus.QuotaExceeded"/> when the manifest would push the tenant
    /// over its storage ceiling; the caller returns 413.
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

        return await ReserveAndPutManifestAsync(
            new OciManifestPutArgs(orgId, repository, reference, bytes, mediaType, hex, digest, blobKey), ct);
    }

    // Resolved manifest coordinates passed to the write tail, bundled to keep the method
    // signature within the parameter-count threshold (S107).
    private sealed record OciManifestPutArgs(
        string OrgId, string Repository, string Reference, byte[] Bytes,
        string MediaType, string Hex, string Digest, string BlobKey);

    // Handles quota reservation, blob put, metadata upsert, tag upsert, and catalog version
    // for a manifest push. Returns QuotaExceeded when the org is over its storage ceiling.
    private async Task<OciManifestStoreResult> ReserveAndPutManifestAsync(
        OciManifestPutArgs a, CancellationToken ct)
    {
        // Quota reservation: manifest blobs that already exist in the Registry tier do not
        // consume additional tenant quota (same content-addressed logic as layer blobs).
        bool newBlob = !await _blobs.Registry.ExistsAsync(a.BlobKey, ct);
        long? quota = newBlob ? await _orgs.GetEffectiveStorageQuotaAsync(a.OrgId, ct) : null;
        bool reserved = false;
        if (newBlob && quota is not null)
        {
            if (!await _orgs.TryReserveStorageAsync(a.OrgId, a.Bytes.LongLength, quota, ct))
            {
                return OciManifestStoreResult.QuotaExceeded;
            }
            reserved = true;
        }

        try
        {
            if (newBlob)
            {
                await _blobs.Registry.PutAsync(a.BlobKey, new MemoryStream(a.Bytes), ct);
            }

            await UpsertBlobRowAsync(a.OrgId, a.Digest, a.MediaType, a.Bytes.Length, a.BlobKey, ct, updateMediaType: true);

            // Repoint the tag and surface the image in the shared catalogue (only tag pushes are
            // catalogued — by-digest manifest pushes, e.g. an index's children, are not the
            // user-facing unit). Mirrors the proxy path's cataloguing with origin='uploaded'.
            bool isTag = !OciCoordinatesParser.IsValidDigest(a.Reference) && OciCoordinatesParser.IsValidTag(a.Reference);
            if (isTag)
            {
                await UpsertTagAsync(a.OrgId, a.Repository, a.Reference, a.Digest, ct);
                await RecordCatalogVersionAsync(
                    new OciCatalogEntry(a.OrgId, a.Repository, a.Reference, a.Digest, a.Hex, a.Bytes.Length, a.BlobKey), ct);
            }

            _logger.LogInformation(
                "OCI manifest push {Repository}/{Reference} → {Digest} ({Bytes} B)",
                a.Repository, a.Reference, a.Digest, a.Bytes.Length);
            return OciManifestStoreResult.Ok(a.Digest);
        }
        catch
        {
            // Release the reservation so the quota counter stays accurate when the blob put
            // or metadata upsert fails. Fire-and-forget: a release failure leaves the counter
            // high (conservative), which is safer than low.
            if (reserved)
            {
                try { await _orgs.ReleaseStorageAsync(a.OrgId, a.Bytes.LongLength, CancellationToken.None); }
                catch (Exception releaseEx)
                {
                    _logger.LogError(releaseEx,
                        "Quota counter release failed for org {OrgId} after OCI manifest store failure; " +
                        "counter may be high until next publish. BlobKey={BlobKey} TraceId={TraceId}",
                        a.OrgId, a.BlobKey,
                        System.Diagnostics.Activity.Current?.TraceId.ToString());
                }
            }
            throw;
        }
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
            if (ex is not Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: SqliteConstraintErrorCode })
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
    public static readonly OciBlobFinalizeResult QuotaExceeded = new(OciFinalizeStatus.QuotaExceeded);
    public static OciBlobFinalizeResult Ok(string digest, long size) => new(OciFinalizeStatus.Ok, digest, size);
}

public enum OciFinalizeStatus { Ok, BadDigest, DigestMismatch, QuotaExceeded }

/// <summary>Outcome of a manifest push.</summary>
public sealed record OciManifestStoreResult(OciManifestStatus Status, string? Digest = null, string? MissingDigest = null)
{
    public static readonly OciManifestStoreResult Invalid = new(OciManifestStatus.Invalid);
    public static readonly OciManifestStoreResult QuotaExceeded = new(OciManifestStatus.QuotaExceeded);
    public static OciManifestStoreResult MissingBlob(string digest) => new(OciManifestStatus.MissingBlob, MissingDigest: digest);
    public static OciManifestStoreResult Ok(string digest) => new(OciManifestStatus.Ok, Digest: digest);
}

public enum OciManifestStatus { Ok, Invalid, MissingBlob, QuotaExceeded }

/// <summary>
/// Thrown by <see cref="OciUploadService.StartUploadAsync"/> when a tenant already has
/// the maximum number of concurrent upload sessions open. Caught by the OCI controller
/// and translated to HTTP 429 with an OCI <c>DENIED</c> error body.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class OciSessionCapExceededException : Exception
{
    public string OrgId { get; }
    public int ActiveCount { get; }
    public int Cap { get; }

    public OciSessionCapExceededException(string orgId, int active, int cap)
        : base($"Tenant {orgId} has {active} open OCI upload sessions; cap is {cap}.")
    {
        OrgId = orgId;
        ActiveCount = active;
        Cap = cap;
    }
}
