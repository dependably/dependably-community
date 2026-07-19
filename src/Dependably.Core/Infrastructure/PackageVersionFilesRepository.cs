using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-file blob records for hosted PyPI versions (<c>package_version_files</c>): one
/// <c>package_versions</c> row per (name, version) carries the version identity, and each
/// distribution file of that version (wheel + sdist + per-platform wheels) maps to its own
/// blob/filename/size/checksum here — the model pypi.org exposes. The parent row's
/// <c>size_bytes</c> is maintained as the SUM of its files so tenant quota accounting stays
/// symmetric between publish reservations and version deletion. Hosted-only: proxy-origin
/// PyPI files live in <c>cache_artifact</c>.
/// </summary>
public sealed class PackageVersionFilesRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public PackageVersionFilesRepository(IMetadataStore db, TimeProvider? time = null)
    {
        _db = db;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Adds a file record and refreshes the parent version's size sum.</summary>
    public async Task<PackageVersionFile> AddAsync(
        string packageVersionId, string orgId, string filename, string blobKey,
        long sizeBytes, string? checksumSha256, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_files
                (id, package_version_id, org_id, filename, blob_key, size_bytes, checksum_sha256, created_at)
            VALUES (@id, @packageVersionId, @orgId, @filename, @blobKey, @sizeBytes, @checksumSha256, @now)
            """,
            new { id, packageVersionId, orgId, filename, blobKey, sizeBytes, checksumSha256, now });
        await RefreshVersionAfterFileChangeAsync(conn, packageVersionId, now);
        return new PackageVersionFile(id, packageVersionId, orgId, filename, blobKey, sizeBytes, checksumSha256, DateTimeOffset.Parse(now));
    }

    /// <summary>
    /// Repoints an existing file record at new bytes (same filename overwrite) and refreshes
    /// the parent version's size sum.
    /// </summary>
    public async Task UpdateForOverwriteAsync(
        string fileId, string blobKey, long sizeBytes, string? checksumSha256, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE by file PK; caller obtained the id from an org-scoped lookup.
        await conn.ExecuteAsync(
            """
            UPDATE package_version_files
               SET blob_key = @blobKey, size_bytes = @sizeBytes, checksum_sha256 = @checksumSha256
             WHERE id = @fileId
            """,
            new { fileId, blobKey, sizeBytes, checksumSha256 });
        // xtenant: keyed by the file PK resolved above; parent id stays FK-bound to it.
        string? versionId = await conn.ExecuteScalarAsync<string>(
            "SELECT package_version_id FROM package_version_files WHERE id = @fileId",
            new { fileId });
        if (versionId is not null)
        {
            string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
            await RefreshVersionAfterFileChangeAsync(conn, versionId, now);
        }
    }

    /// <summary>All file records of one version, upload order.</summary>
    public async Task<IReadOnlyList<PackageVersionFile>> GetByVersionAsync(
        string packageVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK (org-scoped via the caller's package lookup).
        var rows = await conn.QueryAsync<PackageVersionFile>(
            """
            SELECT id, package_version_id as PackageVersionId, org_id as OrgId, filename,
                   blob_key as BlobKey, size_bytes as SizeBytes,
                   checksum_sha256 as ChecksumSha256, created_at as CreatedAt
            FROM package_version_files
            WHERE package_version_id = @packageVersionId
            ORDER BY created_at, filename
            """,
            new { packageVersionId });
        return rows.ToList();
    }

    /// <summary>File records for every version of one package, keyed by version id.</summary>
    public async Task<ILookup<string, PackageVersionFile>> GetByPackageAsync(
        string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by package PK (org-scoped via the caller's package lookup).
        var rows = await conn.QueryAsync<PackageVersionFile>(
            // plane-ok: package_version_files rows exist only for hosted multi-file releases; proxy versions carry no file rows.
            """
            SELECT f.id, f.package_version_id as PackageVersionId, f.org_id as OrgId, f.filename,
                   f.blob_key as BlobKey, f.size_bytes as SizeBytes,
                   f.checksum_sha256 as ChecksumSha256, f.created_at as CreatedAt
            FROM package_version_files f
            JOIN package_versions pv ON pv.id = f.package_version_id
            WHERE pv.package_id = @packageId
            ORDER BY f.created_at, f.filename
            """,
            new { packageId });
        return rows.ToLookup(f => f.PackageVersionId);
    }

    /// <summary>
    /// One file record within a version by exact filename — the publish-path dedup probe
    /// that decides between "add a new file" and "overwrite the existing one".
    /// </summary>
    public async Task<PackageVersionFile?> GetByVersionAndFilenameAsync(
        string packageVersionId, string filename, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK (org-scoped via the caller's package lookup).
        return await conn.QuerySingleOrDefaultAsync<PackageVersionFile>(
            """
            SELECT id, package_version_id as PackageVersionId, org_id as OrgId, filename,
                   blob_key as BlobKey, size_bytes as SizeBytes,
                   checksum_sha256 as ChecksumSha256, created_at as CreatedAt
            FROM package_version_files
            WHERE package_version_id = @packageVersionId AND filename = @filename
            """,
            new { packageVersionId, filename });
    }

    /// <summary>
    /// Resolves a download request: the file record plus its parent version and package for
    /// the block-gate facts. Filename equality rides idx_package_version_files_org_filename.
    /// </summary>
    public async Task<(Package Package, PackageVersion Version, PackageVersionFile File)?> FindFileWithVersionAsync(
        string orgId, string ecosystem, string filename, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Positional tuple projection (the FindVersionByBlobKeySuffixAsync idiom) — Dapper
        // materialises by column order, so no setter-only DTO type is needed for the join row.
        var (PkgId, PkgOrgId, PkgEcosystem, PkgName, PkgPurlName, PkgIsProxy, PkgCreatedAt,
            VerId, VerPackageId, VerVersion, VerPurl, VerBlobKey, VerSizeBytes, VerChecksumSha256,
            VerYanked, VerYankReason, VerFirstFetch, VerCreatedAt, VerVulnCheckedAt,
            VerManualBlockState, VerDeprecated, VerRevokedAt, VerOrigin, VerPublishedAt,
            VerHasInstallScript,
            FileId, FileName, FileBlobKey, FileSizeBytes, FileChecksumSha256, FileCreatedAt) =
            await conn.QuerySingleOrDefaultAsync<(
            string PkgId, string PkgOrgId, string PkgEcosystem, string PkgName, string PkgPurlName,
            bool PkgIsProxy, string PkgCreatedAt,
            string VerId, string VerPackageId, string VerVersion, string VerPurl, string VerBlobKey,
            long VerSizeBytes, string? VerChecksumSha256, bool VerYanked, string? VerYankReason,
            bool VerFirstFetch, string VerCreatedAt, string? VerVulnCheckedAt,
            string? VerManualBlockState, string? VerDeprecated, string? VerRevokedAt,
            string VerOrigin, string? VerPublishedAt, bool VerHasInstallScript,
            string FileId, string FileName, string FileBlobKey, long FileSizeBytes,
            string? FileChecksumSha256, string FileCreatedAt)>(
            // plane-ok: point lookup by (org, filename) for the hosted multi-file serve (origin='uploaded'); proxy is served from cache_artifact.
            """
            SELECT p.id, p.org_id, p.ecosystem, p.name, p.purl_name, p.is_proxy, p.created_at,
                   pv.id, pv.package_id, pv.version, pv.purl, pv.blob_key, pv.size_bytes,
                   pv.checksum_sha256, pv.yanked, pv.yank_reason, pv.first_fetch,
                   pv.created_at, pv.vuln_checked_at, pv.manual_block_state, pv.deprecated,
                   pv.revoked_at, pv.origin, pv.published_at, pv.has_install_script,
                   f.id, f.filename, f.blob_key, f.size_bytes, f.checksum_sha256, f.created_at
            FROM package_version_files f
            JOIN package_versions pv ON pv.id = f.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE f.org_id = @orgId AND f.filename = @filename AND p.ecosystem = @ecosystem
              AND pv.origin = 'uploaded'
            LIMIT 1
            """,
            new { orgId, ecosystem, filename });

        if (PkgId is null)
        {
            return null;
        }

        var pkg = new Package
        {
            Id = PkgId,
            OrgId = PkgOrgId,
            Ecosystem = PkgEcosystem,
            Name = PkgName,
            PurlName = PkgPurlName,
            IsProxy = PkgIsProxy,
            CreatedAt = DateTimeOffset.Parse(PkgCreatedAt)
        };
        var ver = new PackageVersion
        {
            Id = VerId,
            PackageId = VerPackageId,
            Version = VerVersion,
            Purl = VerPurl,
            BlobKey = VerBlobKey,
            SizeBytes = VerSizeBytes,
            ChecksumSha256 = VerChecksumSha256,
            Yanked = VerYanked,
            YankReason = VerYankReason,
            FirstFetch = VerFirstFetch,
            CreatedAt = DateTimeOffset.Parse(VerCreatedAt),
            VulnCheckedAt = VerVulnCheckedAt is not null ? DateTimeOffset.Parse(VerVulnCheckedAt) : null,
            ManualBlockState = VerManualBlockState,
            Deprecated = VerDeprecated,
            RevokedAt = VerRevokedAt is not null ? DateTimeOffset.Parse(VerRevokedAt) : null,
            Origin = VerOrigin,
            PublishedAt = VerPublishedAt is not null ? DateTimeOffset.Parse(VerPublishedAt) : null,
            HasInstallScript = VerHasInstallScript
        };
        var file = new PackageVersionFile(
            FileId, VerId, PkgOrgId, FileName, FileBlobKey,
            FileSizeBytes, FileChecksumSha256, DateTimeOffset.Parse(FileCreatedAt));
        return (pkg, ver, file);
    }

    /// <summary>
    /// Blob keys of every file of a version — the version-delete path removes each of these
    /// from the registry tier before the row cascade.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetBlobKeysForVersionAsync(
        string packageVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK (org-scoped via the caller's package lookup).
        var keys = await conn.QueryAsync<string>(
            "SELECT blob_key FROM package_version_files WHERE package_version_id = @packageVersionId",
            new { packageVersionId });
        return keys.ToList();
    }

    // Keeps the parent version's size_bytes equal to the SUM of its files so the quota
    // decrement on version delete releases exactly what the per-file publish reservations
    // accumulated, and resets the version's scan state — the file set (or a file's bytes)
    // just changed, so the prior OSV pass no longer describes the release.
    private static async Task RefreshVersionAfterFileChangeAsync(
        System.Data.Common.DbConnection conn, string packageVersionId, string now)
    {
        // xtenant: keyed by version PK (org-scoped via the caller's package lookup).
        await conn.ExecuteAsync(
            """
            UPDATE package_versions
               SET size_bytes = COALESCE(
                   (SELECT SUM(size_bytes) FROM package_version_files
                    WHERE package_version_id = @packageVersionId), size_bytes),
                   vuln_checked_at = NULL,
                   updated_at = @now
             WHERE id = @packageVersionId
            """,
            new { packageVersionId, now });
    }
}

/// <summary>One hosted distribution file of a PyPI package version.</summary>
public sealed record PackageVersionFile(
    string Id,
    string PackageVersionId,
    string OrgId,
    string Filename,
    string BlobKey,
    long SizeBytes,
    string? ChecksumSha256,
    DateTimeOffset CreatedAt);
