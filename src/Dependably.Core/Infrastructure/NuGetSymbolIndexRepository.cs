using Dapper;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Persists and resolves the NuGet symbol-server (SSQP) index: a per-org map from a Portable-PDB
/// debug-id key to the exact PDB entry inside a stored <c>.snupkg</c>. Populated on symbol push so
/// a debugger request <c>GET /nuget/symbols/{pdb}/{key}/{pdb}</c> resolves without scanning every
/// symbol package. Keys and filenames are stored lowercased and matched case-insensitively, per the
/// SSQP protocol (clients normalize to lowercase). Every query is tenant-scoped on <c>org_id</c>.
/// </summary>
public sealed class NuGetSymbolIndexRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public NuGetSymbolIndexRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Indexes every extracted PDB of a pushed symbol package. Each row binds the PDB's SSQP key
    /// and filename to the stored <c>.snupkg</c> blob key and the PDB's path within that archive.
    /// Idempotent per (org, key, filename, version) via <c>ON CONFLICT DO NOTHING</c>, so a
    /// re-push of the same coordinate does not duplicate rows.
    /// </summary>
    public Task IndexAsync(
        string orgId, string packageVersionId, string snupkgBlobKey,
        IReadOnlyList<PdbSymbol> symbols, CancellationToken ct = default)
        => IndexOwnedAsync(orgId, SymbolOwner.ForPackageVersion(packageVersionId), snupkgBlobKey, symbols, ct);

    /// <summary>
    /// Indexes every extracted PDB against an owner that is either a hosted
    /// <c>package_versions</c> row or a proxied <c>cache_artifact</c> row. Exactly one of the two
    /// FKs is written, which is what the table's invariant CHECK requires.
    /// </summary>
    public async Task IndexOwnedAsync(
        string orgId, SymbolOwner owner, string snupkgBlobKey,
        IReadOnlyList<PdbSymbol> symbols, CancellationToken ct = default)
    {
        if (symbols.Count == 0)
        {
            return;
        }

        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        foreach (var sym in symbols)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO nuget_symbol_index
                    (id, org_id, package_version_id, cache_artifact_id, owner_kind,
                     pdb_filename, ssqp_key, snupkg_blob_key, entry_path, created_at)
                VALUES (@id, @orgId, @packageVersionId, @cacheArtifactId, @ownerKind,
                        @pdbFilename, @ssqpKey, @snupkgBlobKey, @entryPath, @now)
                ON CONFLICT DO NOTHING
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    packageVersionId = owner.PackageVersionId,
                    cacheArtifactId = owner.CacheArtifactId,
                    ownerKind = owner.Kind,
                    pdbFilename = sym.PdbFileName.ToLowerInvariant(),
                    ssqpKey = sym.SsqpKey.ToLowerInvariant(),
                    snupkgBlobKey,
                    entryPath = sym.EntryPath,
                    now,
                });
        }
    }

    /// <summary>
    /// Indexed-PDB counts for a batch of versions, keyed by <c>package_version_id</c>. A version
    /// with no indexed PDB is absent from the result rather than present with zero. One query per
    /// page: the package-detail view renders every version at once, so a per-row lookup would be
    /// N+1 against one of the hottest management reads.
    /// </summary>
    public async Task<Dictionary<string, int>> CountByVersionsAsync(
        string orgId, IReadOnlyList<string> packageVersionIds, CancellationToken ct = default)
    {
        if (packageVersionIds.Count == 0)
        {
            return [];
        }

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string PackageVersionId, int Count)>(
            """
            SELECT package_version_id, COUNT(*)
            FROM nuget_symbol_index
            WHERE org_id = @orgId AND package_version_id IN @packageVersionIds
            GROUP BY package_version_id
            """,
            new { orgId, packageVersionIds });
        return rows.ToDictionary(r => r.PackageVersionId, r => r.Count);
    }

    /// <summary>
    /// Removes every index row for one version, so a re-index rebuilds rather than accumulates.
    /// The version id alone would be sufficient, but filtering on <paramref name="orgId"/> too
    /// keeps a mis-plumbed caller from reaching another tenant's rows.
    /// </summary>
    public async Task DeleteForVersionAsync(
        string orgId, string packageVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM nuget_symbol_index WHERE org_id = @orgId AND package_version_id = @packageVersionId",
            new { orgId, packageVersionId });
    }

    /// <summary>
    /// Deletes a version's existing index rows and re-inserts <paramref name="symbols"/> as a
    /// single unit — one connection, one transaction. A rebuild is a delete-then-insert by
    /// nature (idempotent insert alone cannot repair a stale <c>snupkg_blob_key</c>), so a
    /// failure partway through (SQLITE_BUSY, a dropped connection, a cancelled request) must
    /// roll back to the version's previous index rather than leaving it partially populated or
    /// empty where a complete index existed before the rebuild started.
    /// </summary>
    public async Task ReplaceForVersionAsync(
        string orgId, string packageVersionId, string snupkgBlobKey,
        IReadOnlyList<PdbSymbol> symbols, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        await conn.ExecuteAsync(
            "DELETE FROM nuget_symbol_index WHERE org_id = @orgId AND package_version_id = @packageVersionId",
            new { orgId, packageVersionId },
            transaction: tx);

        foreach (var sym in symbols)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO nuget_symbol_index
                    (id, org_id, package_version_id, cache_artifact_id, owner_kind,
                     pdb_filename, ssqp_key, snupkg_blob_key, entry_path, created_at)
                VALUES (@id, @orgId, @packageVersionId, NULL, @ownerKind,
                        @pdbFilename, @ssqpKey, @snupkgBlobKey, @entryPath, @now)
                ON CONFLICT DO NOTHING
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    packageVersionId,
                    ownerKind = SymbolOwner.PackageVersion,
                    pdbFilename = sym.PdbFileName.ToLowerInvariant(),
                    ssqpKey = sym.SsqpKey.ToLowerInvariant(),
                    snupkgBlobKey,
                    entryPath = sym.EntryPath,
                    now,
                },
                transaction: tx);
        }

        await tx.CommitAsync(ct);
    }

    /// <summary>
    /// Resolves an SSQP lookup (filename + key, both matched lowercased) to the stored
    /// <c>.snupkg</c> blob key, the PDB's entry path within it, and the OWNING
    /// <c>package_versions</c> row, scoped to <paramref name="orgId"/>. Returns
    /// <see langword="null"/> when the key is not indexed for this tenant.
    ///
    /// <para>
    /// The version row travels with the lookup because serving a PDB is a serve decision like any
    /// other: the caller runs the block gate on it before streaming bytes. Projecting it here
    /// rather than issuing a second query by <c>package_version_id</c> keeps the SSQP hot path at
    /// one round trip.
    /// </para>
    /// </summary>
    public async Task<SymbolIndexRow?> ResolveAsync(
        string orgId, string pdbFileName, string ssqpKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Positional tuple projection (the FindFileWithVersionAsync idiom) — Dapper materialises
        // by column order, so the join row needs no setter-only DTO.
        var (SnupkgBlobKey, EntryPath,
            VerId, VerPackageId, VerVersion, VerPurl, VerBlobKey, VerSizeBytes, VerChecksumSha256,
            VerYanked, VerYankReason, VerFirstFetch, VerCreatedAt, VerVulnCheckedAt,
            VerManualBlockState, VerDeprecated, VerRevokedAt, VerOrigin, VerPublishedAt,
            VerHasInstallScript, VerInstallScriptKind, VerProvenanceStatus, CacheArtifactId) =
            await conn.QueryFirstOrDefaultAsync<(
            string SnupkgBlobKey, string EntryPath,
            string VerId, string VerPackageId, string VerVersion, string VerPurl, string VerBlobKey,
            long VerSizeBytes, string? VerChecksumSha256, bool VerYanked, string? VerYankReason,
            bool VerFirstFetch, string VerCreatedAt, string? VerVulnCheckedAt,
            string? VerManualBlockState, string? VerDeprecated, string? VerRevokedAt,
            string VerOrigin, string? VerPublishedAt, bool VerHasInstallScript,
            string? VerInstallScriptKind, string? VerProvenanceStatus, string? CacheArtifactId)>(
            // plane-ok: LEFT JOIN so a proxy-owned row (cache_artifact plane) resolves too; the
            // caller reads its serve facts by cache_artifact_id and gates on those instead.
            """
            SELECT si.snupkg_blob_key, si.entry_path,
                   pv.id, pv.package_id, pv.version, pv.purl, pv.blob_key, pv.size_bytes,
                   pv.checksum_sha256, pv.yanked, pv.yank_reason, pv.first_fetch,
                   pv.created_at, pv.vuln_checked_at, pv.manual_block_state, pv.deprecated,
                   pv.revoked_at, pv.origin, pv.published_at, pv.has_install_script,
                   pv.install_script_kind, pv.provenance_status, si.cache_artifact_id
            FROM nuget_symbol_index si
            LEFT JOIN package_versions pv ON pv.id = si.package_version_id
            WHERE si.org_id = @orgId AND si.pdb_filename = @pdbFilename AND si.ssqp_key = @ssqpKey
            LIMIT 1
            """,
            new
            {
                orgId,
                pdbFilename = pdbFileName.ToLowerInvariant(),
                ssqpKey = ssqpKey.ToLowerInvariant(),
            });

        if (SnupkgBlobKey is null)
        {
            return null;
        }

        // Proxy-owned rows carry no version row; the caller gates them on the cache artifact's
        // serve facts instead.
        return VerId is null
            ? new SymbolIndexRow(SnupkgBlobKey, EntryPath, null, CacheArtifactId)
            : new SymbolIndexRow(
                SnupkgBlobKey,
                EntryPath,
                new PackageVersion
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
                    HasInstallScript = VerHasInstallScript,
                    InstallScriptKind = VerInstallScriptKind,
                    ProvenanceStatus = VerProvenanceStatus,
                });
    }
}

/// <summary>
/// Which row owns a symbol-index entry. A hosted <c>.snupkg</c> is owned by its
/// <c>package_versions</c> row; a proxied one by the <c>cache_artifact</c> row holding the fetched
/// archive. Exactly one id is ever set, mirroring the table's invariant CHECK.
/// </summary>
public sealed record SymbolOwner(string Kind, string? PackageVersionId, string? CacheArtifactId)
{
    public const string PackageVersion = "package_version";
    public const string CacheArtifact = "cache_artifact";

    public static SymbolOwner ForPackageVersion(string packageVersionId) =>
        new(PackageVersion, packageVersionId, null);

    public static SymbolOwner ForCacheArtifact(string cacheArtifactId) =>
        new(CacheArtifact, null, cacheArtifactId);
}

/// <summary>
/// A resolved symbol-index row: the stored <c>.snupkg</c> blob key, the path of the PDB entry
/// within that archive, and the facts the block gate evaluates before the PDB is served — either
/// the owning hosted <c>package_versions</c> row, or the proxied artifact's serve facts. Exactly
/// one is non-null, following the row's owner_kind.
/// </summary>
public sealed record SymbolIndexRow(
    string SnupkgBlobKey,
    string EntryPath,
    PackageVersion? Version,
    string? CacheArtifactId = null);
