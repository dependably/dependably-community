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
    public async Task IndexAsync(
        string orgId, string packageVersionId, string snupkgBlobKey,
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
                    (id, org_id, package_version_id, pdb_filename, ssqp_key, snupkg_blob_key, entry_path, created_at)
                VALUES (@id, @orgId, @packageVersionId, @pdbFilename, @ssqpKey, @snupkgBlobKey, @entryPath, @now)
                ON CONFLICT DO NOTHING
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    packageVersionId,
                    pdbFilename = sym.PdbFileName.ToLowerInvariant(),
                    ssqpKey = sym.SsqpKey.ToLowerInvariant(),
                    snupkgBlobKey,
                    entryPath = sym.EntryPath,
                    now,
                });
        }
    }

    /// <summary>
    /// Resolves an SSQP lookup (filename + key, both matched lowercased) to the stored
    /// <c>.snupkg</c> blob key and the PDB's entry path within it, scoped to <paramref name="orgId"/>.
    /// Returns <see langword="null"/> when the key is not indexed for this tenant.
    /// </summary>
    public async Task<SymbolIndexRow?> ResolveAsync(
        string orgId, string pdbFileName, string ssqpKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QueryFirstOrDefaultAsync<SymbolIndexRow>(
            """
            SELECT snupkg_blob_key AS SnupkgBlobKey, entry_path AS EntryPath
            FROM nuget_symbol_index
            WHERE org_id = @orgId AND pdb_filename = @pdbFilename AND ssqp_key = @ssqpKey
            LIMIT 1
            """,
            new
            {
                orgId,
                pdbFilename = pdbFileName.ToLowerInvariant(),
                ssqpKey = ssqpKey.ToLowerInvariant(),
            });
    }
}

/// <summary>
/// A resolved symbol-index row: the stored <c>.snupkg</c> blob key and the path of the PDB entry
/// within that archive.
/// </summary>
public sealed record SymbolIndexRow(string SnupkgBlobKey, string EntryPath);
