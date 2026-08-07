using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Gives <c>nuget_symbol_index</c> the polymorphic owner shape (<c>owner_kind</c> +
/// <c>package_version_id</c> / <c>cache_artifact_id</c>) that
/// <c>package_version_licenses</c> and <c>package_version_vulns</c> already use, so a PROXIED
/// <c>.snupkg</c> — which has a <c>cache_artifact</c> row and no <c>package_versions</c> row — can
/// be indexed alongside hosted ones.
///
/// <para>
/// The additive columns land in <c>RunAdditiveMigrationsAsync</c>; what needs a reshape is
/// <c>package_version_id</c> losing NOT NULL, which SQLite's <c>ALTER</c> cannot do. Postgres does
/// it natively.
/// </para>
/// </summary>
public sealed partial class SchemaInitializer
{
    // Substring present in the invariant CHECK body; used to detect the already-migrated shape
    // from sqlite_master rather than by constraint or autoindex name, which renumber after a
    // recreate and would give false positives.
    private const string SymbolOwnerInvariantSignature =
        "owner_kind = 'package_version' AND package_version_id IS NOT NULL";

    /// <summary>
    /// Seeds <c>symbol_server_url</c> on existing nuget.org upstream rows, which predate the
    /// column. New rows get it from <see cref="NuGetSymbolServers.DefaultFor"/> at insert time.
    ///
    /// <para>
    /// Only the canonical nuget.org API hosts match. A private feed that mirrors nuget.org is not
    /// nuget.org, and guessing its symbol host would send debug-id lookups — which carry the PDB
    /// names of private code — to a third party. Rows that already carry a value are left alone,
    /// so an operator who deliberately cleared one does not get it back on the next boot.
    /// </para>
    /// </summary>
    private static async Task SeedNuGetOrgSymbolServerUrlAsync(DbConnection conn)
    {
        // xtenant: one-shot seed across every tenant's nuget upstream rows; each UPDATE is pinned
        // to the row's own id via the host filter below and carries no cross-tenant read.
        var rows = (await conn.QueryAsync<(string Id, string Url)>(
            """
            SELECT id AS Id, url AS Url
            FROM upstream_registry
            WHERE ecosystem = 'nuget' AND symbol_server_url IS NULL
            """)).ToList();

        foreach (var (id, url) in rows)
        {
            if (NuGetSymbolServers.DefaultFor("nuget", url) is not { } symbolUrl)
            {
                continue;
            }

            // xtenant: one-shot seed keyed by the row's own PK id, read from the whole-instance
            // SELECT above; each UPDATE touches exactly the row it came from.
            await conn.ExecuteAsync(
                "UPDATE upstream_registry SET symbol_server_url = @symbolUrl WHERE id = @id",
                new { id, symbolUrl });
        }
    }

    private Task AddSymbolIndexOwnerInvariantAsync(DbConnection conn) =>
        _db.Provider == DbProvider.Postgres
            ? AddSymbolIndexOwnerInvariantPostgresAsync(conn)
            : AddSymbolIndexOwnerInvariantSqliteAsync(conn);

    private static async Task AddSymbolIndexOwnerInvariantPostgresAsync(DbConnection conn)
    {
        long hasConstraint = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.table_constraints
            WHERE table_name = 'nuget_symbol_index'
              AND constraint_name = 'nuget_symbol_index_owner_invariant_check'
            """);
        if (hasConstraint > 0)
        {
            return;
        }

        await conn.ExecuteAsync("ALTER TABLE nuget_symbol_index ALTER COLUMN package_version_id DROP NOT NULL");
        await conn.ExecuteAsync("""
            ALTER TABLE nuget_symbol_index
            ADD CONSTRAINT nuget_symbol_index_owner_invariant_check CHECK (
                (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                OR
                (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
            )
            """);
        await conn.ExecuteAsync("""
            DROP INDEX IF EXISTS idx_nuget_symbol_index_pv_key;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_nuget_symbol_index_pv_key
                ON nuget_symbol_index (org_id, ssqp_key, pdb_filename, package_version_id)
                WHERE owner_kind = 'package_version';
            CREATE UNIQUE INDEX IF NOT EXISTS idx_nuget_symbol_index_ca_key
                ON nuget_symbol_index (org_id, ssqp_key, pdb_filename, cache_artifact_id)
                WHERE owner_kind = 'cache_artifact';
            """);
    }

    private static async Task AddSymbolIndexOwnerInvariantSqliteAsync(DbConnection conn)
    {
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'nuget_symbol_index'");
        if (sql is not null && sql.Contains(SymbolOwnerInvariantSignature, StringComparison.Ordinal))
        {
            return;
        }

        // Recreate-table reshape: DROP IF EXISTS guards a crash between CREATE and RENAME, the
        // copy carries no WHERE so every row survives (a reshape changes structure, never which
        // rows exist), and FK enforcement is off across the copy so DROP does not cascade-delete
        // rows the RENAME is about to re-parent.
        // xtenant: DDL-only; the copy is a whole-table projection, not a cross-tenant read.
        await WithForeignKeysOffAsync(conn, () => conn.ExecuteAsync("""
            DROP TABLE IF EXISTS nuget_symbol_index_new;
            CREATE TABLE nuget_symbol_index_new (
                id                 TEXT PRIMARY KEY,
                org_id             TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                package_version_id TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                pdb_filename       TEXT NOT NULL,
                ssqp_key           TEXT NOT NULL,
                snupkg_blob_key    TEXT NOT NULL,
                entry_path         TEXT NOT NULL,
                created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                    CHECK (created_at IS NULL
                        OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
                        OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
                        OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
                cache_artifact_id  TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind         TEXT NOT NULL DEFAULT 'package_version'
                                   CHECK (owner_kind IN ('package_version','cache_artifact')),
                CHECK (
                    (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                    OR
                    (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
                )
            );
            INSERT INTO nuget_symbol_index_new
                (id, org_id, package_version_id, pdb_filename, ssqp_key, snupkg_blob_key,
                 entry_path, created_at, cache_artifact_id, owner_kind)
            SELECT id, org_id, package_version_id, pdb_filename, ssqp_key, snupkg_blob_key,
                   entry_path, created_at, cache_artifact_id, owner_kind
            FROM nuget_symbol_index;
            DROP TABLE nuget_symbol_index;
            ALTER TABLE nuget_symbol_index_new RENAME TO nuget_symbol_index;
            CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_lookup
                ON nuget_symbol_index (org_id, ssqp_key, pdb_filename);
            CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_pv
                ON nuget_symbol_index (package_version_id);
            CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_ca
                ON nuget_symbol_index (cache_artifact_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_nuget_symbol_index_pv_key
                ON nuget_symbol_index (org_id, ssqp_key, pdb_filename, package_version_id)
                WHERE owner_kind = 'package_version';
            CREATE UNIQUE INDEX IF NOT EXISTS idx_nuget_symbol_index_ca_key
                ON nuget_symbol_index (org_id, ssqp_key, pdb_filename, cache_artifact_id)
                WHERE owner_kind = 'cache_artifact';
            """));
    }
}
