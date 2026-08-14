using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Makes stored account emails agree with how every lookup reads them.
///
/// <para>Account resolution folds case everywhere (<c>WHERE lower(email) = lower(@email)</c>) while
/// <c>UNIQUE (tenant_id, email)</c> and <c>system_admins.email UNIQUE</c> compare bytes. Writes are
/// canonicalized by <see cref="EmailNormalizer"/>; this pass canonicalizes what is already stored
/// and installs the matching case-insensitive unique index, so a second account differing only in
/// case cannot be created by a writer that forgets.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    // Runs on every boot rather than through the _applied_migrations ledger, and deliberately so: a
    // database that already holds case-variant duplicates cannot take the unique index, and a
    // one-shot would record itself as applied on that boot and never install the index once the
    // operator resolved the collision. Every statement here is idempotent, and the duplicate probe
    // is a grouped scan of a table with one row per human — cheap enough to pay at every start.
    //
    // Detect-then-act, in that order and never the reverse: two rows folding to one address both
    // fail the lowercase rewrite (they would collide on the byte-exact UNIQUE) and fail the index
    // creation, and an exception here aborts the rest of schema init — which on SQLite means the
    // remaining statements of a multi-statement batch are silently skipped. So a collision is
    // reported and enforcement is deferred to a later boot: the deployment keeps serving, both
    // accounts keep working exactly as they did, and nothing new can be created in that shape
    // because the write path already canonicalizes.
    private async Task EnsureEmailCaseInsensitiveUniquenessAsync(DbConnection conn)
    {
        await CanonicalizeTenantUserEmailsAsync(conn);
        await CanonicalizeSystemAdminEmailsAsync(conn);
    }

    private async Task CanonicalizeTenantUserEmailsAsync(DbConnection conn)
    {
        // lower() is SQL's own — the same function every account lookup folds with — so the
        // constraint and the lookups agree by construction on each provider.
        // xtenant: instance-wide integrity sweep; a collision is per-tenant but the scan is not.
        var collisionScopes = (await conn.QueryAsync<string>(
            """
            SELECT tenant_id FROM users
            GROUP BY tenant_id, lower(email)
            HAVING COUNT(*) > 1
            """)).ToList();

        if (collisionScopes.Count > 0)
        {
            // Addresses are personal data and are never logged; the tenant ids and the count are
            // what an operator needs to find the rows, and the query is spelled out for them.
            _logger.LogError(
                "Case-insensitive email uniqueness cannot be enforced on users: {GroupCount} " +
                "address(es) exist as more than one account row differing only in case, in " +
                "tenant(s) {Tenants}. Both rows satisfy every account lookup, so which one " +
                "authenticates for that address is not determined by the address. Resolve them " +
                "(delete or re-address the duplicate) and restart; until then the unique index is " +
                "not installed. Find them with: SELECT tenant_id, lower(email), COUNT(*) FROM " +
                "users GROUP BY tenant_id, lower(email) HAVING COUNT(*) > 1",
                collisionScopes.Count,
                string.Join(", ", collisionScopes.Distinct()));
            return;
        }

        // No two rows fold to one address, so lowercasing every row cannot collide on the existing
        // byte-exact UNIQUE.
        // xtenant: instance-wide canonicalization of stored values; identity-preserving.
        await conn.ExecuteAsync("UPDATE users SET email = lower(email) WHERE email <> lower(email)");

        // xtenant: DDL, not a row query.
        await conn.ExecuteAsync(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_ci ON users (tenant_id, lower(email))");
    }

    private async Task CanonicalizeSystemAdminEmailsAsync(DbConnection conn)
    {
        // xtenant: operator-plane table, no tenant column by design.
        int collisions = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM (
                SELECT lower(email) FROM system_admins
                GROUP BY lower(email) HAVING COUNT(*) > 1
            ) dupes
            """);

        if (collisions > 0)
        {
            _logger.LogError(
                "Case-insensitive email uniqueness cannot be enforced on system_admins: " +
                "{GroupCount} address(es) exist as more than one operator row differing only in " +
                "case. Resolve them and restart; until then the unique index is not installed. " +
                "Find them with: SELECT lower(email), COUNT(*) FROM system_admins GROUP BY " +
                "lower(email) HAVING COUNT(*) > 1",
                collisions);
            return;
        }

        // xtenant: operator-plane table, no tenant column by design.
        await conn.ExecuteAsync(
            "UPDATE system_admins SET email = lower(email) WHERE email <> lower(email)");

        // xtenant: DDL, not a row query.
        await conn.ExecuteAsync(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_system_admins_email_ci ON system_admins (lower(email))");
    }
}
