using System.Data.Common;
using Dapper;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// The in-transaction check every credential mint (personal access token, service token, invite,
/// password-reset link, email-change link, remembered device) runs before its INSERT, so a mint
/// that is in flight when the tenant is suspended cannot commit a credential after the
/// suspension's revoke has already run.
///
/// <para>
/// <see cref="TenantStatusEnforcementMiddleware"/> checks the tenant's status once, at the start
/// of the request; the mint commits some time later. In between, <c>OrgRepository.UpdateOrgStatusAsync</c>
/// can lock the org row, delete every credential, and commit. Without this gate the late INSERT
/// lands after that delete and is revived when the tenant is restored. On Postgres the gate reads
/// the org row <c>FOR SHARE</c>: it conflicts with the lifecycle write's <c>FOR UPDATE</c>, so the
/// mint either commits first (and the lifecycle write then deletes its credential) or waits for
/// the status write to commit and then reads the new status and refuses. SQLite needs no row
/// lock: the mint's transaction begins <c>IMMEDIATE</c>, which already serializes it against the
/// lifecycle write.
/// </para>
///
/// <para>
/// <c>read_only</c> still mints, matching the middleware (its members keep using the management
/// plane). A missing or soft-deleted tenant refuses as <see cref="TenantNotReadyReason.NotFound"/>.
/// The refusal is a <see cref="TenantNotReadyException"/>, which
/// <see cref="TenantNotReadyExceptionMiddleware"/> answers the way the status middleware answers
/// a locked-out tenant.
/// </para>
/// </summary>
public static class TenantMintGate
{
    /// <summary>
    /// Throws <see cref="TenantNotReadyException"/> unless <paramref name="orgId"/> is a live
    /// tenant outside a lockout status. Must run inside the minting transaction, before the INSERT.
    /// </summary>
    public static async Task RequireMintableAsync(
        DbConnection conn, DbProvider provider, string orgId, DbTransaction? tx, CancellationToken ct)
    {
        // The orgs row is keyed by its own id, which is the tenant being checked.
        string status = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            provider == DbProvider.Postgres
                ? "SELECT status FROM orgs WHERE id = @orgId AND deleted_at IS NULL FOR SHARE"
                : "SELECT status FROM orgs WHERE id = @orgId AND deleted_at IS NULL",
            new { orgId }, transaction: tx, cancellationToken: ct))
            ?? throw new TenantNotReadyException(orgId, TenantNotReadyReason.NotFound, "tenant not found");

        if (OrgRepository.IsLockoutStatus(status))
        {
            throw new TenantNotReadyException(orgId, TenantNotReadyReason.StatusInactive, $"status='{status}'");
        }
    }
}
