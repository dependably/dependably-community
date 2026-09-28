using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

// Converges upstream_credential_history from the upstream rows present now and from the audit
// trail of upstreams added in the past.
public sealed partial class SchemaInitializer
{
    /// <summary>
    /// How far back the every-boot pass reads <c>upstream_registry_added</c> audit events. It only
    /// has to cover a blue-green cutover, during which the previous release adds upstreams without
    /// recording them; the full audit trail is read once, by
    /// <see cref="BackfillUpstreamCredentialHistoryFromAuditAsync"/>.
    /// </summary>
    internal const int UpstreamCredentialAuditLookbackDays = 30;

    /// <summary>
    /// Records an <c>upstream_credential_history</c> row for every (org, ecosystem) that has an
    /// upstream carrying a credential right now, by the rule the lookup applies
    /// (<see cref="UpstreamRegistryRepository.IsCredentialFree"/>), and for every credentialed
    /// upstream added in the last <see cref="UpstreamCredentialAuditLookbackDays"/> days according
    /// to the audit log, which also finds one that has since been deleted.
    ///
    /// <para>
    /// Deliberately not a ledgered one-shot. During a blue-green cutover the previous release keeps
    /// serving against this database and writes credentialed upstreams without recording them; a
    /// pass that ran once at this release's first boot would miss every one of those, including
    /// one added and deleted inside the window. Running on every boot picks them up at the next
    /// boot of either slot. It only inserts, so it can never make an org public again.
    /// </para>
    /// </summary>
    private async Task ConvergeUpstreamCredentialHistoryAsync(DbConnection conn)
    {
        // xtenant: instance-wide convergence at startup; each history row is written for the
        // org_id of the upstream row it was derived from. HasSecret is read as an integer so the
        // mapping is the same on both providers.
        var rows = await conn.QueryAsync<(string OrgId, string Ecosystem, string? AuthType, string? Username, int HasSecret, string? Url)>(
            """
            SELECT org_id, ecosystem, auth_type, username,
                   CASE WHEN secret IS NOT NULL THEN 1 ELSE 0 END, url
            FROM upstream_registry
            """);

        foreach (var (orgId, ecosystem) in rows
            .Where(r => !UpstreamRegistryRepository.IsCredentialFree(r.AuthType, r.Username, r.HasSecret != 0, r.Url))
            .Select(r => (r.OrgId, r.Ecosystem))
            .Distinct())
        {
            await UpstreamRegistryRepository.RecordCredentialedAsync(conn, orgId, ecosystem);
        }

        string since = _time.GetUtcNow().AddDays(-UpstreamCredentialAuditLookbackDays).ToUtcIso();
        await RecordCredentialedFromAuditAsync(conn, since);
    }

    /// <summary>
    /// One-shot: records every credentialed upstream the whole retained audit log shows was ever
    /// added, so an upstream deleted before the history table existed still keeps its org private.
    /// Audit rows past retention, and rows whose detail retention or member erasure has nulled,
    /// say nothing about the upstream and are not used.
    /// </summary>
    private Task BackfillUpstreamCredentialHistoryFromAuditAsync(DbConnection conn)
        => RecordCredentialedFromAuditAsync(conn, since: "");

    /// <summary>
    /// Reads <c>upstream_registry_added</c> events at or after <paramref name="since"/> (an ISO
    /// timestamp; empty reads them all) for orgs that still exist, and records each one
    /// <see cref="UpstreamRegistryRepository.CredentialedEcosystemFromAuditedAdd"/> classifies as
    /// credentialed.
    /// </summary>
    private static async Task RecordCredentialedFromAuditAsync(DbConnection conn, string since)
    {
        // xtenant: instance-wide backfill at startup; each history row is written for the org_id
        // of the audit row it was derived from, and only for an org that still exists (audit_log
        // keeps rows for deleted orgs, and the history row references orgs).
        var events = await conn.QueryAsync<(string OrgId, string? Ecosystem, string? Detail)>(
            """
            SELECT a.org_id, a.ecosystem, a.detail
            FROM audit_log a
            WHERE a.action = 'upstream_registry_added'
              AND a.org_id IS NOT NULL
              AND a.created_at >= @since
              AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = a.org_id)
            """,
            new { since });

        foreach (var (orgId, ecosystem) in events
            .Select(e => (e.OrgId, Ecosystem: UpstreamRegistryRepository.CredentialedEcosystemFromAuditedAdd(e.Detail, e.Ecosystem)))
            .Where(e => e.Ecosystem is not null)
            .Distinct())
        {
            await UpstreamRegistryRepository.RecordCredentialedAsync(conn, orgId, ecosystem!);
        }
    }
}
