using System.Data.Common;
using System.Globalization;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// Collapses case-variant duplicate <c>project_vuln_analysis</c> rows — two or more rows that
/// <see cref="SbomVulnKeyComparer"/> considers one advisory on one component — down to the single
/// row every reader already resolves to, carrying every fact those rows held.
///
/// <para>The write side no longer produces them: all three writers resolve their conflict key onto
/// the spelling the stored row holds. What this pass exists for is the data already at rest, which
/// nothing else removes — the retraction sweeps match their keep-set through the same comparer and
/// so keep <em>both</em> rows of such a pair, erring toward keeping a fact.</para>
///
/// <para><b>The merge rule.</b> Within a duplicate group the survivor is the row the readers
/// already resolve to: lowest <c>vuln_key</c>, the same <c>ORDER BY vuln_key LIMIT 1</c> the
/// analysis read takes and all three writers resolve their conflict key by. Its <c>vuln_key</c> is
/// kept byte-for-byte — advisory ids are stored verbatim because a GHSA id's suffix is
/// conventionally lowercase while a CVE id is uppercase, and no column is rewritten to one
/// case.</para>
///
/// <para>The two arms move whole, never column by column. The five VEX columns are one statement —
/// a state plus the justification, response and detail that explain it — and the six SARIF columns
/// are one match; taking a state from one row beside a justification from another manufactures an
/// assertion nobody made.</para>
///
/// <para><b>The VEX arm</b> is ranked <c>manual</c> first, then newest <c>updated_at</c>, then
/// survivor. Manual first is the guarantee the writers' <c>vex_source &lt;&gt; 'manual'</c> refusal
/// exists to protect: an operator's decision outranks an uploaded statement wherever the two happen
/// to sit, and a manual arm is never displaced by anything. Ranking the rest by time is sound
/// precisely because <c>updated_at</c> is the VEX arm's own stamp — it names that arm's author —
/// so the newest upload-sourced statement is the one the last document actually asserted.</para>
///
/// <para><b>The SARIF arm</b> is taken from the survivor when the survivor carries one, and
/// otherwise from the first losing row that does. It is deliberately not ranked by time: the row
/// timestamp is documented as <em>not</em> tracking this arm on a manually triaged row, where
/// <c>UpsertSarifBatchAsync</c> leaves it pinned to the triage, so ranking on it would compare a stamp
/// that does not describe the values being compared. With no per-arm stamp to rank by, the pass
/// falls back to the row every reader and writer already resolves to — which is also what keeps the
/// merge additive from an operator's point of view: it fills in the arm the surfaces were missing
/// without changing the arm they were already showing.</para>
///
/// <para><b>Provenance.</b> <c>updated_by</c>/<c>updated_at</c> name the VEX arm's author when a
/// human decided it and the last writing document otherwise. So when the merged VEX arm is manual
/// the stamp is that row's and nothing moves it, and otherwise it is the newest stamp in the group
/// — reproducing exactly the split <c>UpsertSarifBatchAsync</c> expresses as
/// <c>CASE WHEN … = 'manual' THEN &lt;keep&gt; ELSE excluded END</c>, where a document writing the
/// reachability arm of an untriaged row does move the stamp and the same write onto a triaged row
/// does not. The pass never stamps itself: reconciliation records no new decision and no new
/// document, so it reads no clock.</para>
///
/// <para><b>No constraint follows.</b> A case-insensitive UNIQUE would make the invariant
/// structural, but it would also turn the one duplicate-producing race the design tolerates — two
/// Postgres read-committed writes of one advisory in different case, neither snapshot seeing the
/// other's row — from a self-healing pair every reader already treats as one advisory into a
/// constraint violation. The writers name the byte-exact
/// <c>UNIQUE (project_version_id, purl_key, vuln_key)</c> as their conflict target, so a violation
/// of a second, expression-based index is not absorbed by their <c>ON CONFLICT</c> clause at all:
/// it aborts the whole document ingest. This pass converging on every boot is what bounds such a
/// pair's lifetime instead.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    // Runs on every boot rather than through the _applied_migrations ledger, and deliberately so,
    // for the reason the ledger cannot cover: the duplicate-producing race above can still mint a
    // pair at runtime under Postgres, and a one-shot recorded as applied would never revisit it. A
    // convergent pass repairs whatever is there each time the process starts.
    //
    // Cheap on the overwhelmingly common case: one grouped probe returning only the offending
    // (org, version, component) keys, so a database with no duplicates does no row-by-row work,
    // opens no transaction and writes nothing.
    private async Task ReconcileVulnAnalysisCaseVariantsAsync(DbConnection conn)
    {
        // The probe folds case with the same UPPER() the three writers resolve their conflict key
        // with, so it flags exactly the components those writers would now collapse onto one row.
        // Grouping on (project_version_id, purl_key) lets both providers group along the table's
        // own UNIQUE index; org_id is constant per project version and is selected out so the
        // per-scope statements below can be tenant-scoped.
        // xtenant: instance-wide integrity sweep at schema apply; a duplicate pair is per-tenant
        // but the scan that finds one is not, and no tenant context exists at boot.
        var scopes = (await conn.QueryAsync<AnalysisDuplicateScope>(
            """
            SELECT org_id AS OrgId, project_version_id AS ProjectVersionId, purl_key AS PurlKey
            FROM project_vuln_analysis
            GROUP BY org_id, project_version_id, purl_key
            HAVING COUNT(DISTINCT UPPER(vuln_key)) < COUNT(*)
            """)).ToList();

        if (scopes.Count == 0)
        {
            return;
        }

        int collapsed = 0;
        foreach (var scope in scopes)
        {
            collapsed += await ReconcileAnalysisScopeAsync(conn, scope);
        }

        _logger.LogInformation(
            "Collapsed {GroupCount} case-variant duplicate project_vuln_analysis advisory group(s) " +
            "across {ScopeCount} component(s). Each surviving row keeps its stored advisory-id " +
            "spelling and carries both arms of the rows it replaced.",
            collapsed,
            scopes.Count);
    }

    private static async Task<int> ReconcileAnalysisScopeAsync(DbConnection conn, AnalysisDuplicateScope scope)
    {
        var rows = (await conn.QueryAsync<AnalysisMergeRow>(new CommandDefinition(
            """
            SELECT id                AS Id,
                   vuln_key          AS VulnKey,
                   vex_state         AS VexState,
                   vex_justification AS VexJustification,
                   vex_response      AS VexResponse,
                   vex_detail        AS VexDetail,
                   vex_source        AS VexSource,
                   reachability      AS Reachability,
                   confidence        AS Confidence,
                   sarif_suppressed  AS SarifSuppressed,
                   security_severity AS SecuritySeverity,
                   severity_origin   AS SeverityOrigin,
                   fingerprint       AS Fingerprint,
                   updated_by        AS UpdatedBy,
                   updated_at        AS UpdatedAt
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @projectVersionId AND purl_key = @purlKey
            ORDER BY vuln_key, id
            """,
            new { orgId = scope.OrgId, projectVersionId = scope.ProjectVersionId, purlKey = scope.PurlKey })))
            .ToList();

        // Grouped by the readers' own comparer so this pass and every surface agree on what counts
        // as one advisory. LINQ preserves source order for the groups and inside them, so the head
        // of each group is the row ORDER BY vuln_key already made the tenant's.
        var duplicates = rows
            .GroupBy(row => (scope.PurlKey, row.VulnKey), SbomVulnKeyComparer.Instance)
            .Select(group => group.ToList())
            .Where(group => group.Count > 1)
            .ToList();

        if (duplicates.Count == 0)
        {
            return 0;
        }

        await using var dbTx = await conn.BeginTransactionAsync();
        try
        {
            foreach (var group in duplicates)
            {
                foreach (var loser in group.Skip(1))
                {
                    await conn.ExecuteAsync(new CommandDefinition(
                        "DELETE FROM project_vuln_analysis WHERE id = @id AND org_id = @orgId",
                        new { id = loser.Id, orgId = scope.OrgId },
                        dbTx));
                }

                await ApplyMergedAnalysisRowAsync(conn, dbTx, scope.OrgId, MergeAnalysisGroup(group));
            }

            await dbTx.CommitAsync();
        }
        catch
        {
            await dbTx.RollbackAsync();
            throw;
        }

        return duplicates.Count;
    }

    private static Task ApplyMergedAnalysisRowAsync(
        DbConnection conn, DbTransaction dbTx, string orgId, AnalysisMergeRow merged) =>
        conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE project_vuln_analysis SET
                vex_state         = @vexState,
                vex_justification = @vexJustification,
                vex_response      = @vexResponse,
                vex_detail        = @vexDetail,
                vex_source        = @vexSource,
                reachability      = @reachability,
                confidence        = @confidence,
                sarif_suppressed  = @sarifSuppressed,
                security_severity = @securitySeverity,
                severity_origin   = @severityOrigin,
                fingerprint       = @fingerprint,
                updated_by        = @updatedBy,
                updated_at        = @updatedAt
            WHERE id = @id AND org_id = @orgId
            """,
            new
            {
                id = merged.Id,
                orgId,
                vexState = merged.VexState,
                vexJustification = merged.VexJustification,
                vexResponse = merged.VexResponse,
                vexDetail = merged.VexDetail,
                vexSource = merged.VexSource,
                reachability = merged.Reachability,
                confidence = merged.Confidence,
                sarifSuppressed = merged.SarifSuppressed,
                securitySeverity = merged.SecuritySeverity,
                severityOrigin = merged.SeverityOrigin,
                fingerprint = merged.Fingerprint,
                updatedBy = merged.UpdatedBy,
                updatedAt = merged.UpdatedAt,
            },
            dbTx));

    /// <summary>
    /// The merge rule over one duplicate group, survivor first. Pure, so the shape it produces is
    /// decided here and the statement above only stores it.
    /// </summary>
    private static AnalysisMergeRow MergeAnalysisGroup(IReadOnlyList<AnalysisMergeRow> ordered)
    {
        var survivor = ordered[0];

        // OrderByDescending is a stable sort, so rows the two keys cannot separate stay in the
        // caller's survivor-first order and the choice is total.
        var vex = ordered
            .Where(HasVexArm)
            .OrderByDescending(IsManualVexArm)
            .ThenByDescending(StampInstant)
            .FirstOrDefault();
        var sarif = ordered.FirstOrDefault(HasSarifArm);

        // A manual VEX arm's stamp is the human's and no document moves it — the same freeze
        // UpsertSarifBatchAsync applies. Otherwise the stamp names the last document to write any arm of
        // the advisory, which is the newest stamp in the group.
        var provenance = vex is not null && IsManualVexArm(vex)
            ? vex
            : ordered.Aggregate((newest, row) => StampInstant(row) > StampInstant(newest) ? row : newest);

        return new AnalysisMergeRow
        {
            // The survivor's own identity and stored spelling, untouched.
            Id = survivor.Id,
            VulnKey = survivor.VulnKey,
            VexState = vex?.VexState,
            VexJustification = vex?.VexJustification,
            VexResponse = vex?.VexResponse,
            VexDetail = vex?.VexDetail,
            VexSource = vex?.VexSource,
            Reachability = sarif?.Reachability,
            Confidence = sarif?.Confidence,
            SarifSuppressed = sarif?.SarifSuppressed ?? 0,
            SecuritySeverity = sarif?.SecuritySeverity,
            SeverityOrigin = sarif?.SeverityOrigin,
            Fingerprint = sarif?.Fingerprint,
            UpdatedBy = provenance.UpdatedBy,
            UpdatedAt = provenance.UpdatedAt,
        };
    }

    // The same emptiness tests the retraction sweeps apply, so "carries an arm" means one thing
    // across the ingest path and this pass.
    private static bool HasVexArm(AnalysisMergeRow row) =>
        row.VexState is not null || row.VexSource is not null || row.VexJustification is not null
        || row.VexResponse is not null || row.VexDetail is not null;

    private static bool IsManualVexArm(AnalysisMergeRow row) =>
        string.Equals(row.VexSource, "manual", StringComparison.Ordinal);

    private static bool HasSarifArm(AnalysisMergeRow row) =>
        row.Reachability is not null || row.Confidence is not null || row.SarifSuppressed != 0
        || row.SecuritySeverity is not null || row.SeverityOrigin is not null
        || row.Fingerprint is not null;

    // updated_at is canonical ISO-8601 UTC text written at second, millisecond or microsecond
    // precision, so an ordinal string compare ranks a whole-second stamp above a sub-second one in
    // the same second. Parsed instead; an unparseable legacy value sorts oldest rather than winning
    // the comparison by accident.
    private static DateTimeOffset StampInstant(AnalysisMergeRow row) =>
        DateTimeOffset.TryParse(
            row.UpdatedAt,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out var parsed)
            ? parsed
            : DateTimeOffset.MinValue;

    private sealed class AnalysisDuplicateScope
    {
        public string OrgId { get; set; } = "";
        public string ProjectVersionId { get; set; } = "";
        public string PurlKey { get; set; } = "";
    }

    // Not sealed: the purl-key normalization pass reads the same arms plus the scope columns it
    // needs to address a row, and reuses MergeAnalysisGroup so both passes resolve a collision by
    // one rule rather than two.
    private class AnalysisMergeRow
    {
        public string Id { get; set; } = "";
        public string VulnKey { get; set; } = "";
        public string? VexState { get; set; }
        public string? VexJustification { get; set; }
        public string? VexResponse { get; set; }
        public string? VexDetail { get; set; }
        public string? VexSource { get; set; }
        public string? Reachability { get; set; }
        public string? Confidence { get; set; }
        public int SarifSuppressed { get; set; }
        public double? SecuritySeverity { get; set; }
        public string? SeverityOrigin { get; set; }
        public string? Fingerprint { get; set; }
        public string? UpdatedBy { get; set; }
        public string UpdatedAt { get; set; } = "";
    }
}
