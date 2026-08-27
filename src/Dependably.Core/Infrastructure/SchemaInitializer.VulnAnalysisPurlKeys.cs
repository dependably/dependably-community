using System.Data.Common;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// Rewrites stored <c>project_vuln_analysis.purl_key</c> values onto the canonical form
/// <see cref="SbomPurlKey"/> derives, so a row addresses the component every reader addresses.
///
/// <para><c>purl_key</c> has exactly one derivation — <c>%40</c> decoded, then folded for its
/// ecosystem — and the manual-triage endpoint stores the caller's own spelling only after running
/// it through that derivation. Rows written before it did are keyed on whatever the client sent:
/// <c>pkg:pypi/My_Package</c> against a reader deriving <c>pkg:pypi/my-package</c>. The evaluator
/// never finds them, so the suppression an operator recorded goes on not applying and its alert
/// goes on firing — silently, because the row is present and the editor renders it as saved. The
/// write side is fixed; only these rows are not, and nothing else rewrites them.</para>
///
/// <para>Convergent rather than ledgered, for the blue-green reason its sibling passes give: a
/// slot of the previous release serving against this database still writes the caller's verbatim
/// spelling, so a one-shot recorded as applied would leave every row written during the cutover
/// window permanently unfindable. A distinct-key probe makes the pass free on a database that
/// holds none — the scan returns component keys, not rows, and does no row-level work unless one
/// of them is non-canonical.</para>
///
/// <para><b>Collisions.</b> Folding a key can land it on a row that already exists, which the
/// byte-exact <c>UNIQUE (project_version_id, purl_key, vuln_key)</c> refuses. The merge rule is
/// the one <c>ReconcileVulnAnalysisCaseVariantsAsync</c> established and this pass reuses rather
/// than restates: the survivor is the row readers already resolve to — here the row already
/// carrying the canonical key — and within the group the VEX arm is ranked manual first, then
/// newest <c>updated_at</c>, then survivor, with the SARIF arm taken from the survivor when it
/// carries one. Manual first is the point: an operator's decision is exactly what these rows
/// hold, and it must outrank an uploaded statement wherever the fold happens to put the two.
/// Both arms move whole, so no row ends up asserting a combination nobody made.</para>
///
/// <para>Runs before the case-variant reconciliation, so a row this pass merges onto a canonical
/// key is available for that pass to collapse against a case variant in the same boot rather than
/// waiting for the next one.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    private async Task NormalizeVulnAnalysisPurlKeysAsync(DbConnection conn)
    {
        // Distinct component keys, not rows: a database whose keys are all canonical does one
        // scan returning a handful of strings and stops. The canonical form is a C# derivation
        // with no SQL equivalent, so the filtering happens here rather than in the predicate.
        // Streamed rather than buffered: a healthy database rewrites nothing, and materializing
        // every distinct key first would make the no-op case cost memory proportional to the
        // whole corpus on every boot. Same reason TimestampNormalization streams its backlog.
        //
        // A key that is not purl-shaped is left alone: an analysis row that matched no component
        // legitimately keys on a scanner's rule id, and folding that would break the only key it
        // has.
        var rewrites = new Dictionary<string, string>(StringComparer.Ordinal);

        // xtenant: instance-wide integrity sweep at schema apply; the rows are per-tenant but the
        // scan that finds them is not, and no tenant context exists at boot.
        await foreach (string stored in conn.QueryUnbufferedAsync<string>(
            "SELECT DISTINCT purl_key FROM project_vuln_analysis"))
        {
            string? canonical = SbomPurlKey.TryParse(stored)?.Key;
            if (canonical is not null && !string.Equals(canonical, stored, StringComparison.Ordinal))
            {
                rewrites[stored] = canonical;
            }
        }

        if (rewrites.Count == 0)
        {
            return;
        }

        int rewritten = 0;
        int merged = 0;
        foreach (var (stale, canonical) in rewrites.OrderBy(r => r.Key, StringComparer.Ordinal))
        {
            var (keyRewritten, keyMerged) = await NormalizeOnePurlKeyAsync(conn, stale, canonical);
            rewritten += keyRewritten;
            merged += keyMerged;
        }

        _logger.LogInformation(
            "Rewrote {Rewritten} project_vuln_analysis row(s) onto the canonical purl_key their " +
            "readers derive, across {KeyCount} component key(s); {Merged} landed on a row that " +
            "already held the canonical key and were merged into it, manual triage first.",
            rewritten,
            rewrites.Count,
            merged);
    }

    private static async Task<(int Rewritten, int Merged)> NormalizeOnePurlKeyAsync(
        DbConnection conn, string stale, string canonical)
    {
        // Both spellings in one read, so a collision is decided from the rows themselves rather
        // than from a failed insert. UNIQUE (project_version_id, purl_key, vuln_key) bounds each
        // group at one row per spelling.
        // xtenant: same instance-wide sweep; every statement below is scoped by the row's own
        // org_id, which is read here.
        var rows = (await conn.QueryAsync<PurlKeyMergeRow>(new CommandDefinition(
            """
            SELECT id                 AS Id,
                   org_id             AS OrgId,
                   project_version_id AS ProjectVersionId,
                   purl_key           AS PurlKey,
                   vuln_key           AS VulnKey,
                   vex_state          AS VexState,
                   vex_justification  AS VexJustification,
                   vex_response       AS VexResponse,
                   vex_detail         AS VexDetail,
                   vex_source         AS VexSource,
                   reachability       AS Reachability,
                   confidence         AS Confidence,
                   sarif_suppressed   AS SarifSuppressed,
                   security_severity  AS SecuritySeverity,
                   severity_origin    AS SeverityOrigin,
                   fingerprint        AS Fingerprint,
                   updated_by         AS UpdatedBy,
                   updated_at         AS UpdatedAt
            FROM project_vuln_analysis
            WHERE purl_key = @stale OR purl_key = @canonical
            ORDER BY id
            """,
            new { stale, canonical }))).ToList();

        int rewritten = 0;
        int merged = 0;

        await using var dbTx = await conn.BeginTransactionAsync();
        try
        {
            var groups = rows.GroupBy(
                r => (r.OrgId, r.ProjectVersionId, r.VulnKey),
                StringTripleComparer.Instance);

            foreach (var group in groups)
            {
                var staleRow = group.FirstOrDefault(
                    r => string.Equals(r.PurlKey, stale, StringComparison.Ordinal));
                if (staleRow is null)
                {
                    continue;
                }

                var canonicalRow = group.FirstOrDefault(
                    r => string.Equals(r.PurlKey, canonical, StringComparison.Ordinal));

                if (canonicalRow is null)
                {
                    await RewritePurlKeyAsync(conn, dbTx, staleRow.OrgId, staleRow.Id, canonical);
                    rewritten++;
                    continue;
                }

                // Survivor first, which is the row already carrying the key readers derive.
                var ordered = new List<AnalysisMergeRow> { canonicalRow, staleRow };
                await conn.ExecuteAsync(new CommandDefinition(
                    "DELETE FROM project_vuln_analysis WHERE id = @id AND org_id = @orgId",
                    new { id = staleRow.Id, orgId = staleRow.OrgId },
                    dbTx));
                await ApplyMergedAnalysisRowAsync(
                    conn, dbTx, canonicalRow.OrgId, MergeAnalysisGroup(ordered));
                merged++;
            }

            await dbTx.CommitAsync();
        }
        catch
        {
            await dbTx.RollbackAsync();
            throw;
        }

        return (rewritten, merged);
    }

    private static Task RewritePurlKeyAsync(
        DbConnection conn, DbTransaction dbTx, string orgId, string id, string canonical) =>
        conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE project_vuln_analysis SET purl_key = @canonical
            WHERE id = @id AND org_id = @orgId
            """,
            new { canonical, id, orgId },
            dbTx));

    /// <summary>
    /// The merge row plus the three columns needed to address it. A subclass rather than three
    /// more properties on the base, so the case-variant pass's own row shape stays exactly what
    /// its query selects.
    /// </summary>
    private sealed class PurlKeyMergeRow : AnalysisMergeRow
    {
        public string OrgId { get; set; } = "";
        public string ProjectVersionId { get; set; } = "";
        public string PurlKey { get; set; } = "";
    }

    /// <summary>Ordinal equality over the three-part group key, so grouping never folds case.</summary>
    private sealed class StringTripleComparer : IEqualityComparer<(string, string, string)>
    {
        public static readonly StringTripleComparer Instance = new();

        public bool Equals((string, string, string) x, (string, string, string) y) =>
            string.Equals(x.Item1, y.Item1, StringComparison.Ordinal)
            && string.Equals(x.Item2, y.Item2, StringComparison.Ordinal)
            && string.Equals(x.Item3, y.Item3, StringComparison.Ordinal);

        public int GetHashCode((string, string, string) obj) =>
            HashCode.Combine(
                StringComparer.Ordinal.GetHashCode(obj.Item1),
                StringComparer.Ordinal.GetHashCode(obj.Item2),
                StringComparer.Ordinal.GetHashCode(obj.Item3));
    }
}
