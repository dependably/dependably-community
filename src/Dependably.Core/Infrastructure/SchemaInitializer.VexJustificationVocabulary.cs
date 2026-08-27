using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Rewrites <c>project_vuln_analysis.vex_justification</c> values spelled
/// <c>protected_by_perimeter</c> onto <c>protected_at_perimeter</c>, the value CycloneDX defines.
///
/// <para>The column is a closed vocabulary with no CHECK behind it, so a spelling outside the
/// specification stores cleanly and only fails much later, in two places a reader cannot connect
/// back to the write: the CycloneDX export renders a document no consumer validates, and
/// <see cref="Sbom.VexVocabulary.NormalizeJustification"/> drops the value on the way back in, so
/// re-uploading that export silently discards the operator's justification.</para>
///
/// <para>Convergent rather than ledgered, and for the blue-green reason: a slot of the previous
/// release serving against this database still admits the retired spelling from its own triage
/// editor, so a one-shot recorded as applied would leave rows written during the cutover window
/// permanently wrong. Repeating the rewrite on every boot is what makes the column converge on
/// the vocabulary. It is a single statement against one indexed-by-nothing column, on a table the
/// analysis reconciliation pass beside it already scans once per boot.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    /// <summary>The value CycloneDX does not define, and the one it does.</summary>
    private const string RetiredPerimeterJustification = "protected_by_perimeter";
    private const string CycloneDxPerimeterJustification = "protected_at_perimeter";

    private async Task NormalizeVexJustificationVocabularyAsync(DbConnection conn)
    {
        // xtenant: instance-wide vocabulary repair at schema apply; the rows are per-tenant but
        // the pass that finds them is not, and no tenant context exists at boot.
        int rewritten = await conn.ExecuteAsync(
            """
            UPDATE project_vuln_analysis
            SET vex_justification = @canonical
            WHERE vex_justification = @retired
            """,
            new { canonical = CycloneDxPerimeterJustification, retired = RetiredPerimeterJustification });

        if (rewritten > 0)
        {
            _logger.LogInformation(
                "Rewrote {Rewritten} project_vuln_analysis row(s) carrying the non-CycloneDX " +
                "justification '{Retired}' onto '{Canonical}'.",
                rewritten,
                RetiredPerimeterJustification,
                CycloneDxPerimeterJustification);
        }
    }
}
