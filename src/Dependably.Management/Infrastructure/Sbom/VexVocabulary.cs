namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The single place OpenVEX's vocabulary is translated into the CycloneDX analysis vocabulary
/// the <c>project_vuln_analysis</c> CHECK constraints enforce, and the single place a value
/// arriving from any document is checked against those constraints.
///
/// <para>Normalizing at ingest rather than at read is deliberate: a row whose state is spelled
/// in whichever vocabulary its document used forces every reader — the analysis API, the export
/// renderer, the policy evaluator, the UI — to carry the mapping, and a reader that forgets it
/// silently treats an <c>affected</c> row as untriaged.</para>
///
/// <para>A value the CHECK does not admit is dropped rather than stored, because the column is
/// a closed vocabulary and an insert carrying an unknown value fails the whole upload over one
/// producer's spelling.</para>
///
/// <para><b>These three sets are the only spelling of the vocabulary in the product.</b> The
/// triage endpoint validates against them, the ingest normalizer drops against them, and the
/// UI's select options are generated from them. A second, near-identical set held beside the
/// validator is not a duplicate that costs a little maintenance — it is a silent one-way door:
/// a value only the validator admits is accepted from the editor, written to the column, and
/// exported as CycloneDX the specification does not define, and the ingest normalizer then
/// discards it on re-upload, so the round trip loses a decision an operator recorded.</para>
/// </summary>
public static class VexVocabulary
{
    /// <summary>
    /// The one state a justification is defined for; every other state carries none.
    /// </summary>
    public const string NotAffected = "not_affected";

    /// <summary>
    /// Longest rationale the triage endpoint stores. Beyond this it is a document, not a note.
    /// </summary>
    public const int MaxDetailLength = 4000;

    /// <summary>The CycloneDX <c>analysis.state</c> values the column admits.</summary>
    public static readonly IReadOnlySet<string> States = new HashSet<string>(StringComparer.Ordinal)
    {
        "in_triage", "exploitable", "resolved", "resolved_with_pedigree", "false_positive", NotAffected,
    };

    /// <summary>The CycloneDX <c>analysis.justification</c> values.</summary>
    public static readonly IReadOnlySet<string> Justifications = new HashSet<string>(StringComparer.Ordinal)
    {
        "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
        "requires_environment", "protected_by_compiler", "protected_at_runtime",
        "protected_at_perimeter", "protected_by_mitigating_control",
    };

    /// <summary>The CycloneDX <c>analysis.response</c> values.</summary>
    public static readonly IReadOnlySet<string> Responses = new HashSet<string>(StringComparer.Ordinal)
    {
        "can_not_fix", "will_not_fix", "update", "rollback", "workaround_available",
    };

    /// <summary>Returns the state when the column admits it, else null.</summary>
    public static string? NormalizeState(string? state) =>
        state is not null && States.Contains(state) ? state : null;

    /// <summary>Returns the justification when the column admits it, else null.</summary>
    public static string? NormalizeJustification(string? justification) =>
        justification is not null && Justifications.Contains(justification) ? justification : null;

    /// <summary>Returns the response when the column admits it, else null.</summary>
    public static string? NormalizeResponse(string? response) =>
        response is not null && Responses.Contains(response) ? response : null;

    /// <summary>
    /// Maps an OpenVEX <c>status</c> onto the CycloneDX state. OpenVEX has four statuses to
    /// CycloneDX's six; the two CycloneDX states with no OpenVEX counterpart
    /// (<c>resolved_with_pedigree</c>, <c>false_positive</c>) are simply never produced by this
    /// direction of the mapping rather than being approximated.
    /// </summary>
    public static string? FromOpenVexStatus(string? status) => status switch
    {
        "not_affected" => "not_affected",
        "affected" => "exploitable",
        "fixed" => "resolved",
        "under_investigation" => "in_triage",
        _ => null,
    };

    /// <summary>
    /// Maps an OpenVEX justification onto the CycloneDX justification vocabulary. The two
    /// "code is not present" spellings collapse onto <c>code_not_present</c> because CycloneDX
    /// draws no distinction between the component being absent and its vulnerable code being
    /// absent, and an unrecognised justification is dropped rather than guessed at.
    /// </summary>
    public static string? FromOpenVexJustification(string? justification) => justification switch
    {
        "component_not_present" => "code_not_present",
        "vulnerable_code_not_present" => "code_not_present",
        "vulnerable_code_not_in_execute_path" => "code_not_reachable",
        "vulnerable_code_cannot_be_controlled_by_adversary" => "requires_configuration",
        "inline_mitigations_already_exist" => "protected_by_mitigating_control",
        _ => null,
    };
}
