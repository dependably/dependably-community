namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The verdict one CISA 2026 minimum element receives for one stored SBOM document. See
/// <see cref="SbomConformanceScorer"/>'s class doc comment for the three-state model this exists
/// to carry, and why two more states sit beside it.
/// </summary>
public enum SbomElementState
{
    /// <summary>The element carries a real, usable value.</summary>
    Present,

    /// <summary>
    /// The element is missing and the document says nothing about why — CISA's "silent absence",
    /// the state P4 exists to distinguish from <see cref="ExplicitlyUnknown"/>.
    /// </summary>
    Absent,

    /// <summary>
    /// The element is missing, and the document itself explicitly says so — SPDX's
    /// <c>NOASSERTION</c>/<c>NONE</c>. CISA-conformant supplier behaviour (P4b): this must never
    /// read as a failure the way <see cref="Absent"/> does.
    /// </summary>
    ExplicitlyUnknown,

    /// <summary>
    /// This document's OWN FORMAT has no mechanism to carry the element at all — a structural
    /// fact about the format, not a claim about the supplier's practice. CycloneDX has no
    /// <c>NOASSERTION</c>-equivalent token (so it can never demonstrate P4's Explicit Unknowns
    /// practice); SPDX 2.3 has no lifecycle element (so it can never carry D5 Generation
    /// Context). Kept apart from <see cref="Absent"/> so a reader is never told a supplier failed
    /// to do something their chosen format cannot express.
    /// </summary>
    NotApplicable,

    /// <summary>
    /// dependably does not parse this element from an ingested document at all today — a gap in
    /// THIS REGISTRY's own tooling, not a claim about the document. Kept apart from
    /// <see cref="Absent"/> for the identical reason <see cref="NotApplicable"/> is: a reader must
    /// never be told a supplier is missing something dependably never looked for.
    /// </summary>
    NotAssessed,
}

/// <summary>Which half of the CISA 2026 baseline an element belongs to, for grouping in the UI.</summary>
public enum SbomElementCategory
{
    /// <summary>One of the 9 SBOM Metadata elements (D1-D9) — a fact about the document itself.</summary>
    Metadata,

    /// <summary>
    /// One of the 8 Component Data elements (D10-D17) — assessed once per component and rolled
    /// up to a document-level count, never collapsed to a single instance state.
    /// </summary>
    Component,

    /// <summary>One of the 6 Practices and Processes (P1-P6) — the 4 assessable from stored data.</summary>
    Practice,
}

/// <summary>
/// One element's verdict. <see cref="Total"/>/<see cref="PresentCount"/>/
/// <see cref="ExplicitUnknownCount"/>/<see cref="NotAssessedCount"/>/<see cref="AbsentCount"/> are
/// populated only for a <see cref="SbomElementCategory.Component"/> element or a practice derived
/// from one — the per-component rollup <see cref="SbomConformanceScorer"/>'s class doc comment
/// describes, and always sum to <see cref="Total"/>. A <see cref="SbomElementCategory.Metadata"/>
/// element's single <see cref="State"/> is the whole answer, and those five fields stay null.
///
/// <para><see cref="NotAssessedCount"/> exists for the same reason
/// <see cref="SbomElementState.NotAssessed"/> does at the instance level: a component this
/// registry's OWN parser or storage bound could not resolve — never one the supplier left
/// silent — must not inflate <see cref="AbsentCount"/>, the count a reader acts on as a named
/// supplier gap.</para>
/// </summary>
public sealed record SbomElementVerdict(
    string ElementId,
    SbomElementCategory Category,
    SbomElementState State,
    int? Total = null,
    int? PresentCount = null,
    int? ExplicitUnknownCount = null,
    int? AbsentCount = null,
    int? NotAssessedCount = null);

/// <summary>
/// The full scorecard for one stored <c>doc_type='sbom'</c> document: its format/tool facts plus
/// one verdict per assessed CISA 2026 element, in <see cref="SbomConformanceScorer.ElementOrder"/>.
/// </summary>
public sealed record SbomConformanceScorecard(
    string DocumentId,
    string Format,
    string? SpecVersion,
    int ComponentTotal,
    IReadOnlyList<SbomElementVerdict> Elements);
