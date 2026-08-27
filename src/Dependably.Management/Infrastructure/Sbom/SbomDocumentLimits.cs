namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The per-document ceilings every ingest parser refuses above.
///
/// <para>The byte cap in <see cref="SbomOptions"/> bounds what is read off the wire; these bound
/// what one document may turn into. The two are not interchangeable, because the ratio between
/// them is entirely the producer's: a document well inside the byte cap can carry hundreds of
/// thousands of minimal entries, and each one becomes a row plus a round trip on the request
/// thread — a request that never returns, written into a table the retraction sweep then
/// re-reads whole.</para>
///
/// <para>Every ceiling refuses rather than truncates, the rule the component cap already set: a
/// silently truncated document reads as a complete one, and for the analysis arms specifically a
/// dropped statement is a suppression that stops applying with nothing anywhere saying so.</para>
///
/// <para>They sit together rather than one per parser because they answer one question — how
/// much work may a single upload commit this instance to — and a VEX document's statements land
/// in the same table by the same writer whether CycloneDX or OpenVEX spelled them.</para>
/// </summary>
public static class SbomDocumentLimits
{
    /// <summary>The ceiling on one document's component inventory.</summary>
    public const int MaxComponents = 50_000;

    /// <summary>
    /// The ceiling on one document's analysis statements — CycloneDX <c>vulnerabilities[]</c> and
    /// OpenVEX <c>statements[]</c>, which the ingest writer treats as one vocabulary — counted
    /// <b>once per component a statement names</b>, because that pair is the unit that becomes a
    /// <c>project_vuln_analysis</c> row and an entry in the retraction sweep's asserted set.
    ///
    /// <para>Counting parsed statements instead bounds the wrong number, by an unbounded factor:
    /// <c>affects[]</c> and OpenVEX <c>products[]</c> carry no length limit of their own, so one
    /// statement naming a million components is a single statement and a million writes. The two
    /// array lengths multiply, so only their product is a bound.</para>
    ///
    /// <para>A statement naming no component charges one. It asserts nothing and writes nothing,
    /// but it still costs a parsed entry, and charging it keeps the statement array bounded as
    /// well — otherwise a document of nothing but product-less statements would be admitted at
    /// any length.</para>
    /// </summary>
    public const int MaxComponentStatements = 50_000;

    /// <summary>The ceiling on one SARIF log's <c>results[]</c>, summed across every run.</summary>
    public const int MaxResults = 50_000;
}
