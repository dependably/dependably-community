namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// How an export narrows the component set — the same three-state vocabulary the component
/// table's own <c>scope=all|prod|dev</c> filter reads (<c>SbomAnalysisProjection.ScopeFilters</c>),
/// not a parallel one. <c>Prod</c> reads <c>SbomAnalysisProjection.IsProdScope</c>: excludes
/// <c>dependency_scope = 'dev'</c> <b>and</b> <c>sbom_scope = 'excluded'</c>, and keeps
/// <c>unknown</c>-scoped rows — excluding those too would silently drop every component nothing
/// has classified, which for a project with no SARIF upload is most of them. A second declaration
/// of this vocabulary is exactly how the export option and the analysis-table filter drifted
/// before: an operator filtering the table to <c>prod</c> and the export dialog to the same word
/// must see the same component ids, not two different answers to one apparent question.
/// </summary>
public enum SbomComponentFilter
{
    /// <summary>No filtering. Every loaded component is kept.</summary>
    All,

    /// <summary>Keeps components <c>SbomAnalysisProjection.IsProdScope</c> classifies as prod. <c>unknown</c> is kept.</summary>
    Prod,

    /// <summary>Keeps only components whose <c>dependency_scope</c> is exactly <c>dev</c>.</summary>
    Dev,
}

/// <summary>
/// The choices an SBOM/collection export makes: which document shape (<paramref name="Variant"/>),
/// which serialization (<paramref name="Format"/>), which CycloneDX spec version
/// (<paramref name="SpecVersion"/>), and whether the component set is narrowed
/// (<paramref name="Filter"/>). Every call site constructs this with named arguments — the four
/// fields are all <c>string</c>/enum and same-typed positional arguments reorder silently on a
/// call-site edit, which a positional constructor call would not catch at compile time.
/// </summary>
public sealed record SbomExportOptions(
    string Variant, string Format, string SpecVersion, SbomComponentFilter Filter)
{
    /// <summary>Today's behaviour before this option set existed: inventory / cyclonedx-json / 1.7 / unfiltered.</summary>
    public static SbomExportOptions Default { get; } = new(
        Variant: "inventory", Format: "cyclonedx-json", SpecVersion: "1.7", Filter: SbomComponentFilter.All);
}
