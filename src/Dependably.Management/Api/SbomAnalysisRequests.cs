namespace Dependably.Api;

/// <summary>
/// Filter, sort and pagination state for <c>GET …/versions/{versionId}/analysis</c>.
///
/// <para>Bound as an object rather than as loose scalars so the whole read has one validation site
/// and one documented shape. Every field is optional; <see cref="SbomAnalysisController"/> clamps
/// the numbers and rejects an unrecognised enumerated value with a 422 rather than silently falling
/// back to a default — a filter that quietly did nothing would report a narrower risk picture than
/// the caller asked for.</para>
///
/// <para>Plain settable properties, not init-only: MVC query binding writes them after
/// construction, and there is no <c>Optional&lt;T&gt;</c> here to keep away from the OpenAPI
/// exporter's constructor-default reflection.</para>
/// </summary>
public sealed class ProjectAnalysisFilterRequest
{
    /// <summary>1-based page number.</summary>
    public int Page { get; set; } = 1;

    /// <summary>Rows per page, clamped to <see cref="SbomAnalysisProjection.MaxPageSize"/>.</summary>
    public int Limit { get; set; } = SbomAnalysisProjection.DefaultPageSize;

    /// <summary><c>priority</c> | <c>name</c> | <c>version</c> | <c>severity</c> | <c>scope</c>.</summary>
    public string? Sort { get; set; }

    /// <summary><c>asc</c> | <c>desc</c>.</summary>
    public string? Dir { get; set; }

    /// <summary>Substring match over the component name and its purl.</summary>
    public string? Q { get; set; }

    /// <summary><c>all</c> | <c>prod</c> | <c>dev</c>. Absent means all.</summary>
    public string? Scope { get; set; }

    /// <summary>Severity bucket a component must carry on a visible advisory.</summary>
    public string? Sev { get; set; }

    /// <summary>Reachability a component must carry on a visible advisory.</summary>
    public string? Reach { get; set; }

    /// <summary>
    /// <c>all</c> | <c>present</c> | <c>absent</c> | <c>unknown</c> — the registry cross-link state
    /// a component must be in. <c>absent</c> is the blind-spot view: everything this application
    /// ships that the registry has never served.
    /// </summary>
    public string? Registry { get; set; }

    /// <summary>When true, only components carrying at least one policy finding.</summary>
    public bool Violations { get; set; }

    /// <summary>When true, suppressed advisories count toward the filters and the rollup.</summary>
    public bool Suppressed { get; set; }
}

/// <summary>
/// One manual VEX triage decision for <c>PUT …/versions/{versionId}/analysis</c>.
///
/// <para><see cref="PurlKey"/> and <see cref="VulnKey"/> address the row and are required. The four
/// analysis fields are <see cref="Optional{T}"/> because null is a legitimate VALUE for each of
/// them — clearing a stale justification is a real decision, and a plain nullable would collapse
/// "the editor did not touch this field" into "the operator cleared it", silently discarding an
/// earlier call as a side effect of an unrelated edit.</para>
///
/// <para>Declared as init-only properties rather than constructor parameters: the OpenAPI schema
/// exporter reflects a constructor parameter's default value, and a custom struct's <c>default</c>
/// does not round-trip through parameter metadata, which 500s the generated document. See
/// <see cref="UpdateProxySettingsRequest"/> for the same treatment.</para>
/// </summary>
public sealed record UpdateProjectVulnAnalysisRequest
{
    /// <summary>Version-less canonical purl of the component the statement is about.</summary>
    public string? PurlKey { get; init; }

    /// <summary>Advisory id the statement is about, as the operator's view names it.</summary>
    public string? VulnKey { get; init; }

    /// <summary>CycloneDX <c>analysis.state</c>.</summary>
    public Optional<string?> VexState { get; init; }

    /// <summary>CycloneDX <c>analysis.justification</c>; meaningful only with <c>not_affected</c>.</summary>
    public Optional<string?> VexJustification { get; init; }

    /// <summary>CycloneDX <c>analysis.response</c>.</summary>
    public Optional<string?> VexResponse { get; init; }

    /// <summary>Free-text rationale recorded with the decision.</summary>
    public Optional<string?> VexDetail { get; init; }
}
