using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The closed vocabulary <c>sbom_components.explicit_unknown_fields</c> holds: which of CISA's
/// X4 "indicate unknown" duty fields an INGESTED document explicitly asserted was unknown, rather
/// than simply never mentioning. Two distinct sources feed it, and neither covers every member:
/// <see cref="SpdxParser"/> populates <see cref="Producer"/>/<see cref="License"/> ONLY, from
/// SPDX's own <c>NOASSERTION</c>/<c>NONE</c> tokens — the only two duty fields SPDX 2.3 itself
/// defines a NOASSERTION-eligible property for (see below); <see cref="CycloneDxParser"/>
/// populates all FOUR component-scoped members, but ONLY from this registry's own
/// <c>dependably:*-status</c> properties read back on a re-upload — plain CycloneDX defines no
/// generic "mark unknown" token of its own, so a CycloneDX document from any OTHER producer's
/// absences are always silent, never explicit, and stay NULL here. <see cref="SbomConformanceScorer"/>
/// is what turns those asymmetries into an honest verdict rather than scoring every silent
/// absence identically regardless of what its format or its producer could have said.
///
/// <para><b>Four members, not the six duty fields X4 names overall.</b> <see cref="Version"/>
/// (X4/D12a) and <see cref="Identifier"/> (X4/D13a) join <see cref="Producer"/>/<see cref="License"/>
/// here ONLY for the CycloneDX round-trip use above — SPDX 2.3's <c>versionInfo</c> and
/// <c>externalRefs[]</c> are still not established as <c>NOASSERTION</c>-eligible fields, so
/// <see cref="SpdxParser"/> never sets either. Tool Version has no per-component analogue — it is
/// a document-level fact, read back separately onto <see cref="CycloneDxDocument.ToolVersionExplicitlyUnknown"/>,
/// never through this component-scoped vocabulary. Hash Value has no <c>NOASSERTION</c>-eligible
/// property in either format: <c>checksums[]</c>/<c>hashes[]</c> is a list that is present or
/// absent as a whole, not a single field a producer marks unknown, and
/// <see cref="SbomConformanceScorer"/>'s D14/D15 rollup already reads a NULL hash column as
/// <c>NotAssessed</c> rather than <c>Absent</c> regardless of cause (it cannot yet tell "no hash
/// asserted" from "dropped for length" either) — so a component this registry's own dependably
/// export marked <c>dependably:hash-status=unknown</c> already avoids the false-Absent claim this
/// vocabulary exists to prevent, and adding a fifth member here would only reclassify an
/// already-honest <c>NotAssessed</c> into <c>ExplicitlyUnknown</c>, not close a gap.</para>
/// </summary>
internal static class SbomExplicitUnknownFields
{
    /// <summary>
    /// X4/D10e: SPDX's <c>supplier</c>, or a dependably-exported CycloneDX document's own
    /// <c>dependably:producer-status</c> property, was explicitly asserted unknown.
    /// </summary>
    public const string Producer = "producer";

    /// <summary>
    /// X4/D16e: both SPDX <c>licenseConcluded</c> AND <c>licenseDeclared</c> resolved to nothing
    /// real, and at least one of the two was explicitly <c>NOASSERTION</c>/<c>NONE</c> rather
    /// than simply absent from the document; or a dependably-exported CycloneDX document's own
    /// <c>dependably:license-status</c> property was explicitly asserted unknown.
    /// </summary>
    public const string License = "license";

    /// <summary>
    /// X4/D12a: a dependably-exported CycloneDX document's own <c>dependably:version-status</c>
    /// property was explicitly asserted unknown. CycloneDX-only — SPDX's <c>versionInfo</c> is not
    /// established as a <c>NOASSERTION</c>-eligible field.
    /// </summary>
    public const string Version = "version";

    /// <summary>
    /// X4/D13a: a dependably-exported CycloneDX document's own <c>dependably:identifier-status</c>
    /// property was explicitly asserted unknown. CycloneDX-only, same reason as <see cref="Version"/>.
    /// </summary>
    public const string Identifier = "identifier";

    private static readonly IReadOnlySet<string> KnownFields =
        new HashSet<string>(StringComparer.Ordinal) { Producer, License, Version, Identifier };

    private static readonly IReadOnlySet<string> EmptySet =
        new HashSet<string>(StringComparer.Ordinal);

    /// <summary>Null for an empty set — an empty JSON array on the row is never written.</summary>
    public static string? Serialize(IReadOnlyList<string> fields) =>
        fields.Count == 0 ? null : JsonSerializer.Serialize(fields);

    /// <summary>
    /// Parses the stored column back to a set, tolerating a malformed or unrecognised value as
    /// empty — the same "never let a bad stored value crash a reader" posture every other JSON
    /// column on this table takes.
    /// </summary>
    public static IReadOnlySet<string> Parse(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return EmptySet;
        }

        try
        {
            string[]? values = JsonSerializer.Deserialize<string[]>(json);
            return values is null
                ? EmptySet
                : new HashSet<string>(values.Where(KnownFields.Contains), StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            return EmptySet;
        }
    }
}
