namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The closed set of "kind" tokens <c>sbom_components.additional_identifiers</c> stores — the
/// contract between the two ingest front ends that WRITE the column
/// (<see cref="CycloneDxParser"/>, <see cref="SpdxParser"/>) and the one export boundary that
/// READS it (<c>SbomExportService</c>), so a kind spelling can never drift between them. CPE,
/// SWHID and OmniBOR each have a defined CycloneDX component field and are emitted there natively;
/// <see cref="CommitHash"/> and <see cref="Uuid"/> have no CycloneDX component field and are
/// disclosed as <c>dependably:identifier:*</c> properties instead — see
/// <c>SbomExportService.BuildComponentObject</c> for exactly which arm each kind takes.
///
/// <para><b>CPE is never synthesized</b> (D13b) — a value with this kind lands here only when a
/// source document asserted one; nothing in this codebase constructs a CPE from advisory-side
/// data, because a CPE this registry built rather than received is an assertion it cannot stand
/// behind, and a wrong CPE silently mismatches a consumer's vulnerability lookup.</para>
///
/// <para><b>"Organization-specific identifiers" (CISA's own phrase) are deliberately out of
/// scope.</b> Neither CycloneDX nor SPDX 2.3 defines a structural home for an identifier of that
/// kind distinct from a free-form property/annotation a producer already writes in its own
/// namespace — inventing a vocabulary for it here would not be parsing what a document asserts,
/// it would be guessing which of a producer's arbitrary properties counts. The same reasoning
/// that keeps CPE synthesis out of this file keeps this kind out of it too.</para>
/// </summary>
internal static class SbomIdentifierKinds
{
    /// <summary>Common Platform Enumeration — CycloneDX's native <c>cpe</c> field; SPDX <c>externalRefs</c> SECURITY <c>cpe22Type</c>/<c>cpe23Type</c>.</summary>
    public const string Cpe = "cpe";

    /// <summary>Software Heritage persistent identifier — CycloneDX's native <c>swhid</c> array; SPDX <c>externalRefs</c> PERSISTENT-ID <c>swh</c>.</summary>
    public const string Swhid = "swhid";

    /// <summary>OmniBOR artifact identifier (gitoid) — CycloneDX's native <c>omniborId</c> array; SPDX <c>externalRefs</c> PERSISTENT-ID <c>gitoid</c>.</summary>
    public const string Omnibor = "omnibor";

    /// <summary>A version-control commit hash — CycloneDX's <c>pedigree.commits[].uid</c>. No SPDX 2.3 externalRef type carries this.</summary>
    public const string CommitHash = "commit-hash";

    /// <summary>A UUID identifier — a CycloneDX <c>externalReferences</c> entry whose <c>url</c> is a <c>urn:uuid:</c> URN. No SPDX 2.3 externalRef type carries this.</summary>
    public const string Uuid = "uuid";
}
