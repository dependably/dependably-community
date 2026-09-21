namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The subset of a CycloneDX document this codebase reads, projected out of the raw JSON by
/// <see cref="CycloneDxParser"/>. Deliberately a narrow hand-written subset rather than a full
/// object model: ingest reads inventory, the dependency graph and embedded analysis statements,
/// and every other element of the specification survives only in the verbatim stored blob.
/// </summary>
/// <param name="SpecVersion">specVersion, already checked against the accepted range.</param>
/// <param name="ToolName">First producing tool's name, when the document names one.</param>
/// <param name="ToolVersion">First producing tool's version, when the document names one.</param>
/// <param name="Root">metadata.component — the application the document describes.</param>
/// <param name="Components">components[], in document order.</param>
/// <param name="Dependencies">dependencies[]: bom-ref to the refs it depends on.</param>
/// <param name="Statements">vulnerabilities[] analysis statements, empty for a plain inventory.</param>
/// <param name="LifecyclesJson">
/// metadata.lifecycles as a JSON array of <c>{"phase"}</c> or <c>{"name","description"}</c>
/// entries, in document order, or null when the document declared none. A strong ingest-time
/// quality signal — a source-phase document legitimately carries no component hashes.
/// </param>
/// <param name="ToolVersionExplicitlyUnknown">
/// X4/D8b, read back: true when the SAME tool entry <paramref name="ToolName"/> came from also
/// carried dependably's own <c>dependably:tool-version-status</c> property — a dependably export
/// re-ingested here, so the document explicitly said its tool's version was unknown rather than
/// simply omitting it. False (never true) when <paramref name="ToolName"/> is null: nothing named
/// to qualify.
/// </param>
public sealed record CycloneDxDocument(
    string SpecVersion,
    string? ToolName,
    string? ToolVersion,
    CycloneDxRootComponent? Root,
    IReadOnlyList<CycloneDxComponent> Components,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Dependencies,
    IReadOnlyList<CycloneDxAnalysisStatement> Statements,
    string? LifecyclesJson = null,
    bool ToolVersionExplicitlyUnknown = false);

/// <summary>metadata.component: the subject of the document, which seeds a created project.</summary>
public sealed record CycloneDxRootComponent(string? BomRef, string? Name, string? Version, string? Type);

/// <summary>One components[] entry.</summary>
/// <param name="BomRef">bom-ref, the identity the dependency graph refers to.</param>
/// <param name="Name">components[].name, the one required field.</param>
/// <param name="Version">components[].version, absent for some component types.</param>
/// <param name="Type">components[].type.</param>
/// <param name="Purl">components[].purl verbatim, null when the component declares none.</param>
/// <param name="Scope">components[].scope, kept only when it is a value the column admits.</param>
/// <param name="LicenseSpdx">The declared licences folded into one SPDX expression, else null.</param>
/// <param name="Description">components[].description, clipped.</param>
/// <param name="Author">
/// authors[].name joined, else the 1.4-era author string, else manufacturer.name — the
/// person(s)/entity who created the component. manufacturer is CycloneDX's own automated-creation
/// analogue of authors[] (its schema: "Components created through automated means may have
/// @.manufacturer instead"), never a Producer fallback — see <paramref name="Producer"/>'s own
/// comment for why manufacturer and supplier are kept apart. Distinct from
/// <paramref name="Producer"/>: CISA's 2026 baseline separates Component Producer from Component
/// Author explicitly.
/// </param>
/// <param name="Copyright">components[].copyright, clipped.</param>
/// <param name="Group">components[].group — an npm scope, a Maven groupId.</param>
/// <param name="WebsiteUrl">externalReferences[] of type website.</param>
/// <param name="VcsUrl">externalReferences[] of type vcs.</param>
/// <param name="IssueTrackerUrl">externalReferences[] of type issue-tracker.</param>
/// <param name="DistributionUrl">externalReferences[] of type distribution.</param>
/// <param name="HashesJson">components[].hashes as a JSON array of {"alg","content"}, else null.</param>
/// <param name="VersionRange">
/// components[].versionRange, added in CycloneDX 1.7 and mutually exclusive with
/// <paramref name="Version"/>: a component declaring a range has no concrete version, so this is
/// what says why the version is absent rather than leaving it unexplained.
/// </param>
/// <param name="IsExternal">
/// components[].isExternal, added in CycloneDX 1.7. Null when the document did not say — which
/// every document below 1.7 is, so absence is not the same claim as false.
/// </param>
/// <param name="ManifestDevDeclared">
/// The CycloneDX property taxonomy's dev-dependency marker (<c>cdx:npm:package:development</c> and
/// the sibling per-ecosystem spellings — see <see cref="CycloneDxParser"/>), read verbatim as
/// true/false/absent. This is a MANIFEST declaration, not a reachability verdict — it seeds
/// <c>sbom_components.dependency_scope</c> only when nothing has verified it yet; see
/// <see cref="SbomIngestRepository"/>'s ingest-side handling for why the two are not the same claim.
/// </param>
/// <param name="Producer">
/// components[].supplier.name (an organizationalEntity, present in the schema since CycloneDX
/// 1.2 — CycloneDX's own schema: "The organization that supplied the component"), falling back
/// to the older components[].publisher string for a producer that still only emits that — CISA's
/// Component Producer element, matching SPDX's own <c>supplier</c> (see <see cref="SpdxParser"/>).
/// supplier wins when a document carries both, as the structurally correct, modern field.
///
/// <para>components[].manufacturer is a DIFFERENT concept and is never folded in here:
/// CycloneDX's own schema documents manufacturer as the automated-creation analogue of
/// <paramref name="Author"/>'s authors[] ("Components created through automated means may have
/// @.manufacturer instead"), not a Component Producer synonym — see
/// <paramref name="Author"/>. Reading it as Producer would misattribute the party that BUILT the
/// component as the party that SUPPLIED it, exactly the confusion CISA and CycloneDX both keep
/// separate.</para>
///
/// <para>Distinct from <paramref name="Author"/>, which is who created the code, not who ships
/// it.</para>
/// </param>
/// <param name="LicenseNamed">
/// CISA D16c's discriminator: <c>true</c> when <paramref name="LicenseSpdx"/> was resolved from a
/// single <c>licenses[].license.name</c> entry (no SPDX <c>id</c>, no <c>expression</c>) rather
/// than a genuine SPDX identifier/expression — the ONLY signal that tells the export boundary
/// which native CycloneDX <c>licenseChoice</c> shape to render, because <c>license.name</c> is
/// legal with no <c>url</c> at all, so "no URL" cannot itself mean "must be an expression".
/// </param>
/// <param name="LicenseUrl">
/// CISA D16c's URL fallback: populated only when <paramref name="LicenseNamed"/> is <c>true</c>
/// AND the same <c>license</c> entry also carried a <c>url</c>. A name-only entry with no URL
/// still renders natively as a name-only <c>license</c> object — see
/// <paramref name="LicenseNamed"/>, which is what makes that shape representable. Appended last,
/// not inserted beside <paramref name="LicenseSpdx"/>, so no existing positional call site
/// silently reorders onto it.
/// </param>
/// <param name="AdditionalIdentifiersJson">
/// CISA D13c/D13d: every identifier the document asserts BESIDE <paramref name="Purl"/> — CPE,
/// SWHID, OmniBOR, a commit hash, a UUID — as a JSON array of <c>{"kind","value"}</c> pairs (see
/// <see cref="SbomIdentifierKinds"/> and <see cref="SbomAdditionalIdentifiers"/>), or null when
/// the document asserted none. Appended last for the same reason <paramref name="LicenseUrl"/>
/// was.
/// </param>
/// <param name="ExplicitUnknownFieldsJson">
/// CISA X4/P4a's ingest-scoring signal (see <see cref="SbomExplicitUnknownFields"/>): which of
/// this component's "indicate unknown" duty fields the SOURCE DOCUMENT explicitly asserted
/// unknown, rather than simply never mentioning, as a JSON array of strings. <see cref="SpdxParser"/>
/// populates <see cref="SbomExplicitUnknownFields.Producer"/>/<see cref="SbomExplicitUnknownFields.License"/>
/// from SPDX's own <c>NOASSERTION</c>/<c>NONE</c> tokens — the only two duty fields SPDX 2.3
/// itself defines a NOASSERTION-eligible property for. <see cref="CycloneDxParser"/> populates all
/// FOUR component-scoped members (also <see cref="SbomExplicitUnknownFields.Version"/>/
/// <see cref="SbomExplicitUnknownFields.Identifier"/>) ONLY from this registry's own
/// <c>dependably:*-status</c> component properties (<see cref="DependablyExportProperties"/>) —
/// the vocabulary a dependably EXPORT writes for exactly these duties, read back on a re-upload so
/// a dependably-to-dependably round trip demonstrates the practice instead of reading as a silent
/// absence for every component this registry itself already marked unknown. Plain CycloneDX
/// defines no vocabulary-free equivalent, so a document from any OTHER producer carries none of
/// these properties and this stays null for it, exactly as before. Appended last, same reason as
/// <paramref name="AdditionalIdentifiersJson"/>.
/// </param>
/// <param name="ContainmentDeclared">
/// SPDX-only (see <see cref="SpdxParser"/>): true when this component was the <c>relatedSpdxElement</c>
/// of a <c>CONTAINS</c> relationship anywhere in the document — CISA's Relationship attribute is
/// defined as inclusion, so a document asserting "the image CONTAINS this package" has asserted a
/// relationship for D17 (<see cref="SbomConformanceScorer"/>'s <c>ComponentDependencyRelationship</c>
/// rollup) exactly as much as one asserting <c>DEPENDS_ON</c> has. It is DELIBERATELY never folded
/// into the dependency GRAPH itself (<see cref="SbomDependencyGraph"/>'s adjacency, hence never
/// into <c>dependency_kind</c>/<c>dependency_path</c>): a containment edge states no depth or
/// route, and a container/OS SBOM commonly declares CONTAINS from its root straight to every
/// package it holds — folding that into the graph's shortest-path walk would read a declared
/// multi-hop <c>DEPENDS_ON</c> chain as a false single-hop <c>direct</c> dependency the instant a
/// root-level CONTAINS edge to the same component also exists. This flag is a purely internal
/// scoring signal: never exported, never rendered, never a value <c>dependency_kind</c> itself can
/// take.
/// </param>
public sealed record CycloneDxComponent(
    string? BomRef,
    string Name,
    string? Version,
    string? Type,
    string? Purl,
    string? Scope,
    string? LicenseSpdx,
    string? Description = null,
    string? Author = null,
    string? Copyright = null,
    string? Group = null,
    string? WebsiteUrl = null,
    string? VcsUrl = null,
    string? IssueTrackerUrl = null,
    string? DistributionUrl = null,
    string? HashesJson = null,
    string? VersionRange = null,
    bool? IsExternal = null,
    bool? ManifestDevDeclared = null,
    string? Producer = null,
    string? LicenseUrl = null,
    bool? LicenseNamed = null,
    string? AdditionalIdentifiersJson = null,
    string? ExplicitUnknownFieldsJson = null,
    bool ContainmentDeclared = false);

/// <summary>
/// One (product, vulnerability) analysis statement, from either a vulnerabilities-only VEX
/// document or the vulnerabilities[] array embedded in an SBOM-with-VDR. Products are carried as
/// the raw <c>affects[].ref</c> strings, which are bom-refs conventionally spelled as purls.
/// </summary>
public sealed record CycloneDxAnalysisStatement(
    string VulnId,
    IReadOnlyList<string> ProductRefs,
    string? State,
    string? Justification,
    string? Response,
    string? Detail);
