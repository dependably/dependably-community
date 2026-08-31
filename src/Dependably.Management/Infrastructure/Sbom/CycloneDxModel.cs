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
public sealed record CycloneDxDocument(
    string SpecVersion,
    string? ToolName,
    string? ToolVersion,
    CycloneDxRootComponent? Root,
    IReadOnlyList<CycloneDxComponent> Components,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Dependencies,
    IReadOnlyList<CycloneDxAnalysisStatement> Statements);

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
/// <param name="Author">authors[].name joined, else the 1.4-era author string, else publisher.</param>
/// <param name="Copyright">components[].copyright, clipped.</param>
/// <param name="Group">components[].group — an npm scope, a Maven groupId.</param>
/// <param name="WebsiteUrl">externalReferences[] of type website.</param>
/// <param name="VcsUrl">externalReferences[] of type vcs.</param>
/// <param name="IssueTrackerUrl">externalReferences[] of type issue-tracker.</param>
/// <param name="DistributionUrl">externalReferences[] of type distribution.</param>
/// <param name="HashesJson">components[].hashes as a JSON array of {"alg","content"}, else null.</param>
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
    string? HashesJson = null);

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
