using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Renders a project version's component inventory, vulnerability disclosure and effective VEX
/// state as fresh CycloneDX JSON under the caller's chosen <see cref="SbomExportOptions"/>
/// (spec version 1.6 or 1.7, optionally narrowed by <see cref="SbomComponentFilter"/>), and
/// resolves an uploaded document's original blob coordinate for verbatim download. Built directly
/// against <c>System.Text.Json</c> — CONTRACT D2 forbids a new NuGet dependency on the CycloneDX
/// serializer, so a re-render is a re-render: it is not byte-identical to whatever was originally
/// uploaded, only spec-valid CycloneDX covering the same components, licences, dependency graph
/// and vulnerability analysis the database holds (or the subset <c>SbomExportOptions.Filter</c>
/// selected from it).
///
/// Every query here is written directly against the schema rather than through another agent's
/// repository, per the fleet contract's "repositories are not shared" rule — a little query
/// duplication in exchange for a mergeable worktree.
/// </summary>
public sealed partial class SbomExportService
{
    /// <summary>
    /// Declares which version of each project an aggregate document selected. Emitted in
    /// <c>metadata.properties</c> because a document that does not say what it chose is read as
    /// exhaustive — and this one is not: it carries each project's <c>is_latest</c> version, which
    /// is the same selection the collection's own rollup counts describe.
    /// </summary>
    public const string LatestPerProjectSelection = "latest-per-project";

    /// <summary>
    /// dependably's own SBOM Tool identity (D7/D8) — the entity <c>metadata.tools</c> must name
    /// when this service is the producer, not the ingested document's own tool (which
    /// <c>project_documents.tool_name</c>/<c>tool_version</c> already hold separately). The name
    /// matches the fixed literal <c>VulnTrackerEnrichmentClient</c> already announces at its own
    /// handshake — one identity string for the product, not a second spelling invented here — and
    /// the version is read at runtime from the assembly's informational version (falling back to
    /// its plain version, then to a literal), the same three-step precedence
    /// <c>CoreStartupService</c> and <c>VulnTrackerEnrichmentClient</c> already use, so it never
    /// drifts from <c>Directory.Build.props</c>' <c>&lt;Version&gt;</c>.
    /// </summary>
    private static class DependablyToolIdentity
    {
        public const string Name = "dependably-community";

        public static readonly string Version =
            typeof(DependablyToolIdentity).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(DependablyToolIdentity).Assembly.GetName().Version?.ToString()
            // vocab-ok: dependably's own reflection-read version, not a P4/X4 "indicate
            // unknown" duty about an absent author-asserted field — a defensive fallback for
            // a read that cannot itself fail under a real build.
            ?? "unknown";
    }

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly ProjectRepository _projects;
    private readonly InstanceVulnTrackerConfig _tracker;
    private readonly Sbom.SbomAuthorSigner _signer;

    public SbomExportService(
        IMetadataStore db, TimeProvider time, ProjectRepository projects, InstanceVulnTrackerConfig tracker,
        Sbom.SbomAuthorSigner signer)
    {
        _db = db;
        _time = time;
        _projects = projects;
        _tracker = tracker;
        _signer = signer;
    }

    // Appends the signature-state property to an already-built metadata.properties array. Must
    // run BEFORE the array is assigned to metadata (the property is itself covered by the
    // signature that gets attached last), never after. See DependablyExportProperties.SignatureState
    // for the property's own doc comment and its closed value vocabulary.
    private static void AddSignatureStateProperty(JsonArray properties, string state) =>
        properties.Add(new JsonObject { ["name"] = DependablyExportProperties.SignatureState, ["value"] = state });

    /// <summary>
    /// Whether the operator's optional vulnerability-tracker connection is enabled and dialable —
    /// the single fact every SSVC/NVD-derived per-vulnerability signal in an exported document
    /// shares, so a consumer can tell "absent because the feature is off" from "the source said
    /// nothing" without the per-vulnerability signal itself carrying that distinction.
    /// </summary>
    private async Task<bool> IsTrackerConfiguredAsync(CancellationToken ct)
        => (await _tracker.ResolveAsync(ct)).IsActive;

    /// <summary>
    /// D1 (SBOM Author): the entity OPERATING the tool, not the tool itself. This data model has
    /// no per-tenant display name — <c>orgs</c> carries only <c>slug</c>, which is therefore the
    /// only tenant-derivable answer without inventing a configuration knob nothing else in this
    /// data model can answer. It may fall short of "full name, not an acronym" for a tenant
    /// whose slug is abbreviated, which is a data-quality limit of the one string this model
    /// holds, not a choice this method makes.
    ///
    /// <para>Every export renders the SAME value regardless of whether the document is a fresh
    /// synthesis (a collection, built from no single ingested original) or is amending an
    /// uploaded SBOM (a per-project export) — dependably is the author of the SBOM DATA being
    /// emitted right now either way. The uploaded document's own author, when it named one, is a
    /// different entity's claim this parser does not capture yet; until it does, this method's
    /// value is what an amending export honestly states, with the gap left here rather than the
    /// field silently omitted.</para>
    /// </summary>
    private static JsonArray BuildAuthorsMetadata(string orgSlug) =>
        new(new JsonObject { ["name"] = orgSlug });

    /// <summary>
    /// D7/D8 (SBOM Tool Name/Version): dependably's OWN identity, read at runtime rather than a
    /// string that drifts from <c>Directory.Build.props</c> — see
    /// <see cref="DependablyToolIdentity"/>. CISA's element covers a tool used to "generate OR
    /// AMEND" the SBOM: <paramref name="originalToolName"/> (when a document named one) is
    /// emitted FIRST — the tool that generated the components this document still describes —
    /// and dependably second, as the amending tool. A collection document passes no original: it
    /// is synthesized from many projects' data rather than amending any single upload, so only
    /// dependably belongs in the chain.
    /// </summary>
    private static JsonObject BuildToolsMetadata(string? originalToolName, string? originalToolVersion)
    {
        var components = new JsonArray();
        if (originalToolName is not null)
        {
            var original = new JsonObject { ["type"] = "application", ["name"] = originalToolName };
            if (originalToolVersion is not null)
            {
                original["version"] = originalToolVersion;
            }
            else
            {
                // X4/D8b: a document named this tool but not its version — indicate unknown
                // rather than leaving the field silently absent.
                original["properties"] = new JsonArray(
                    Prop(DependablyExportProperties.ToolVersionStatus, DependablyExportProperties.AbsenceReason()));
            }

            components.Add(original);
        }

        components.Add(new JsonObject
        {
            ["type"] = "application",
            ["name"] = DependablyToolIdentity.Name,
            ["version"] = DependablyToolIdentity.Version,
        });

        return new JsonObject { ["components"] = components };
    }

    /// <summary>
    /// D5 (SBOM Generation Context): dependably's own honest phase claim for EVERY document this
    /// service renders, regardless of variant or aggregation — the claim describes what this
    /// EXPORT is, not what any one uploaded document was. A bare <c>build</c> phase would be a
    /// false provenance claim: this registry never observes a build, only what a producer already
    /// uploaded plus its own scan. <c>post-build</c> is the defined CycloneDX phase that fits
    /// best, and a second, named entry carries the nuance the defined vocabulary alone cannot —
    /// "and data available at the time" is explicitly part of what this element covers, and a
    /// document whose component set came from an upload but whose vulnerability data came from
    /// dependably's own scan is exactly the case that sentence exists to describe.
    /// </summary>
    private static JsonArray BuildLifecyclesMetadata() => new(
        new JsonObject { ["phase"] = "post-build" },
        new JsonObject
        {
            ["name"] = "dependably-merged-observation",
            ["description"] =
                "Observed at a registry: merges a component inventory carried by an uploaded "
                + "SBOM (or a re-scan of previously uploaded components) with dependably's own "
                + "vulnerability scan and policy evaluation.",
        });

    /// <summary>
    /// Renders CycloneDX JSON under <paramref name="options"/> (<c>Variant</c> is <c>inventory</c>
    /// or <c>vdr</c>; <c>SpecVersion</c> is <c>1.6</c> or <c>1.7</c>; <c>Filter</c> optionally
    /// narrows the component set — see <see cref="SbomComponentFilter"/>), or <c>null</c> when the
    /// project or version does not resolve for this org.
    /// </summary>
    public async Task<string?> BuildSbomDocumentAsync(
        string orgId, string projectId, string versionId, SbomExportOptions options, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var resolved = await ResolveProjectVersionAsync(conn, orgId, projectId, versionId, ct);
        if (resolved is null)
        {
            return null;
        }

        var (components, filteredOutCount, installScriptFacts, ownHashFacts, trackerConfigured,
             orgSlug, sbomTool, vulnRows, analysisRows, affectedApps) =
            await LoadExportStateAsync(conn, orgId, resolved, options, ct);

        // Resolved before the content fingerprint (below): the rendered signature-state is
        // itself an asserted fact the fingerprint must cover — see this partial class' Revision
        // file for the "signature identity" decision. Resolving here also satisfies the older
        // requirement that this run before metadata.properties is built: the signature-state
        // property it decides is itself part of what gets signed, so it must exist before the
        // signature is attached at the very end of this method.
        var (resolvedSigningKey, signatureState, orgHasActiveKey) = await _signer.ResolveAsync(orgId, ct);
        using var signingKey = resolvedSigningKey;

        bool isVdr = options.Variant == DocKindVdr;
        string contentFingerprint = ComputeContentFingerprint(
            resolved,
            new ComponentFingerprintInputs(
                Components: components,
                InstallScriptByComponentId: installScriptFacts,
                OwnHashByComponentId: ownHashFacts,
                IncludePurlIdentity: isVdr),
            new ProvenanceIdentity(
                OrgSlug: orgSlug,
                OriginalToolName: sbomTool?.ToolName,
                OriginalToolVersion: sbomTool?.ToolVersion),
            isVdr ? VdrVulnFingerprintFacts(vulnRows, analysisRows, installScriptFacts) : null,
            orgHasActiveKey);
        // D6a: derived from the data the fingerprint just hashed, never from the render clock.
        string derivedChangedAtIso =
            DeriveDocumentChangedAt(resolved, components, vulnRows, analysisRows);
        var revision = await ResolveRevisionAsync(
            conn,
            new RevisionKey(
                OrgId: orgId,
                ProjectVersionId: resolved.ProjectVersionId,
                DocKind: options.Variant,
                Format: options.Format,
                ScopeFilter: ScopeFilterValue(options.Filter)),
            contentFingerprint, derivedChangedAtIso, ct);

        string rootRef = $"{resolved.ProjectName}@{resolved.VersionLabel}";

        var properties = BuildCoverageProperties(
            components, trackerConfigured, options.Filter, filteredOutCount, documentCarriesInventory: true);
        AddSignatureStateProperty(properties, signatureState);

        var doc = new JsonObject
        {
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = options.SpecVersion,
            // D9d (RFC 9562): stable per document shape — see this partial class' Revision file
            // for the full serial/version decision.
            ["serialNumber"] = revision.SerialNumber,
            // D9c: an integer, not a SemVer string — see the Revision file's class doc comment.
            ["version"] = revision.Revision,
            ["metadata"] = new JsonObject
            {
                // D6a/b: the last time the DATA changed, not render time — see ResolveRevisionAsync.
                ["timestamp"] = revision.ChangedAtIso,
                // D1 (SBOM Author): the entity operating this deployment for this tenant — see
                // BuildAuthorsMetadata for why the org slug is the value.
                ["authors"] = BuildAuthorsMetadata(orgSlug),
                // D7/D8 (SBOM Tool Name/Version): this is an AMENDING export — the version's
                // components came from an uploaded SBOM, so the original producing tool (when the
                // document named one) is emitted first, dependably second. See BuildToolsMetadata.
                ["tools"] = BuildToolsMetadata(sbomTool?.ToolName, sbomTool?.ToolVersion),
                // D5 (SBOM Generation Context): see BuildLifecyclesMetadata for the exact claim.
                ["lifecycles"] = BuildLifecyclesMetadata(),
                // X3: Component Data elements apply to the target component too. This registry's
                // data model has no producer, hash, licence or identifier for a PROJECT as a
                // whole — those are facts about a built artefact, and a project describes an
                // application, not a single downloadable blob — so there is nothing more to add
                // here than what is already emitted. A dedicated unknown/withheld vocabulary
                // would let this state that explicitly; until one exists this stays silent
                // rather than inventing one.
                ["component"] = new JsonObject
                {
                    ["type"] = resolved.Classifier,
                    ["bom-ref"] = rootRef,
                    ["name"] = resolved.ProjectName,
                    ["version"] = resolved.VersionLabel,
                },
                ["properties"] = properties,
            },
            ["components"] = BuildComponentsArray(
                components, installScriptByComponentId: installScriptFacts, specVersion: options.SpecVersion,
                ownHashByComponentId: ownHashFacts),
            ["dependencies"] = BuildDependenciesArray(rootRef, components),
        };

        if (options.Variant == DocKindVdr)
        {
            doc["vulnerabilities"] = BuildVulnerabilitiesArray(vulnRows, analysisRows, installScriptFacts, affectedApps);
        }

        // Last: everything above is what gets signed. See SbomAuthorSigner's own doc comment for
        // why attach/resolve are split rather than one "sign the document" call.
        if (signingKey is not null)
        {
            Sbom.SbomAuthorSigner.Attach(doc, signingKey);
        }

        return doc.ToJsonString();
    }

    /// <summary>
    /// Renders one CycloneDX document, under the caller's chosen <see cref="SbomExportOptions"/>,
    /// covering every project beneath a collection, or <c>null</c> when the id is not a collection
    /// this org holds.
    ///
    /// <para><b>Shape.</b> Each project is a top-level <c>components[]</c> entry of its own
    /// classifier type, carrying its libraries in a nested <c>components[]</c>. A flat merge was
    /// rejected: it loses which project each library came from — the only thing this document adds
    /// over the per-project exports — and it produces an INVALID document, because bom-refs are
    /// derived from the purl and the same library in two projects would collide on a ref the spec
    /// requires to be unique. Every ref here is therefore namespaced by project id, while the
    /// <c>purl</c> field stays the bare purl a consumer matches on.</para>
    ///
    /// <para><b>Selection.</b> Each project contributes its <c>is_latest</c> version and nothing
    /// else, which is what the collection's own rollup counts describe — an export whose contents
    /// disagreed with the numbers rendered beside its button would be worse than no export. The
    /// rule is stated in <c>metadata.properties</c> rather than left implicit, and a project with
    /// no version at all is still listed, as an empty entry, so the document never reads as
    /// exhaustive when it is not.</para>
    ///
    /// <para>This is deliberately NARROWER than <c>ProjectLifecycle.InServiceFilter</c>, which the
    /// blast radius and the VEX affected-count both use and which admits several concurrently
    /// active versions per project. The two answer different questions: that filter asks "what is
    /// still running", while a CycloneDX document needs one component per project — emitting a
    /// project twice, once per active release, produces two entries a consumer cannot tell apart
    /// without a per-version label the format gives no place to put. Selecting <c>is_latest</c>
    /// keeps the document's contents matching the rollup counts rendered beside its own button,
    /// which is the property that makes the export legible. Exporting every active version is a
    /// real shape and still needs that label; nothing has asked for it.</para>
    ///
    /// <para><b>No deduplication.</b> A library shipped by three projects appears three times, once
    /// under each. VEX analysis is per-project — the same advisory can be not-affected in one and
    /// live in another — so a single merged entry would need one analysis block holding two
    /// contradictory truths. Reducing on purl downstream is trivial; recovering provenance from a
    /// pre-deduplicated document is not.</para>
    ///
    /// <para>The walk is not transactional, so a concurrent upload can land in the middle of it and
    /// produce a mixed snapshot — the same property the rollup counts have.</para>
    /// </summary>
    /// <summary>
    /// Everything one render reads from the database before it builds anything. Loaded in one
    /// place so the revision fingerprint, D6a's derived changed_at and the rendered document are
    /// guaranteed to see the same state — computing any of them from a later read would work from
    /// data the document does not describe.
    /// </summary>
    private readonly record struct ExportState(
        List<ComponentRow> Components,
        int FilteredOutCount,
        Dictionary<string, bool> InstallScriptFacts,
        Dictionary<string, string> OwnHashFacts,
        bool TrackerConfigured,
        string OrgSlug,
        ToolRow? SbomTool,
        List<ComponentVulnRow> VulnRows,
        List<AnalysisRow> AnalysisRows,
        Dictionary<string, int> AffectedApps);

    /// <summary>
    /// Loads <see cref="ExportState"/>. The vulnerability and analysis rows are read up front
    /// rather than inside the caller's <c>vdr</c> branch, because the revision fingerprint and the
    /// derived changed_at both need the SAME state the rendered document carries.
    /// </summary>
    private async Task<ExportState> LoadExportStateAsync(
        DbConnection conn, string orgId, ResolvedVersion resolved, SbomExportOptions options,
        CancellationToken ct)
    {
        var loaded = await LoadComponentsAsync(conn, orgId, resolved.ProjectVersionId, ct);
        var (components, filteredOutCount) = ApplyComponentFilter(loaded, options.Filter);

        List<ComponentVulnRow> vulnRows = [];
        List<AnalysisRow> analysisRows = [];
        Dictionary<string, int> affectedApps = new(StringComparer.Ordinal);
        if (options.Variant == DocKindVdr)
        {
            vulnRows = FilterVulnsToKeptComponents(
                await LoadComponentVulnsAsync(conn, orgId, resolved.ProjectVersionId, ct), components);
            analysisRows = await LoadAnalysisAsync(conn, orgId, resolved.ProjectVersionId, ct);
            affectedApps = await CountAffectedApplicationsAsync(
                conn, orgId, vulnRows.Select(v => v.OsvId).Distinct(StringComparer.Ordinal).ToList(), ct);
        }

        return new ExportState(
            components,
            filteredOutCount,
            await LoadInstallScriptFactsAsync(conn, orgId, resolved.ProjectVersionId, ct),
            await LoadOwnHashFactsAsync(conn, orgId, resolved.ProjectVersionId, ct),
            await IsTrackerConfiguredAsync(ct),
            await LoadOrgSlugAsync(conn, orgId, ct),
            await LoadDocumentToolAsync(conn, orgId, resolved.ProjectVersionId, "sbom", ct),
            vulnRows,
            analysisRows,
            affectedApps);
    }

    public async Task<string?> BuildCollectionSbomDocumentAsync(
        string orgId, string collectionId, SbomExportOptions options, CancellationToken ct)
    {
        var subtree = await _projects.ListSubtreeProjectsAsync(orgId, collectionId, ct);
        if (subtree is null)
        {
            return null;
        }

        var collection = await _projects.GetAsync(orgId, collectionId, ct);
        if (collection is null)
        {
            return null;
        }

        await using var conn = await _db.OpenAsync(ct);

        string rootRef = $"collection:{collection.Id}";
        var projectEntries = new JsonArray();
        var dependencies = new JsonArray();
        var rootDependsOn = new JsonArray();
        var vulnerabilities = new JsonArray();
        int withoutSbom = 0;
        var coverage = new CoverageAccumulator();
        bool trackerConfigured = await IsTrackerConfiguredAsync(ct);
        string orgSlug = await LoadOrgSlugAsync(conn, orgId, ct);

        var buffers = new CollectionBuffers(projectEntries, dependencies, vulnerabilities);
        foreach (var project in subtree)
        {
            string projectRef = $"{rootRef}/project:{project.ProjectId}";
            rootDependsOn.Add(projectRef);

            if (!await AppendCollectionProjectAsync(
                    conn, new CollectionProjectExport(orgId, options, projectRef),
                    project, buffers, coverage, ct))
            {
                withoutSbom++;
            }
        }

        dependencies.Insert(0, new JsonObject { ["ref"] = rootRef, ["dependsOn"] = rootDependsOn });

        var metadataProperties = BuildCollectionMetadataProperties(
            subtree.Count, withoutSbom, coverage, trackerConfigured, options.Filter);

        // Resolved before metadataProperties is finalized below, for the same reason
        // BuildSbomDocumentAsync resolves it early — see SbomAuthorSigner's doc comment.
        var (resolvedSigningKey, resolvedSignatureState, _) = await _signer.ResolveAsync(orgId, ct);
        using var signingKey = resolvedSigningKey;
        AddSignatureStateProperty(metadataProperties, resolvedSignatureState);

        // A collection document does NOT carry D6/D9 revision identity: serialNumber is a fresh
        // random value and version is always 1, on every render, regardless of whether the
        // subtree's data changed. This document therefore FAILS D6 and D9 as currently
        // implemented — this is not a principled exclusion, it is an unresolved gap. The obstacle
        // is a column-shape one, not a semantic one: sbom_export_revisions is keyed by a single
        // project_version_id, and a collection's subject is a subtree of many projects' own
        // is_latest versions rather than one project_version_id — the same kind of change
        // (subtree membership moving) that a project version's own component set already handles
        // correctly by fingerprinting and bumping. Each per-project export nested inside this
        // document still carries its own correct revision identity when exported on its own.
        var doc = new JsonObject
        {
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = options.SpecVersion,
            ["serialNumber"] = $"urn:uuid:{Guid.NewGuid()}",
            ["version"] = 1,
            ["metadata"] = new JsonObject
            {
                ["timestamp"] = _time.GetUtcNow().ToUtcIso(),
                // D1: same tenant identity as a per-project export — see BuildAuthorsMetadata.
                ["authors"] = BuildAuthorsMetadata(orgSlug),
                // D7/D8: a collection document is synthesized from many projects' own data, not
                // amending any single upload, so only dependably belongs in the chain — see
                // BuildToolsMetadata.
                ["tools"] = BuildToolsMetadata(originalToolName: null, originalToolVersion: null),
                // D5: same generation-context claim as a per-project export.
                ["lifecycles"] = BuildLifecyclesMetadata(),
                // No version: a collection has none, and CycloneDX permits omitting it. Inventing
                // one would be the document asserting something the model does not hold. X3
                // (producer/hash/licence/identifiers): the same reasoning as a per-project
                // export's target component applies — a collection describes a folder, not a
                // built artefact, so there is nothing more to add.
                ["component"] = new JsonObject
                {
                    ["type"] = "application",
                    ["bom-ref"] = rootRef,
                    ["name"] = collection.Name,
                },
                ["properties"] = metadataProperties,
            },
            ["components"] = projectEntries,
            ["dependencies"] = dependencies,
        };

        if (options.Variant == "vdr")
        {
            doc["vulnerabilities"] = vulnerabilities;
        }

        // Last: everything above is what gets signed.
        if (signingKey is not null)
        {
            Sbom.SbomAuthorSigner.Attach(doc, signingKey);
        }

        return doc.ToJsonString();
    }

    /// <summary>
    /// Renders one subtree project into the collection document's buffers. Returns false when the
    /// project has no SBOM: it is still listed and marked, because dropping it would make the
    /// document claim the folder holds only the projects someone has uploaded for.
    /// </summary>
    private static async Task<bool> AppendCollectionProjectAsync(
        DbConnection conn,
        CollectionProjectExport export,
        ProjectSubtreeEntry project,
        CollectionBuffers buffers,
        CoverageAccumulator coverage,
        CancellationToken ct)
    {
        var entry = new JsonObject
        {
            ["type"] = project.Classifier,
            ["bom-ref"] = export.ProjectRef,
            ["name"] = project.Name,
        };
        if (project.VersionLabel is not null)
        {
            entry["version"] = project.VersionLabel;
        }

        if (project.ProjectVersionId is null)
        {
            entry["properties"] = new JsonArray(
                new JsonObject { ["name"] = "dependably:noSbom", ["value"] = "true" });
            buffers.Projects.Add(entry);
            buffers.Dependencies.Add(new JsonObject { ["ref"] = export.ProjectRef, ["dependsOn"] = new JsonArray() });
            return false;
        }

        await AppendProjectAsync(
            conn,
            new ProjectExport(export.OrgId, project.ProjectVersionId, export.ProjectRef, export.Options),
            entry,
            buffers,
            coverage,
            ct);
        return true;
    }

    /// <summary>The collection document's metadata properties: the aggregate facts plus coverage.</summary>
    private static JsonArray BuildCollectionMetadataProperties(
        int projectCount, int withoutSbom, CoverageAccumulator coverage, bool trackerConfigured, SbomComponentFilter filter)
    {
        var metadataProperties = new JsonArray(
            new JsonObject { ["name"] = "dependably:aggregate", ["value"] = "collection" },
            new JsonObject { ["name"] = "dependably:selection", ["value"] = LatestPerProjectSelection },
            new JsonObject { ["name"] = "dependably:projectCount", ["value"] = projectCount.ToString(CultureInfo.InvariantCulture) },
            new JsonObject { ["name"] = "dependably:projectsWithoutSbom", ["value"] = withoutSbom.ToString(CultureInfo.InvariantCulture) });
        // DeepClone: a JsonNode can only ever have one parent, and coverage.ToProperties() returns
        // an array whose own entries are already parented to it — appending the nodes themselves
        // (rather than clones) throws the moment the second entry is added.
        foreach (var prop in coverage.ToProperties(trackerConfigured, filter, withoutSbom))
        {
            metadataProperties.Add(prop!.DeepClone());
        }

        return metadataProperties;
    }

    /// <summary>
    /// Resolves the blob coordinate and derived filename for an uploaded document's verbatim
    /// original, or <c>null</c> when the document does not exist for this org.
    /// </summary>
    public async Task<ProjectDocumentOriginal?> ResolveOriginalAsync(
        string orgId, string documentId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<OriginalRow>(new CommandDefinition(
            """
            SELECT pd.blob_key AS BlobKey, pd.sha256 AS Sha256, pd.format AS Format,
                   pd.doc_type AS DocType, p.name AS ProjectName, pv.version AS VersionLabel
            FROM project_documents pd
            JOIN project_versions pv ON pv.id = pd.project_version_id
            JOIN projects p ON p.id = pv.project_id
            WHERE pd.id = @documentId AND pd.org_id = @orgId
            """,
            new { documentId, orgId }, cancellationToken: ct));

        return row is null
            ? null
            : new ProjectDocumentOriginal
            {
                BlobKey = row.BlobKey,
                Sha256 = row.Sha256,
                Format = row.Format,
                DocType = row.DocType,
                FileName = ProjectDocumentNaming.FileName(row.ProjectName, row.VersionLabel, row.DocType),
            };
    }

    // ── Project/version resolution ──────────────────────────────────────────

    // CreatedAt (D6a) is the floor DeriveChangedAt starts from — the earliest a document's data
    // could have "last changed" is when the project_version itself was created, which matters for
    // a version carrying no component/vuln/analysis rows at all.
    private sealed record ResolvedVersion(
        string ProjectVersionId, string ProjectName, string VersionLabel, string Classifier,
        DateTimeOffset CreatedAt);

    // {versionId} accepts the literal "latest", resolved with a one-line query per the fleet
    // contract — B0's helper is not imported here.
    private static async Task<ResolvedVersion?> ResolveProjectVersionAsync(
        System.Data.IDbConnection conn, string orgId, string projectId, string versionId, CancellationToken ct)
    {
        var project = await conn.QuerySingleOrDefaultAsync<ProjectRow>(new CommandDefinition(
            "SELECT name AS Name, classifier AS Classifier FROM projects WHERE id = @projectId AND org_id = @orgId",
            new { projectId, orgId }, cancellationToken: ct));
        if (project is null)
        {
            return null;
        }

        string versionSql = versionId == "latest"
            ? """
              SELECT id AS Id, version AS Version, created_at AS CreatedAt FROM project_versions
              WHERE project_id = @projectId AND org_id = @orgId AND is_latest = 1
              """
            : """
              SELECT id AS Id, version AS Version, created_at AS CreatedAt FROM project_versions
              WHERE id = @versionId AND project_id = @projectId AND org_id = @orgId
              """;

        var version = await conn.QuerySingleOrDefaultAsync<VersionRow>(new CommandDefinition(
            versionSql, new { projectId, orgId, versionId }, cancellationToken: ct));

        return version is null
            ? null
            : new ResolvedVersion(version.Id, project.Name, version.Version, project.Classifier, version.CreatedAt);
    }

    private static async Task<List<ComponentRow>> LoadComponentsAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
        => (await conn.QueryAsync<ComponentRow>(new CommandDefinition(
            """
            SELECT id AS Id, purl AS Purl, name AS Name, version AS Version,
                   ecosystem AS Ecosystem, purl_name AS PurlName,
                   component_type AS ComponentType, sbom_scope AS SbomScope,
                   dependency_kind AS DependencyKind, dependency_scope AS DependencyScope,
                   dependency_path AS DependencyPath, license_spdx AS LicenseSpdx,
                   license_url AS LicenseUrl, license_is_named AS LicenseNamed,
                   version_range AS VersionRange, is_external AS IsExternal,
                   vuln_checked_at AS VulnCheckedAt, component_producer AS ComponentProducer,
                   component_hashes AS ComponentHashes, additional_identifiers AS AdditionalIdentifiers,
                   created_at AS CreatedAt
            FROM sbom_components
            WHERE project_version_id = @pvId AND org_id = @orgId
            ORDER BY name, version
            """,
            new { pvId = projectVersionId, orgId }, cancellationToken: ct))).AsList();

    private static async Task<List<ComponentVulnRow>> LoadComponentVulnsAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
        => (await conn.QueryAsync<ComponentVulnRow>(new CommandDefinition(
            """
            SELECT sc.id AS ComponentId, sc.purl AS ComponentPurl,
                   sc.ecosystem AS Ecosystem, sc.purl_name AS PurlName,
                   sc.dependency_kind AS DependencyKind, sc.dependency_scope AS DependencyScope,
                   v.osv_id AS OsvId, v.aliases AS Aliases, v.severity AS Severity,
                   v.cvss_score AS CvssScore, v.nvd_score AS NvdScore,
                   v.nvd_checked_at AS NvdCheckedAt, v.nvd_asserted_at AS NvdAssertedAt,
                   v.is_kev AS IsKev, v.kev_known_ransomware AS IsKevRansomware,
                   v.kev_due_date AS KevDueDate, v.kev_date_added AS KevDateAdded,
                   v.kev_required_action AS KevRequiredAction, v.kev_cwes AS KevCwes, v.kev_notes AS KevNotes,
                   v.epss_score AS EpssScore, v.epss_percentile AS EpssPercentile,
                   v.ssvc_exploitation AS SsvcExploitation, v.ssvc_automatable AS SsvcAutomatable,
                   v.ssvc_technical_impact AS SsvcTechnicalImpact,
                   v.ssvc_checked_at AS SsvcCheckedAt, v.ssvc_asserted_at AS SsvcAssertedAt,
                   v.osv_id LIKE 'MAL-%' AS IsMalicious, scv.checked_at AS LinkCheckedAt
            FROM sbom_component_vulns scv
            JOIN sbom_components sc ON sc.id = scv.component_id
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            WHERE sc.project_version_id = @pvId AND sc.org_id = @orgId
            ORDER BY sc.name, v.osv_id
            """,
            new { pvId = projectVersionId, orgId }, cancellationToken: ct))).AsList();

    private static async Task<List<AnalysisRow>> LoadAnalysisAsync(
        System.Data.IDbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
    {
        var rows = await conn.QueryAsync<AnalysisRow>(new CommandDefinition(
            """
            SELECT purl_key AS PurlKey, vuln_key AS VulnKey, vex_state AS VexState,
                   vex_justification AS VexJustification, vex_response AS VexResponse,
                   vex_detail AS VexDetail, reachability AS Reachability, updated_at AS UpdatedAt
            FROM project_vuln_analysis
            WHERE project_version_id = @projectVersionId AND org_id = @orgId
            """,
            new { projectVersionId, orgId }, cancellationToken: ct));
        return rows.AsList();
    }

    /// <summary>
    /// One project version's registry-catalogue install-script cross-link, keyed by
    /// <c>sbom_components.id</c> — the boolean-only twin of
    /// <c>SbomAnalysisRepository.ListRegistryFactsAsync</c>'s <c>HasInstallScriptThisVersion</c>
    /// arm, written directly here rather than shared per the fleet contract's "repositories are not
    /// shared" rule. A miss (absent from the returned map) means "unknown to this registry", never
    /// "verified clean" — <see cref="DependablyExportProperties.InstallScript"/> is emitted only on
    /// a positive match for exactly that reason.
    /// </summary>
    private static async Task<Dictionary<string, bool>> LoadInstallScriptFactsAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
    {
        // plane-ok: this is the hosted half of a deliberate two-statement read; the proxy plane is
        // resolved by the cached-plane query immediately below and merged into one map.
        var hosted = await conn.QueryAsync<InstallScriptRow>(new CommandDefinition(
            """
            SELECT c.id AS ComponentId,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM package_versions pv
                       WHERE pv.package_id = p.id AND pv.has_install_script = 1
                         AND pv.version = c.version) THEN 1 ELSE 0 END AS HasInstallScript
            FROM sbom_components c
            JOIN packages p ON p.org_id = c.org_id AND p.ecosystem = c.ecosystem AND p.purl_name = c.purl_name
            WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));

        // xtenant: cache_artifact is the global proxy catalogue; the org filter is on the
        // tenant_artifact_access binding joined below, and on sbom_components driving the read.
        var cached = await conn.QueryAsync<InstallScriptRow>(new CommandDefinition(
            """
            SELECT c.id AS ComponentId,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM cache_artifact ca
                       JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
                       WHERE ca.ecosystem = c.ecosystem AND ca.name = c.purl_name
                         AND ca.has_install_script = 1 AND ca.version = c.version) THEN 1 ELSE 0 END AS HasInstallScript
            FROM sbom_components c
            WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));

        var result = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var row in hosted)
        {
            result[row.ComponentId] = result.GetValueOrDefault(row.ComponentId) || row.HasInstallScript;
        }

        foreach (var row in cached)
        {
            result[row.ComponentId] = result.GetValueOrDefault(row.ComponentId) || row.HasInstallScript;
        }

        return result;
    }

    /// <summary>
    /// dependably's own ingest-time SHA-256 for a component we can attribute to the SPECIFIC
    /// artefact this component names, keyed by <c>sbom_components.id</c> — the stronger claim
    /// D14's hash-emission precedence prefers over a third-party document's assertion. A
    /// component matching neither plane below, or matching one only ambiguously, has no digest
    /// to prefer, and its document-asserted hash, if any, is emitted natively instead — see
    /// <see cref="BuildComponentHashes"/>. Never asserting a digest we cannot attribute to a
    /// specific artefact is the governing rule for both planes: a wrong or unattributable digest
    /// is worse than none, because the consumer's own verification then fails with no way to
    /// tell why.
    ///
    /// <para><b>Hosted plane.</b> <c>package_versions</c> is <c>UNIQUE (package_id, version)</c> —
    /// one row per version, enforced by the schema, so an ecosystem shipping multiple artefacts
    /// per version (a wheel and an sdist) still resolves to exactly one row here and there is no
    /// analogous ambiguity to guard against.</para>
    ///
    /// <para><b>Proxy plane.</b> <c>cache_artifact</c> is <c>UNIQUE (ecosystem, name, version,
    /// filename)</c> — Maven routinely maps one purl coordinate to several filenames (a POM and a
    /// JAR), and an SBOM component names the coordinate, not the file, so when this org's own
    /// bindings resolve MORE THAN ONE filename for a component's coordinate there is no principled
    /// way to choose between their digests; the component is excluded from the result entirely
    /// rather than picking one arbitrarily. Even the single-match case reads the digest from
    /// <c>tenant_artifact_access.content_hash</c> ONLY, never <c>cache_artifact.content_hash</c>
    /// — a bound-but-unhashed tenant row (<c>CacheAccessOrigin.FirstFetchUnidentified</c>, see
    /// <c>CacheAccessRecorder.BindingFor</c>) means this org's own bytes were never hashed, and
    /// the shared row's hash may describe a different tenant's bytes entirely; NULL there is "we
    /// do not know", not "ask the shared row instead" (see
    /// <c>CacheArtifactServeFacts.ContentDivergesFromSharedFacts</c>, which documents the same
    /// invariant for the serve path).</para>
    /// </summary>
    private static async Task<Dictionary<string, string>> LoadOwnHashFactsAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, CancellationToken ct)
    {
        // plane-ok: this is the hosted half of a deliberate two-statement read; the proxy plane is
        // resolved by the cached-plane query immediately below and merged into one map.
        var hosted = await conn.QueryAsync<OwnHashRow>(new CommandDefinition(
            """
            SELECT c.id AS ComponentId, pv.checksum_sha256 AS Sha256
            FROM sbom_components c
            JOIN packages p ON p.org_id = c.org_id AND p.ecosystem = c.ecosystem AND p.purl_name = c.purl_name
            JOIN package_versions pv ON pv.package_id = p.id AND pv.version = c.version
            WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
              AND pv.checksum_sha256 IS NOT NULL
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));

        // xtenant: cache_artifact is the global proxy catalogue; the org filter is on the
        // tenant_artifact_access binding joined below, and on sbom_components driving the read.
        // One row per (component, filename) this org has its own binding for — never resolved
        // through the shared cache_artifact.content_hash — so a component whose coordinate
        // matches more than one filename surfaces as more than one row here, which the grouping
        // below turns into exclusion rather than an arbitrary pick.
        var cached = await conn.QueryAsync<OwnHashRow>(new CommandDefinition(
            """
            SELECT c.id AS ComponentId, ca.filename AS Filename, taa.content_hash AS Sha256
            FROM sbom_components c
            JOIN cache_artifact ca ON ca.ecosystem = c.ecosystem AND ca.name = c.purl_name AND ca.version = c.version
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = c.org_id
            WHERE c.org_id = @orgId AND c.project_version_id = @projectVersionId
              AND taa.content_hash IS NOT NULL
            """,
            new { orgId, projectVersionId }, cancellationToken: ct));

        // Indexer assignment, not ToDictionary: a duplicate ComponentId here is a schema-invariant
        // violation this read should absorb as last-wins, not turn into a hard throw partway
        // through an SBOM export.
#pragma warning disable S3267
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var row in hosted)
        {
            if (row.Sha256 is not null)
            {
                result[row.ComponentId] = row.Sha256;
            }
        }
#pragma warning restore S3267

        foreach (var group in cached.GroupBy(r => r.ComponentId, StringComparer.Ordinal))
        {
            var rows = group.ToList();
            // More than one filename resolves for this coordinate: the component names a
            // coordinate, not a file, so there is no principled way to pick one artefact's digest
            // over the other's — exclude rather than misattribute.
            string? sha256 = rows.Count == 1 ? rows[0].Sha256 : null;
            if (sha256 is null)
            {
                continue;
            }

            result.TryAdd(group.Key, sha256);
        }

        return result;
    }

    /// <summary>The tenant identity D1 (SBOM Author) names — the only per-tenant human-readable
    /// string this data model holds; see <see cref="BuildAuthorsMetadata"/> for why.</summary>
    private static async Task<string> LoadOrgSlugAsync(
        System.Data.Common.DbConnection conn, string orgId, CancellationToken ct) =>
        await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT slug FROM orgs WHERE id = @orgId", new { orgId }, cancellationToken: ct))
        // Defensive only: the caller already resolved a project through this org id, so the row
        // exists. Falling back to the id itself keeps the document author-bearing rather than
        // throwing over a fact this method cannot make any truer.
        ?? orgId;

    /// <summary>
    /// One uploaded document's own recorded tool — D7/D8's "generate or amend" original half.
    /// <paramref name="docType"/> names which document kind is the original this export is
    /// amending: <c>sbom</c> for an inventory/VDR export (whose components came from the
    /// uploaded SBOM), <c>vex</c> for a standalone VEX export (whose analysis rows may equally
    /// have come from manual triage or an uploaded SARIF, in which case there is no single
    /// original tool to name and this returns null).
    /// </summary>
    private static async Task<ToolRow?> LoadDocumentToolAsync(
        System.Data.Common.DbConnection conn, string orgId, string projectVersionId, string docType,
        CancellationToken ct) =>
        await conn.QuerySingleOrDefaultAsync<ToolRow>(new CommandDefinition(
            """
            SELECT tool_name AS ToolName, tool_version AS ToolVersion
            FROM project_documents
            WHERE org_id = @orgId AND project_version_id = @projectVersionId AND doc_type = @docType
            """,
            new { orgId, projectVersionId, docType }, cancellationToken: ct));

    private static JsonObject Prop(string name, string value) => new() { ["name"] = name, ["value"] = value };

    private static string BoolValue(bool value) =>
        value ? DependablyExportProperties.TrueValue : DependablyExportProperties.FalseValue;

    private static string TriStateValue(bool? value) =>
        value is null ? DependablyExportProperties.UnknownValue : BoolValue(value.Value);

    // ── Document-level coverage/freshness metadata ───────────────────────────

    /// <summary>
    /// Buckets one document's components into scanned/unscanned/unscannable using the same
    /// classification <c>SbomPolicyEvaluationService.CountCoverage</c> applies on the analysis
    /// surface, and finds the latest scan stamp among the scanned set. A C# loop over the
    /// already-loaded component rows, not a query — scannability is a code-level classification
    /// (<see cref="SbomScannableComponents"/>), and every caller here already holds the full
    /// component list for the document it is building.
    /// </summary>
    /// <summary>
    /// The scan-coverage tally a document reports: how many of its components this registry
    /// scanned, left unscanned and cannot scan, plus when the newest of those scans ran.
    /// </summary>
    private readonly record struct ScanCoverage(
        int Scanned, int Unscanned, int Unscannable, DateTimeOffset? LastScanAt);

    private static ScanCoverage SummarizeCoverage(
        IReadOnlyList<ComponentRow> components)
    {
        int scanned = 0, unscanned = 0, unscannable = 0;
        DateTimeOffset? lastScanAt = null;

        foreach (var c in components)
        {
            if (!SbomScannableComponents.IsScannable(c.Ecosystem, c.Purl))
            {
                unscannable++;
                continue;
            }

            if (c.VulnCheckedAt is null)
            {
                unscanned++;
                continue;
            }

            scanned++;
            if (lastScanAt is null || c.VulnCheckedAt > lastScanAt)
            {
                lastScanAt = c.VulnCheckedAt;
            }
        }

        return new ScanCoverage(scanned, unscanned, unscannable, lastScanAt);
    }

    /// <summary>
    /// <paramref name="documentCarriesInventory"/> has NO default — the exact shape
    /// <c>DependablyExportProperties.FullInventoryRendered</c>'s own doc comment calls out as the
    /// failure mode a sibling property (<c>FilteredOutCount</c>) already warns against: a
    /// parameter that silently defaults to the affirmative claim is a silent hole, not a
    /// convenience. <c>false</c> only ever comes from <see cref="BuildVexDocumentAsync"/>'s call
    /// site — a standalone VEX document carries no <c>components[]</c> array of its own,
    /// structurally, so it can never truthfully make this claim regardless of how many components
    /// <paramref name="components"/> happens to hold for the underlying project version.
    /// </summary>
    private static JsonArray BuildCoverageProperties(
        IReadOnlyList<ComponentRow> components, bool trackerConfigured, SbomComponentFilter filter,
        int filteredOutCount, bool documentCarriesInventory)
    {
        bool fullInventoryRendered =
            documentCarriesInventory && filter == SbomComponentFilter.All && components.Count > 0;
        return CoverageProperties(
            SummarizeCoverage(components), trackerConfigured, filter, filteredOutCount,
            fullInventoryRendered);
    }

    private static JsonArray CoverageProperties(
        ScanCoverage coverage, bool trackerConfigured, SbomComponentFilter filter,
        int filteredOutCount, bool fullInventoryRendered)
    {
        var (scanned, unscanned, unscannable, lastScanAt) = coverage;
        var arr = new JsonArray
        {
            Prop(DependablyExportProperties.ScannedCount, scanned.ToString(CultureInfo.InvariantCulture)),
            Prop(DependablyExportProperties.UnscannedCount, unscanned.ToString(CultureInfo.InvariantCulture)),
            Prop(DependablyExportProperties.UnscannableCount, unscannable.ToString(CultureInfo.InvariantCulture)),
            Prop(DependablyExportProperties.TrackerConfigured, BoolValue(trackerConfigured)),
            Prop(DependablyExportProperties.ComponentFilter, ScopeFilterValue(filter)),
            Prop(DependablyExportProperties.FilteredOutCount, filteredOutCount.ToString(CultureInfo.InvariantCulture)),
            // P2/P2f (Coverage): distinct from the scan-coverage counts above. See the property's
            // own doc comment for exactly what this states and does not.
            Prop(DependablyExportProperties.FullInventoryRendered, BoolValue(fullInventoryRendered)),
        };
        string? lastScanAtIso = lastScanAt.ToUtcIsoOrNull();
        if (lastScanAtIso is not null)
        {
            arr.Add(Prop(DependablyExportProperties.LastScanAt, lastScanAtIso));
        }

        return arr;
    }

    /// <summary>
    /// Accumulates <see cref="SummarizeCoverage"/> across every project in a collection subtree, so
    /// the aggregate document states one scanned/unscanned/unscannable/last-scan-at answer for the
    /// whole document rather than per-project figures the reader would have to sum themselves.
    /// </summary>
    private sealed class CoverageAccumulator
    {
        private int _scanned;
        private int _unscanned;
        private int _unscannable;
        private DateTimeOffset? _lastScanAt;
        private int _filteredOutCount;

        // filteredOutCount has no default: a call site that forgets it would otherwise report a
        // truthful-looking "0" on a document that actually filtered something out — the same
        // silent-hole class BlockGateRequestConstructionComplianceTests exists to prevent for its
        // own record type.
        public void Add(IReadOnlyList<ComponentRow> components, int filteredOutCount)
        {
            var (scanned, unscanned, unscannable, lastScanAt) = SummarizeCoverage(components);
            _scanned += scanned;
            _unscanned += unscanned;
            _unscannable += unscannable;
            _filteredOutCount += filteredOutCount;
            if (lastScanAt is not null && (_lastScanAt is null || lastScanAt > _lastScanAt))
            {
                _lastScanAt = lastScanAt;
            }
        }

        // P2e: a collection linking to a project with no SBOM at all is the collection-level
        // analogue of a linked SBOM the recipient cannot access — withoutSbom > 0 sinks
        // dependably:full-inventory-rendered to "false" even under an unfiltered (all) render.
        // The empty-set guard (zero components across the WHOLE subtree) applies here exactly as
        // it does for a single project's own document — see BuildCoverageProperties.
        public JsonArray ToProperties(bool trackerConfigured, SbomComponentFilter filter, int withoutSbom)
        {
            bool fullInventoryRendered = filter == SbomComponentFilter.All && withoutSbom == 0
                && (_scanned + _unscanned + _unscannable) > 0;
            return CoverageProperties(
                new ScanCoverage(_scanned, _unscanned, _unscannable, _lastScanAt),
                trackerConfigured, filter, _filteredOutCount, fullInventoryRendered);
        }
    }

    private static AnalysisRow? FindAnalysis(
        Dictionary<(string PurlKey, string VulnKey), AnalysisRow> byKey,
        string purlKey, string osvId, string? aliasesJson)
    {
        if (byKey.TryGetValue((purlKey, osvId), out var direct))
        {
            return direct;
        }

        // The alias fallback matches the design's documented posture: vulnerabilities.aliases has
        // no index, so a VEX/SARIF statement citing an alias id is resolved in memory, scoped to
        // this version's small analysis set — never a SQL join over the alias column.
        foreach (string alias in ParseStringArray(aliasesJson))
        {
            if (byKey.TryGetValue((purlKey, alias), out var byAlias))
            {
                return byAlias;
            }
        }

        return null;
    }

    /// <summary>
    /// Loads one project version's components (and, for a VDR, its advisories) and appends them to
    /// the document being assembled. Split out of the subtree walk so that walk stays a walk.
    /// </summary>
    /// <summary>One subtree project's export coordinates.</summary>
    private readonly record struct ProjectExport(
        string OrgId, string ProjectVersionId, string ProjectRef, SbomExportOptions Options);

    /// <summary>The three arrays the collection document is assembled into.</summary>
    private readonly record struct CollectionBuffers(
        JsonArray Projects, JsonArray Dependencies, JsonArray Vulnerabilities);

    /// <summary>The loop-invariant half of one subtree project's export coordinates.</summary>
    private readonly record struct CollectionProjectExport(
        string OrgId, SbomExportOptions Options, string ProjectRef);

    private static async Task AppendProjectAsync(
        DbConnection conn, ProjectExport export, JsonObject entry, CollectionBuffers buffers,
        CoverageAccumulator coverage, CancellationToken ct)
    {
        var (orgId, projectVersionId, projectRef, options) = export;

        var loaded = await LoadComponentsAsync(conn, orgId, projectVersionId, ct);
        var (components, filteredOutCount) = ApplyComponentFilter(loaded, options.Filter);
        var installScriptFacts = await LoadInstallScriptFactsAsync(conn, orgId, projectVersionId, ct);
        var ownHashFacts = await LoadOwnHashFactsAsync(conn, orgId, projectVersionId, ct);
        coverage.Add(components, filteredOutCount);
        entry["components"] = BuildComponentsArray(
            components, projectRef, installScriptFacts, options.SpecVersion, ownHashFacts);
        buffers.Projects.Add(entry);

        foreach (var node in BuildDependenciesArray(projectRef, components, projectRef))
        {
            buffers.Dependencies.Add(node!.DeepClone());
        }

        if (options.Variant != "vdr")
        {
            return;
        }

        var vulnRows = await LoadComponentVulnsAsync(conn, orgId, projectVersionId, ct);
        vulnRows = FilterVulnsToKeptComponents(vulnRows, components);
        // Loaded per project and never shared: a purl-keyed lookup spanning the subtree would
        // bleed one project's VEX suppression onto another project's finding.
        var analysisRows = await LoadAnalysisAsync(conn, orgId, projectVersionId, ct);
        var affectedApps = await CountAffectedApplicationsAsync(
            conn, orgId, vulnRows.Select(v => v.OsvId).Distinct(StringComparer.Ordinal).ToList(), ct);
        foreach (var vuln in BuildVulnerabilitiesArray(vulnRows, analysisRows, installScriptFacts, affectedApps, projectRef))
        {
            buffers.Vulnerabilities.Add(vuln!.DeepClone());
        }
    }

    // Null is not an empty analysis object — it is the signal to omit the CycloneDX "analysis"
    // key entirely. An empty JsonObject would emit `"analysis": {}`, a different document.
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "null means 'omit this CycloneDX key'; an empty node emits a different document.")]
    private static JsonObject? BuildAnalysis(AnalysisRow? a)
    {
        if (a?.VexState is null)
        {
            return null;
        }

        var obj = new JsonObject { ["state"] = a.VexState };
        if (a.VexJustification is not null)
        {
            obj["justification"] = a.VexJustification;
        }

        if (a.VexResponse is not null)
        {
            obj["response"] = new JsonArray(JsonValue.Create(a.VexResponse));
        }

        if (a.VexDetail is not null)
        {
            obj["detail"] = a.VexDetail;
        }

        return obj;
    }

    // Null is not an empty ratings array — it is the signal to omit the CycloneDX "ratings" key.
    // Both call sites test for null before assigning; `[]` would emit `"ratings": []`, which
    // asserts "rated, with no ratings" rather than "unrated".
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "null means 'omit this CycloneDX key'; an empty node emits a different document.")]
    private static JsonArray? BuildRatings(string? severity, double? cvssScore)
    {
        if (severity is null && cvssScore is null)
        {
            return null;
        }

        var rating = new JsonObject();
        if (cvssScore is not null)
        {
            rating["score"] = cvssScore.Value;
        }

        if (severity is not null)
        {
            rating["severity"] = severity.ToLowerInvariant();
        }

        return new JsonArray(rating);
    }

    private static JsonObject BuildSource(string vulnId) => vulnId switch
    {
        _ when vulnId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) => new JsonObject
        {
            ["name"] = "NVD",
            ["url"] = $"https://nvd.nist.gov/vuln/detail/{vulnId}",
        },
        _ when vulnId.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase) => new JsonObject
        {
            ["name"] = "GitHub Advisories",
            ["url"] = $"https://github.com/advisories/{vulnId}",
        },
        _ => new JsonObject { ["name"] = "OSV" },
    };

    /// <summary>
    /// A component's bom-ref. <paramref name="prefix"/> is null for a single-project document,
    /// where the bare purl is unique; an aggregate document passes the project's own ref, because
    /// the SAME library in two projects would otherwise collide on a ref CycloneDX requires to be
    /// unique across the document. The <c>purl</c> FIELD is never prefixed — that is the value a
    /// consumer matches on.
    /// </summary>
    private static string RefOf(ComponentRow c, string? prefix = null)
    {
        string bare = c.Purl ?? (c.Version is null ? c.Name : $"{c.Name}@{c.Version}");
        return prefix is null ? bare : $"{prefix}/{bare}";
    }

    private static List<string> ParseStringArray(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    // ── Row projections ──────────────────────────────────────────────────────

    private sealed class ProjectRow
    {
        public string Name { get; set; } = "";
        public string Classifier { get; set; } = "";
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class VersionRow
    {
        public string Id { get; set; } = "";
        public string Version { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ComponentRow
    {
        public string Id { get; set; } = "";
        public string? Purl { get; set; }
        public string Name { get; set; } = "";
        public string? Version { get; set; }
        public string? Ecosystem { get; set; }
        public string? PurlName { get; set; }
        public string? ComponentType { get; set; }
        public string? SbomScope { get; set; }
        public string? DependencyKind { get; set; }
        public string? DependencyScope { get; set; }
        public string? DependencyPath { get; set; }
        public string? LicenseSpdx { get; set; }
        public string? LicenseUrl { get; set; }
        public bool? LicenseNamed { get; set; }
        public string? VersionRange { get; set; }
        public bool? IsExternal { get; set; }
        public DateTimeOffset? VulnCheckedAt { get; set; }
        public string? ComponentProducer { get; set; }
        public string? ComponentHashes { get; set; }
        public string? AdditionalIdentifiers { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ComponentVulnRow
    {
        public string ComponentId { get; set; } = "";
        public string ComponentPurl { get; set; } = "";
        public string? Ecosystem { get; set; }
        public string? PurlName { get; set; }
        public string? DependencyKind { get; set; }
        public string? DependencyScope { get; set; }
        public DateTimeOffset LinkCheckedAt { get; set; }
        public string OsvId { get; set; } = "";
        public string? Aliases { get; set; }
        public string? Severity { get; set; }
        public double? CvssScore { get; set; }
        public double? NvdScore { get; set; }
        public string? NvdCheckedAt { get; set; }
        public string? NvdAssertedAt { get; set; }
        public bool IsKev { get; set; }
        public bool? IsKevRansomware { get; set; }
        public string? KevDueDate { get; set; }
        public string? KevDateAdded { get; set; }
        public string? KevRequiredAction { get; set; }
        public string? KevCwes { get; set; }
        public string? KevNotes { get; set; }
        public double? EpssScore { get; set; }
        public double? EpssPercentile { get; set; }
        public string? SsvcExploitation { get; set; }
        public string? SsvcAutomatable { get; set; }
        public string? SsvcTechnicalImpact { get; set; }
        public string? SsvcCheckedAt { get; set; }
        public string? SsvcAssertedAt { get; set; }
        public bool IsMalicious { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class AnalysisRow
    {
        public string PurlKey { get; set; } = "";
        public string VulnKey { get; set; } = "";
        public string? VexState { get; set; }
        public string? VexJustification { get; set; }
        public string? VexResponse { get; set; }
        public string? VexDetail { get; set; }
        public string? Reachability { get; set; }
        public DateTimeOffset UpdatedAt { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class VulnLookupRow
    {
        public string OsvId { get; set; } = "";
        public string? Severity { get; set; }
        public double? CvssScore { get; set; }
        public double? NvdScore { get; set; }
        public string? NvdCheckedAt { get; set; }
        public string? NvdAssertedAt { get; set; }
        public bool IsKev { get; set; }
        public bool? IsKevRansomware { get; set; }
        public string? KevDueDate { get; set; }
        public string? KevDateAdded { get; set; }
        public string? KevRequiredAction { get; set; }
        public string? KevCwes { get; set; }
        public string? KevNotes { get; set; }
        public double? EpssScore { get; set; }
        public double? EpssPercentile { get; set; }
        public string? SsvcExploitation { get; set; }
        public string? SsvcAutomatable { get; set; }
        public string? SsvcTechnicalImpact { get; set; }
        public string? SsvcCheckedAt { get; set; }
        public string? SsvcAssertedAt { get; set; }
        public bool IsMalicious { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class InstallScriptRow
    {
        public string ComponentId { get; set; } = "";
        public bool HasInstallScript { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class OwnHashRow
    {
        public string ComponentId { get; set; } = "";
        // Only ever populated by the proxy-plane query; the hosted-plane query never selects it,
        // and Dapper leaves an unselected property at its default. It exists solely so more than
        // one row can be told apart per component (see LoadOwnHashFactsAsync's grouping) — its
        // value itself is never read.
        public string? Filename { get; set; }
        public string? Sha256 { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class ToolRow
    {
        public string? ToolName { get; set; }
        public string? ToolVersion { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class AffectedApplicationsRow
    {
        public string OsvId { get; set; } = "";
        public int Count { get; set; }
    }

    private sealed class OriginalRow
    {
        public string BlobKey { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string Format { get; set; } = "";
        public string DocType { get; set; } = "";
        public string ProjectName { get; set; } = "";
        public string VersionLabel { get; set; } = "";
    }
}

/// <summary>Blob coordinate and derived display name for an uploaded document's original bytes.</summary>
public sealed class ProjectDocumentOriginal
{
    public string BlobKey { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public string Format { get; init; } = "";
    public string DocType { get; init; } = "";
    public string FileName { get; init; } = "";
}
