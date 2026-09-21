using Dependably.Protocol.Provenance;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Scores one stored <c>doc_type='sbom'</c> document against CISA's 2026 SBOM Minimum Elements —
/// the ingest half of the baseline this registry already exports against (D683/D688). Every
/// verdict is a read over <see cref="ProjectDocument"/> and its version's <see cref="SbomComponentRow"/>
/// set, both already held before this class runs; nothing here re-parses the stored blob, per the
/// acceptance criterion CISA's own issue records.
///
/// <para><b>The governing rule: a state may only reflect what the SUPPLIER did or did not do.</b>
/// Anything attributable to a requirement CISA does not impose, to this registry's own parser, to
/// the document's format, or to this registry's own storage bound is
/// <see cref="SbomElementState.NotApplicable"/> or <see cref="SbomElementState.NotAssessed"/> —
/// never <see cref="SbomElementState.Absent"/>. A false "this supplier is missing X" published
/// about a third party's document is reputational damage this feature must never cause, so every
/// rule below is written to fail CLOSED toward "we do not know" rather than toward blaming a
/// supplier for this registry's own limitation.</para>
///
/// <para><b>Three states, not two — the whole product.</b> An element on a real document is
/// <see cref="SbomElementState.Present"/> (a usable value), <see cref="SbomElementState.Absent"/>
/// (missing, and the document says nothing about why, with no applicable excuse), or
/// <see cref="SbomElementState.ExplicitlyUnknown"/> (missing, and the document itself explicitly
/// says so — SPDX's <c>NOASSERTION</c>/<c>NONE</c>, or this registry's own <c>dependably:</c>
/// vocabulary read back from a re-uploaded export). The third state is CISA-conformant supplier
/// behaviour (P4b) and must never read as a failure the way the second does. Two further states
/// exist because a real element can be un-scoreable without being a claim about the supplier at
/// all: <see cref="SbomElementState.NotApplicable"/> when the document's OWN FORMAT (or the
/// specific format VERSION it declares) has no mechanism to carry the element, and
/// <see cref="SbomElementState.NotAssessed"/> when dependably itself does not parse the element
/// from an ingested document today, or cannot tell a genuine absence apart from its own storage
/// bound silently dropping an over-long value (see <see cref="ScoreComponentRollup"/>'s
/// <c>ComponentVerdict.NotAssessed</c> arm).</para>
///
/// <para><b>Component Data elements are a rollup, not a single instance.</b> D10-D17 apply to
/// every component the document lists (X3), so one document produces one COUNT per state rather
/// than one instance verdict — <see cref="SbomElementVerdict.Total"/>/<see cref="SbomElementVerdict.PresentCount"/>/
/// <see cref="SbomElementVerdict.ExplicitUnknownCount"/>/<see cref="SbomElementVerdict.NotAssessedCount"/>/
/// <see cref="SbomElementVerdict.AbsentCount"/>. The verdict's own <see cref="SbomElementVerdict.State"/>
/// is a derived summary — <see cref="SbomElementState.Absent"/> the moment even one component has
/// a genuine, unexcused gap (<c>AbsentCount &gt; 0</c>), regardless of how many others are fine;
/// <see cref="SbomElementState.NotAssessed"/> only when EVERY component fell into that bucket (we
/// learned nothing at all); <see cref="SbomElementState.Present"/> otherwise — because the counts,
/// not a collapsed label, are the actionable answer: "named missing elements, never a single
/// percentage" applies exactly as much to "112 of 140 components have no producer" as it does to
/// a document-level field.</para>
///
/// <para><b>Explicit-unknown tracking.</b> <see cref="SbomComponentRow.ExplicitUnknownFields"/> is
/// populated by <see cref="SpdxParser"/> from SPDX's own <c>NOASSERTION</c>/<c>NONE</c> (Producer
/// and License only — see <see cref="SbomExplicitUnknownFields"/>'s own class doc comment), and by
/// <see cref="CycloneDxParser"/> from all four component-scoped members, ONLY from this registry's
/// own <c>dependably:*-status</c> properties — the vocabulary a dependably EXPORT writes,
/// read back on a re-upload so a dependably-to-dependably round trip demonstrates the practice
/// rather than reading as silent absence for every component this registry itself already marked
/// unknown. A CycloneDX document from any OTHER producer carries none of these properties, so the
/// column stays null for it exactly as for a plain CycloneDX document with no opinion on the
/// matter — <see cref="ScoreExplicitUnknowns"/> is what turns that asymmetry into
/// <see cref="SbomElementState.NotApplicable"/> rather than blaming a third-party tool for not
/// using a private vocabulary it has never heard of (Producer/License only — D12/D13's own
/// explicit-unknown state is scored per component by <see cref="ClassifyVersion"/>/
/// <see cref="ClassifyIdentifiers"/> directly and does not feed this document-level P4 rollup, the
/// same scope <see cref="ScoreExplicitUnknowns"/> already held before this vocabulary widened).</para>
/// </summary>
public static class SbomConformanceScorer
{
    // ── SBOM Metadata (D1-D9) ───────────────────────────────────────────────
    public const string SbomAuthor = "D1";
    public const string SbomAuthorSignature = "D2";
    public const string SbomDataFormatName = "D3";
    public const string SbomDataFormatVersion = "D4";
    public const string SbomGenerationContext = "D5";
    public const string SbomTimestamp = "D6";
    public const string SbomToolName = "D7";
    public const string SbomToolVersion = "D8";
    public const string SbomVersion = "D9";

    // ── Component Data (D10-D17) ─────────────────────────────────────────────
    public const string ComponentProducer = "D10";
    public const string ComponentName = "D11";
    public const string ComponentVersion = "D12";
    public const string ComponentIdentifiers = "D13";
    public const string ComponentHashValue = "D14";
    public const string ComponentHashAlgorithm = "D15";
    public const string ComponentLicense = "D16";
    public const string ComponentDependencyRelationship = "D17";

    // ── Practices and Processes (assessable subset) ─────────────────────────
    public const string Coverage = "P2";
    public const string ExplicitUnknowns = "P4";
    public const string Frequency = "P5";
    public const string MachineProcessable = "P6";

    /// <summary>Every element id this scorer emits, in display order.</summary>
    public static readonly IReadOnlyList<string> ElementOrder =
    [
        SbomAuthor, SbomAuthorSignature, SbomDataFormatName, SbomDataFormatVersion,
        SbomGenerationContext, SbomTimestamp, SbomToolName, SbomToolVersion, SbomVersion,
        ComponentProducer, ComponentName, ComponentVersion, ComponentIdentifiers,
        ComponentHashValue, ComponentHashAlgorithm, ComponentLicense, ComponentDependencyRelationship,
        Coverage, ExplicitUnknowns, Frequency, MachineProcessable,
    ];

    private const string SpdxFormat = "spdx-json";

    // CycloneDX's earliest accepted version. metadata.lifecycles (D5) is a 1.5+ field — see
    // CycloneDxParser's own comment on DefinedLifecyclePhases — so a document declaring exactly
    // this version cannot carry D5 at all, a format-version fact rather than a supplier gap.
    private const string CycloneDxVersionPredatingLifecycles = "1.4";

    /// <summary>
    /// Scores <paramref name="document"/> — which must be its version's <c>doc_type='sbom'</c>
    /// row — against <paramref name="components"/>, that same version's full component set.
    /// </summary>
    public static SbomConformanceScorecard Score(
        ProjectDocument document, IReadOnlyList<SbomComponentRow> components)
    {
        var producer = ScoreComponentRollup(ComponentProducer, components, ClassifyProducer);
        var license = ScoreComponentRollup(ComponentLicense, components, ClassifyLicense);

        List<SbomElementVerdict> elements =
        [
            // D1: dependably parses neither an ingested document's own author claim today — see
            // the class doc comment.
            new(SbomAuthor, SbomElementCategory.Metadata, SbomElementState.NotAssessed),
            ScoreAuthorSignature(document),
            // D3: project_documents.format is NOT NULL on every stored row.
            new(SbomDataFormatName, SbomElementCategory.Metadata, SbomElementState.Present),
            // D4: both ingest front ends refuse a document outside their accepted spec-version
            // set, so a stored sbom row always carries one. Whether a specific accepted version
            // is ITSELF deprecated by the format's own maintainers is not evaluated — see the
            // class doc comment's descope list.
            new(SbomDataFormatVersion, SbomElementCategory.Metadata, SbomElementState.Present),
            ScoreGenerationContext(document),
            // D6: the document's OWN metadata.timestamp/created is not parsed — only this
            // registry's receipt time (uploaded_at) is stored, a different claim.
            new(SbomTimestamp, SbomElementCategory.Metadata, SbomElementState.NotAssessed),
            ScoreToolName(document),
            ScoreToolVersion(document),
            // D9: the document's own version/serialNumber/documentNamespace identity is not
            // parsed at ingest today.
            new(SbomVersion, SbomElementCategory.Metadata, SbomElementState.NotAssessed),
        ];

        elements.Add(producer);

        // D11: name is NOT NULL on every stored component row — trivially satisfied by every
        // document that reached this table at all.
        elements.Add(new SbomElementVerdict(
            ComponentName, SbomElementCategory.Component, SbomElementState.Present,
            Total: components.Count, PresentCount: components.Count,
            ExplicitUnknownCount: 0, AbsentCount: 0, NotAssessedCount: 0));

        // D12a: a versionRange is a different, but still present, identifier of change — the same
        // predicate SbomExportService's own VersionStatus duty uses. Neither format's NATIVE
        // versionInfo/version is established as carrying a NOASSERTION-eligible token, but a
        // dependably-exported CycloneDX document's own dependably:version-status property, read
        // back into SbomExplicitUnknownFields.Version, is — see ClassifyVersion.
        elements.Add(ScoreComponentRollup(ComponentVersion, components, ClassifyVersion));

        // D13a: an identifier is purl OR any additional-identifier entry — the same predicate
        // SbomExportService's own IdentifierStatus duty uses. Neither format's native fields carry
        // a NOASSERTION-equivalent for "no identifier at all", but dependably's own
        // dependably:identifier-status readback does — see ClassifyIdentifiers.
        elements.Add(ScoreComponentRollup(ComponentIdentifiers, components, ClassifyIdentifiers));

        // D14/D15: component_hashes holds {alg,content} pairs together — this projection cannot
        // represent a hash value without its algorithm, so the two elements share one verdict
        // shape from stored data. NULL is NEVER read as Absent: both parsers drop an
        // over-length hashes array to NULL on the exact same bound that turns a genuine assertion
        // into silence (the bound-becomes-assertion shape), and sbom_components carries no marker
        // distinguishing "no hash asserted" from "dropped for length" — until that marker exists,
        // every NULL here is NotAssessed, never a claim that the supplier provided nothing.
        var hashVerdict = ScoreComponentRollup(
            ComponentHashValue, components,
            c => c.ComponentHashes is not null ? ComponentVerdict.Present : ComponentVerdict.NotAssessed);
        elements.Add(hashVerdict);
        elements.Add(hashVerdict with { ElementId = ComponentHashAlgorithm });

        elements.Add(license);

        // D17: a direct or transitive position is a demonstrated relationship. graph-unknown is
        // SbomDependencyGraph's own fallback for a root this registry's own walk could not reach —
        // our limitation, not the supplier's, so it is NotAssessed rather than Absent. A
        // component the document's dependency GRAPH never mentions is still Present when the
        // document declared it via a SPDX CONTAINS edge instead (ContainmentDeclared) — see
        // ClassifyDependencyRelationship. Only a component named by neither is a genuine,
        // unexcused silence.
        elements.Add(ScoreComponentRollup(ComponentDependencyRelationship, components, ClassifyDependencyRelationship));

        elements.Add(ScoreCoverage(components));
        elements.Add(ScoreExplicitUnknowns(document, producer, license));

        // P5/P6: see the class doc comment on the practices this class can assess from a single
        // stored document versus the ones (P1, P3) that need history or infrastructure facts this
        // scorer is never handed.
        elements.Add(new SbomElementVerdict(Frequency, SbomElementCategory.Practice, SbomElementState.Present));
        elements.Add(new SbomElementVerdict(MachineProcessable, SbomElementCategory.Practice, SbomElementState.Present));

        return new SbomConformanceScorecard(document.Id, document.Format, document.SpecVersion, components.Count, elements);
    }

    private static SbomElementVerdict ScoreGenerationContext(ProjectDocument document)
    {
        if (string.Equals(document.Format, SpdxFormat, StringComparison.Ordinal))
        {
            // SPDX 2.3 defines no lifecycle-equivalent element at all — a structural fact about
            // the format, not a claim about this particular supplier.
            return new SbomElementVerdict(SbomGenerationContext, SbomElementCategory.Metadata, SbomElementState.NotApplicable);
        }

        if (document.Lifecycles is not null)
        {
            return new SbomElementVerdict(SbomGenerationContext, SbomElementCategory.Metadata, SbomElementState.Present);
        }

        if (string.Equals(document.SpecVersion, CycloneDxVersionPredatingLifecycles, StringComparison.Ordinal))
        {
            // metadata.lifecycles is a CycloneDX 1.5+ field; a 1.4 document cannot carry it
            // regardless of supplier intent.
            return new SbomElementVerdict(SbomGenerationContext, SbomElementCategory.Metadata, SbomElementState.NotApplicable);
        }

        // A 1.5+ document with no stored lifecycles is ambiguous the same way a NULL
        // component_hashes is (see ComponentHashValue above): CycloneDxParser drops an
        // over-length lifecycles array to NULL on the same bound that turns a real assertion
        // into silence, and project_documents carries no marker distinguishing "declared none"
        // from "dropped for length" — so this cannot be read as a supplier gap until one exists.
        return new SbomElementVerdict(SbomGenerationContext, SbomElementCategory.Metadata, SbomElementState.NotAssessed);
    }

    // D2 (SBOM Author Signature). signature_status is populated only for a document uploaded
    // while verify_sbom_signatures was 'warn' or 'block' (SbomController's admission check) —
    // never while the policy was 'off', and never with the gate's own synthesized 'unverifiable'
    // (a fact about live policy, not about the document, and never persisted —
    // ADR-sbom-author-signature). SbomController's admission check DOES run for SPDX — it scores
    // every non-CycloneDX upload SbomSignatureVerdict.Unsigned and persists 'unsigned' under
    // 'warn'/'block' the same as it would for a genuinely unsigned CycloneDX document, so format-
    // switching cannot evade the policy (SbomAuthorSignatureIngestTests.cs's
    // SpdxDocument_UnderBlock_IsScoredAsUnsigned_NotExempt pins exactly this). What SPDX cannot
    // carry is a REAL signature: it defines no signature carrier at all, so a persisted 'unsigned'
    // on an SPDX row is never evidence the supplier chose not to sign — the format gave them
    // nothing to sign with — and the SCORE below must not read that as their D2 failure, the same
    // pattern ScoreGenerationContext already applies to D5.
    //
    // A NULL row is ambiguous between "this registry never checked" and, for a CycloneDX
    // document, "this build predates the check" — both read as NotAssessed. 'unanchored'
    // (SbomSignatureVerdict.UnanchoredStatus, never ProvenanceStatuses' own vocabulary — see that
    // record's class doc comment) is this registry's own trust-store gap, not a claim about the
    // supplier, so it reads NotAssessed too, under the same "under-claim toward what dependably
    // itself could not verify" rule as every other NotAssessed arm in this file.
    private static SbomElementVerdict ScoreAuthorSignature(ProjectDocument document) =>
        new(SbomAuthorSignature, SbomElementCategory.Metadata,
            string.Equals(document.Format, SpdxFormat, StringComparison.Ordinal)
                ? SbomElementState.NotApplicable
                : document.SignatureStatus switch
                {
                    ProvenanceStatuses.Verified => SbomElementState.Present,
                    ProvenanceStatuses.Failed => SbomElementState.Absent,
                    ProvenanceStatuses.Unsigned => SbomElementState.Absent,
                    SbomSignatureVerdict.UnanchoredStatus => SbomElementState.NotAssessed,
                    _ => SbomElementState.NotAssessed,
                });

    private static SbomElementVerdict ScoreToolName(ProjectDocument document) =>
        new(SbomToolName, SbomElementCategory.Metadata,
            document.ToolName is not null ? SbomElementState.Present : SbomElementState.Absent);

    private static SbomElementVerdict ScoreToolVersion(ProjectDocument document)
    {
        if (document.ToolName is null)
        {
            // Nothing named to have a version of — D8 has no subject on this document, distinct
            // from a named tool that omitted its own version.
            return new SbomElementVerdict(SbomToolVersion, SbomElementCategory.Metadata, SbomElementState.NotApplicable);
        }

        if (document.ToolVersion is not null)
        {
            return new SbomElementVerdict(SbomToolVersion, SbomElementCategory.Metadata, SbomElementState.Present);
        }

        // X4/D8b, read back: the named tool's own entry explicitly carried dependably's own
        // dependably:tool-version-status=unknown property (a dependably export re-ingested here)
        // — the document itself said so, which is CISA-conformant P4b behaviour, never a silent
        // gap the way an ordinary named-tool-no-version document is.
        return new SbomElementVerdict(
            SbomToolVersion, SbomElementCategory.Metadata,
            document.ToolVersionExplicitlyUnknown ? SbomElementState.ExplicitlyUnknown : SbomElementState.Absent);
    }

    /// <summary>One component's classification for a single element's rollup.</summary>
    private enum ComponentVerdict
    {
        Present,
        ExplicitlyUnknown,
        NotAssessed,
        Absent,
    }

    private static ComponentVerdict ClassifyProducer(SbomComponentRow c) =>
        c.ComponentProducer is not null
            ? ComponentVerdict.Present
            : HasExplicitUnknown(c, SbomExplicitUnknownFields.Producer)
                ? ComponentVerdict.ExplicitlyUnknown
                : ComponentVerdict.Absent;

    private static ComponentVerdict ClassifyLicense(SbomComponentRow c) =>
        c.LicenseSpdx is not null
            ? ComponentVerdict.Present
            : HasExplicitUnknown(c, SbomExplicitUnknownFields.License)
                ? ComponentVerdict.ExplicitlyUnknown
                : ComponentVerdict.Absent;

    private static ComponentVerdict ClassifyVersion(SbomComponentRow c) =>
        c.Version is not null || c.VersionRange is not null
            ? ComponentVerdict.Present
            : HasExplicitUnknown(c, SbomExplicitUnknownFields.Version)
                ? ComponentVerdict.ExplicitlyUnknown
                : ComponentVerdict.Absent;

    private static ComponentVerdict ClassifyIdentifiers(SbomComponentRow c) =>
        c.Purl is not null || c.AdditionalIdentifiers is not null
            ? ComponentVerdict.Present
            : HasExplicitUnknown(c, SbomExplicitUnknownFields.Identifier)
                ? ComponentVerdict.ExplicitlyUnknown
                : ComponentVerdict.Absent;

    // direct/transitive: the document declared a relationship. graph-unknown: SbomDependencyGraph
    // declared a graph it could not route this component through — this registry's own routing
    // limitation (see SbomDependencyGraph's own doc comment on the distinction), not a claim the
    // supplier said nothing. null: the document's dependencies[]/relationships[] graph never
    // mentions this component at all — genuine, unexcused silence. Used by P2 Coverage only —
    // Coverage is a depth/completeness practice, so it stays blind to a containment edge that
    // asserts no depth at all, unlike D17 below.
    private static ComponentVerdict ClassifyGraphPosition(SbomComponentRow c) => c.DependencyKind switch
    {
        "direct" or "transitive" => ComponentVerdict.Present,
        "graph-unknown" => ComponentVerdict.NotAssessed,
        _ => ComponentVerdict.Absent,
    };

    // D17 (Component Dependency Relationship): the same DependencyKind arms ClassifyGraphPosition
    // reads, but ContainmentDeclared can UPGRADE either of the two non-Present arms — a document
    // that asserted a CONTAINS edge for this component has demonstrated a relationship for D17's
    // purpose (CISA's Relationship attribute is defined as inclusion, not depth) whether the
    // separate DEPENDS_ON-family walk placed the component at all (null DependencyKind) or merely
    // could not route it from the resolved root (graph-unknown, this registry's own limitation on
    // THAT walk — a real gap CONTAINS is independent evidence against). It is deliberately NOT
    // folded into DependencyKind/DependencyPath themselves (see
    // CycloneDxComponent.ContainmentDeclared's own doc comment for why minting a depth claim from
    // containment would be a false one) — only D17's own rollup reads it, so P2 Coverage (a
    // depth/completeness practice) stays exactly as ClassifyGraphPosition already scored it.
    private static ComponentVerdict ClassifyDependencyRelationship(SbomComponentRow c) =>
        c.DependencyKind is "direct" or "transitive" || c.ContainmentDeclared
            ? ComponentVerdict.Present
            : c.DependencyKind == "graph-unknown" ? ComponentVerdict.NotAssessed : ComponentVerdict.Absent;

    /// <summary>
    /// Builds one component-collection element's rollup: classifies every component, then derives
    /// <c>State</c> from the counts — <see cref="SbomElementState.Absent"/> the moment one
    /// component has a genuine, unexcused gap; <see cref="SbomElementState.NotAssessed"/> only
    /// when every component fell into that bucket; <see cref="SbomElementState.Present"/>
    /// otherwise. A zero-component document is <see cref="SbomElementState.Absent"/> outright — a
    /// real, document-level fact (there is nothing here to support the non-affectedness
    /// inference), not this registry's limitation.
    /// </summary>
    private static SbomElementVerdict ScoreComponentRollup(
        string elementId,
        IReadOnlyList<SbomComponentRow> components,
        Func<SbomComponentRow, ComponentVerdict> classify)
    {
        int present = 0, explicitUnknown = 0, notAssessed = 0, absent = 0;
        foreach (var component in components)
        {
            switch (classify(component))
            {
                case ComponentVerdict.Present: present++; break;
                case ComponentVerdict.ExplicitlyUnknown: explicitUnknown++; break;
                case ComponentVerdict.NotAssessed: notAssessed++; break;
                default: absent++; break;
            }
        }

        var state = components.Count == 0
            ? SbomElementState.Absent
            : absent > 0
                ? SbomElementState.Absent
                : notAssessed == components.Count
                    ? SbomElementState.NotAssessed
                    : SbomElementState.Present;

        return new SbomElementVerdict(
            elementId, SbomElementCategory.Component, state,
            Total: components.Count, PresentCount: present,
            ExplicitUnknownCount: explicitUnknown, AbsentCount: absent, NotAssessedCount: notAssessed);
    }

    private static bool HasExplicitUnknown(SbomComponentRow component, string field) =>
        SbomExplicitUnknownFields.Parse(component.ExplicitUnknownFields).Contains(field);

    /// <summary>
    /// P2 Coverage: CISA's 2021 "Depth" element, which required at least direct dependencies, is
    /// replaced by Coverage, which names NO minimum depth — so a flat, fully direct inventory
    /// satisfies it exactly as well as one with deep transitive chains. This reuses D17's own
    /// per-component graph classification (a direct OR transitive position both count, and
    /// graph-unknown is this registry's own routing limitation, never the supplier's) rather than
    /// inventing a depth floor the cited clause abolished.
    /// </summary>
    private static SbomElementVerdict ScoreCoverage(IReadOnlyList<SbomComponentRow> components) =>
        ScoreComponentRollup(Coverage, components, ClassifyGraphPosition) with { Category = SbomElementCategory.Practice };

    /// <summary>
    /// P4 Explicit Unknowns. P4a is conditional — "WHEN a required field is absent, state
    /// whether it is unknown or withheld" — so a document with no unexcused Producer/Licence
    /// absences satisfies it VACUOUSLY: the duty never triggered. <paramref name="producer"/> and
    /// <paramref name="license"/> are D10/D16's already-computed rollups, reused rather than
    /// recomputed so the two verdicts can never drift from what this same document's component
    /// table shows.
    ///
    /// <para>When there IS at least one unexcused absence: an SPDX document had a universally
    /// recognized mechanism (<c>NOASSERTION</c>) and simply did not use it everywhere, which is
    /// <see cref="SbomElementState.Absent"/>. A CycloneDX document that has demonstrated ANY use
    /// of this registry's own <c>dependably:</c> vocabulary (read back by
    /// <see cref="CycloneDxParser"/>) has proven the mechanism was available to it, so a remaining
    /// gap is scored the same way; one that never demonstrates the vocabulary at all is
    /// <see cref="SbomElementState.NotApplicable"/> — plain CycloneDX defines no vocabulary a
    /// third-party producer could plausibly have used, so an unexcused gap there is not
    /// attributable to the supplier failing an available duty.</para>
    /// </summary>
    private static SbomElementVerdict ScoreExplicitUnknowns(
        ProjectDocument document, SbomElementVerdict producer, SbomElementVerdict license)
    {
        // Counts duty-FIELD instances, not components: each component contributes one Producer
        // check and one Licence check, so Total is twice the component count and every other
        // count here is summed the same way across both fields.
        int total = (producer.Total ?? 0) + (license.Total ?? 0);
        int present = (producer.PresentCount ?? 0) + (license.PresentCount ?? 0);
        int explicitUnknown = (producer.ExplicitUnknownCount ?? 0) + (license.ExplicitUnknownCount ?? 0);
        int absent = (producer.AbsentCount ?? 0) + (license.AbsentCount ?? 0);

        SbomElementState state;
        if (absent == 0)
        {
            state = SbomElementState.Present;
        }
        else
        {
            bool isSpdx = string.Equals(document.Format, SpdxFormat, StringComparison.Ordinal);
            state = isSpdx || explicitUnknown > 0 ? SbomElementState.Absent : SbomElementState.NotApplicable;
        }

        return new SbomElementVerdict(
            ExplicitUnknowns, SbomElementCategory.Practice, state,
            Total: total, PresentCount: present,
            ExplicitUnknownCount: explicitUnknown, AbsentCount: absent, NotAssessedCount: 0);
    }
}
