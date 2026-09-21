using System.Globalization;
using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Reads SPDX 2.3 JSON into the same <see cref="CycloneDxDocument"/> / <see cref="CycloneDxComponent"/>
/// projection <see cref="CycloneDxParser"/> writes. SPDX ingest is a second front end onto the one
/// <c>sbom_components</c> pipeline, not a second pipeline: the merge, the dependency-graph walk,
/// the policy evaluator, the vulnerability scan queue and the exporter all read whichever parser
/// produced a document identically, because they never see which one it was.
///
/// <para><b>Accepted version.</b> SPDX-2.3 only. It is the version current real producers default
/// to (Syft, Trivy) and the one CISA's 2026 baseline names as widely deployed; 2.2 is close enough
/// in package-object shape that widening the accepted set later is a plausible low-risk follow-up,
/// the same way CycloneDX ingest widened its own range one version at a time.</para>
///
/// <para><b>SPDX 3.0 needs its own parser, not an extension of this one.</b> 3.0 replaces the flat
/// <c>packages[]</c> / <c>relationships[]</c> arrays this parser reads with a JSON-LD
/// <c>@graph</c> of typed nodes (<c>software_Package</c>, a <c>Relationship</c> shaped
/// <c>{from, to[], relationshipType}</c> rather than <c>{spdxElementId, relatedSpdxElement}</c>),
/// identifies a purl through <c>externalIdentifier[].externalIdentifierType</c> instead of
/// <c>externalRefs[].referenceType</c>, and carries a licence under
/// <c>simpleLicensing_licenseExpression</c> rather than <c>licenseConcluded</c>/<c>licenseDeclared</c>.
/// None of this parser's property paths resolve against a 3.0 document — a 3.0 upload would
/// silently extract nothing rather than fail loudly, which the strict spdxVersion check below
/// exists specifically to turn into a 422 instead.</para>
///
/// <para><b>The document's subject is not one of its own components.</b> SPDX has no
/// <c>metadata.component</c> the way CycloneDX does — the package a <c>documentDescribes</c>
/// entry or <c>DESCRIBES</c> relationship names lives in the same flat <c>packages[]</c> array as
/// everything else. That package becomes <see cref="CycloneDxDocument.Root"/> and is excluded from
/// <see cref="CycloneDxDocument.Components"/>, preserving the same separation CycloneDX keeps
/// between the SBOM's subject and its inventory.</para>
///
/// <para><b>A real producer's DESCRIBES target is not always its dependency graph's root.</b> A
/// directory-scanning generator (Syft's <c>dir:</c> source) describes the scanned directory
/// itself, while <c>DEPENDS_ON</c>/<c>DEPENDENCY_OF</c> edges are rooted at the manifest's own
/// package one level below it. When that happens the resolved root ref has no outgoing edge in
/// the relationship graph, and every component reads <c>graph-unknown</c> — the same honest
/// fallback <see cref="SbomDependencyGraph"/> already gives a CycloneDX document with a partial or
/// absent <c>dependencies[]</c> graph. This is not a bug to route around: it is what the document
/// actually claims about its own shape. <c>ReadContainedRefs</c> separately reads any
/// <c>CONTAINS</c> edges the same directory-scanning shape commonly declares from that root
/// straight to every package — but into <see cref="CycloneDxComponent.ContainmentDeclared"/>, a
/// purely D17-facing signal, never into this graph: folding a containment edge into a
/// shortest-path depth walk would read a genuinely multi-hop <c>DEPENDS_ON</c> chain as a false
/// single-hop <c>direct</c> dependency the moment a root-level <c>CONTAINS</c> to the same
/// component also exists, which is a claim the document never made.</para>
/// </summary>
public static class SpdxParser
{
    /// <summary>The one spdxVersion ingest accepts. Anything else is a 422, never a best-effort parse.</summary>
    public const string AcceptedSpdxVersion = "SPDX-2.3";

    /// <summary>SPDX's two spelled-out "no assertion" tokens, folded to the same null CycloneDX's own absent fields already use.</summary>
    private static readonly string[] UnassertedTokens = ["NOASSERTION", "NONE"];

    /// <summary>True when the document declares an SPDX spdxVersion, whatever else it carries.</summary>
    public static bool IsSpdx(JsonElement root) =>
        root.ValueKind == JsonValueKind.Object
        && JsonRead.String(root, "spdxVersion") is { } version
        && version.StartsWith("SPDX-", StringComparison.Ordinal);

    /// <summary>Parses the whole document, or throws <see cref="SbomParseException"/>.</summary>
    public static CycloneDxDocument Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new SbomParseException(SbomParseFailure.Malformed);
        }

        string specVersion = JsonRead.String(root, "spdxVersion")
            ?? throw new SbomParseException(SbomParseFailure.Malformed);
        if (!string.Equals(specVersion, AcceptedSpdxVersion, StringComparison.Ordinal))
        {
            throw new SbomParseException(SbomParseFailure.UnsupportedSpecVersion, specVersion);
        }

        var (toolName, toolVersion) = ReadTool(root);
        string? documentRef = JsonRead.String(root, "SPDXID");
        string? rootRef = ResolveDescribedRef(root, documentRef);
        var containedRefs = ReadContainedRefs(root);
        var packages = ReadPackages(root, containedRefs);

        CycloneDxRootComponent? rootComponent = null;
        var components = new List<CycloneDxComponent>(packages.Count);
        foreach (var package in packages)
        {
            if (rootRef is not null && string.Equals(package.BomRef, rootRef, StringComparison.Ordinal))
            {
                rootComponent = new CycloneDxRootComponent(package.BomRef, package.Name, package.Version, package.Type);
                continue;
            }

            components.Add(package);
        }

        return components.Count > SbomDocumentLimits.MaxComponents
            ? throw new SbomParseException(
                SbomParseFailure.TooManyComponents,
                SbomDocumentLimits.MaxComponents.ToString(CultureInfo.InvariantCulture))
            : new CycloneDxDocument(
                specVersion, toolName, toolVersion, rootComponent, components, ReadRelationships(root), []);
    }

    // creationInfo.creators[] holds free-form "Tool: <name>-<version>", "Organization: …" and
    // "Person: …" entries in any order and any count; the first Tool entry is the producing tool,
    // the same "first entry wins" tolerance CycloneDxParser.ReadTool applies to metadata.tools.
    private static (string? Name, string? Version) ReadTool(JsonElement root)
    {
        var creationInfo = JsonRead.Object(root, "creationInfo");
        if (creationInfo is null)
        {
            return (null, null);
        }

        foreach (var creator in JsonRead.Array(creationInfo.Value, "creators"))
        {
            if (creator.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            string? text = creator.GetString();
            if (text is null || !text.StartsWith("Tool: ", StringComparison.Ordinal))
            {
                continue;
            }

            string toolText = text["Tool: ".Length..];
            int boundary = LastVersionBoundary(toolText);
            return boundary < 0
                ? (toolText, null)
                : (toolText[..boundary], toolText[(boundary + 1)..]);
        }

        return (null, null);
    }

    // "name-version" is the SPDX creators[] convention for a tool entry ("syft-1.46.0",
    // "cyclonedx-cli-0.28.1"): the last hyphen immediately before a digit-led segment is the
    // version boundary. A tool name that itself ends in a digit-led hyphenated segment reads as
    // its own version instead — the same ambiguity CycloneDX's single-string 1.4-era author field
    // accepts, and both fields are display-only.
    private static int LastVersionBoundary(string text)
    {
        int dash = text.LastIndexOf('-');
        return dash >= 0 && dash + 1 < text.Length && char.IsAsciiDigit(text[dash + 1]) ? dash : -1;
    }

    // documentDescribes is the pre-2.3 shape (still commonly emitted alongside relationships[] for
    // backward compatibility); a DESCRIBES relationship from the document's own SPDXID is the
    // shape 2.3 itself prefers. Both name the SBOM's subject, so both are read, documentDescribes
    // first because it names the subject directly rather than requiring a relationship scan.
    private static string? ResolveDescribedRef(JsonElement root, string? documentRef) =>
        FromDocumentDescribes(root) ?? FromDescribesRelationship(root, documentRef);

    private static string? FromDocumentDescribes(JsonElement root)
    {
        foreach (var entry in JsonRead.Array(root, "documentDescribes"))
        {
            if (entry.ValueKind == JsonValueKind.String)
            {
                string? described = entry.GetString();
                if (!string.IsNullOrWhiteSpace(described))
                {
                    return described;
                }
            }
        }

        return null;
    }

    private static string? FromDescribesRelationship(JsonElement root, string? documentRef)
    {
        foreach (var entry in JsonRead.Array(root, "relationships"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? type = JsonRead.String(entry, "relationshipType");
            if (!string.Equals(type, "DESCRIBES", StringComparison.Ordinal))
            {
                continue;
            }

            string? from = JsonRead.String(entry, "spdxElementId");
            if (documentRef is not null && from is not null
                && !string.Equals(from, documentRef, StringComparison.Ordinal))
            {
                continue;
            }

            string? to = JsonRead.String(entry, "relatedSpdxElement");
            if (to is not null)
            {
                return to;
            }
        }

        return null;
    }

    private static List<CycloneDxComponent> ReadPackages(JsonElement root, IReadOnlySet<string> containedRefs)
    {
        var packages = new List<CycloneDxComponent>();
        foreach (var entry in JsonRead.Array(root, "packages"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? name = JsonRead.String(entry, "name");
            if (string.IsNullOrWhiteSpace(name))
            {
                // name is SPDX-mandatory on a package too; a row with no name has no identity to
                // merge on and no label to render — the same rule CycloneDxParser.ReadComponents
                // applies to a components[] entry with no name.
                continue;
            }

            string? spdxId = JsonRead.String(entry, "SPDXID");

            var (license, licenseUnasserted) = ReadLicenseTracked(entry);
            var (producer, producerUnasserted) = ReadEntityTracked(entry, "supplier");

            var explicitUnknown = new List<string>(2);
            if (producerUnasserted)
            {
                explicitUnknown.Add(SbomExplicitUnknownFields.Producer);
            }

            if (licenseUnasserted)
            {
                explicitUnknown.Add(SbomExplicitUnknownFields.License);
            }

            packages.Add(new CycloneDxComponent(
                BomRef: spdxId,
                Name: name,
                Version: JsonRead.String(entry, "versionInfo"),
                Type: ReadType(entry),
                Purl: ReadPurl(entry),
                Scope: null,
                LicenseSpdx: license,
                Description: Clip(JsonRead.String(entry, "description"), SbomProjectionLimits.MaxDescriptionLength),
                Author: Clip(ReadEntity(entry, "originator"), SbomProjectionLimits.MaxTextLength),
                Copyright: Clip(ReadUnasserted(entry, "copyrightText"), SbomProjectionLimits.MaxTextLength),
                Group: null,
                WebsiteUrl: ReadLinkedUrl(entry, "homepage"),
                VcsUrl: null,
                IssueTrackerUrl: null,
                DistributionUrl: ReadLinkedUrl(entry, "downloadLocation"),
                HashesJson: ReadHashesJson(entry),
                VersionRange: null,
                IsExternal: null,
                ManifestDevDeclared: null,
                Producer: Clip(producer, SbomProjectionLimits.MaxTextLength),
                AdditionalIdentifiersJson: ReadAdditionalIdentifiers(entry),
                ExplicitUnknownFieldsJson: SbomExplicitUnknownFields.Serialize(explicitUnknown),
                ContainmentDeclared: spdxId is not null && containedRefs.Contains(spdxId)));
        }

        return packages;
    }

    // primaryPackagePurpose (SPDX 2.3 §7.24) admits APPLICATION/FRAMEWORK/LIBRARY/CONTAINER/
    // OPERATING-SYSTEM/DEVICE/FIRMWARE/FILE/SOURCE/ARCHIVE/INSTALL/OTHER — a wider vocabulary than
    // CycloneDX's own closed component.type enum, which has no member for SOURCE, ARCHIVE, INSTALL
    // or OTHER. component_type is exported verbatim (SbomExportService writes
    // c.ComponentType ?? "library" with no enum guard of its own — see SpdxParser's own doc
    // comment on why an unmapped value cannot be allowed to reach that column at all), so only the
    // eight purposes CycloneDX actually has a matching member for are mapped; the rest are
    // unrepresentable in this projection today and read as no assertion rather than an invalid one.
    private static readonly IReadOnlyDictionary<string, string> PrimaryPackagePurposeToComponentType =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["APPLICATION"] = "application",
            ["FRAMEWORK"] = "framework",
            ["LIBRARY"] = "library",
            ["CONTAINER"] = "container",
            ["OPERATING-SYSTEM"] = "operating-system",
            ["DEVICE"] = "device",
            ["FIRMWARE"] = "firmware",
            ["FILE"] = "file",
        };

    private static string? ReadType(JsonElement package)
    {
        string? purpose = JsonRead.String(package, "primaryPackagePurpose");
        return purpose is not null && PrimaryPackagePurposeToComponentType.TryGetValue(purpose, out string? type)
            ? type
            : null;
    }

    // externalRefs[] carries several unrelated taxonomies (SECURITY/cpe23Type, PERSISTENT-ID/…);
    // the PACKAGE-MANAGER category's purl referenceType is the one this projection's identity
    // column reads, matching what CycloneDxParser reads from components[].purl. First match wins,
    // the same tolerance CycloneDxParser.ReadExternalReferences applies to a repeated type.
    private static string? ReadPurl(JsonElement package)
    {
        foreach (var reference in JsonRead.Array(package, "externalRefs"))
        {
            string? category = JsonRead.String(reference, "referenceCategory");
            string? type = JsonRead.String(reference, "referenceType");
            if (!string.Equals(category, "PACKAGE-MANAGER", StringComparison.Ordinal)
                || !string.Equals(type, "purl", StringComparison.Ordinal))
            {
                continue;
            }

            string? locator = JsonRead.String(reference, "referenceLocator");
            if (locator is not null)
            {
                return locator;
            }
        }

        return null;
    }

    // externalRefs categories beyond PACKAGE-MANAGER/purl: SECURITY's cpe22Type/cpe23Type (D13b —
    // never synthesized, captured only when the document itself asserted one) and PERSISTENT-ID's
    // swh/gitoid (SWHID/OmniBOR, D13c). SPDX 2.3 defines no PERSISTENT-ID (or other) referenceType
    // for a bare commit hash or a UUID the way CycloneDX's pedigree.commits[].uid and a
    // urn:uuid:-typed externalReferences entry do — those two kinds are genuinely absent from
    // this format's own vocabulary, not merely unread here. PACKAGE-MANAGER's other referenceTypes
    // (maven-central, npm, nuget, bower, …) are alternate package-manager coordinates for the SAME
    // identity purl already carries, not a distinct identifier kind, so none of them is read here.
    private static string? ReadAdditionalIdentifiers(JsonElement package)
    {
        var identifiers = new List<(string Kind, string Value)>();
        foreach (var reference in JsonRead.Array(package, "externalRefs"))
        {
            string? category = JsonRead.String(reference, "referenceCategory");
            string? type = JsonRead.String(reference, "referenceType");
            string? locator = JsonRead.String(reference, "referenceLocator");
            if (locator is null)
            {
                continue;
            }

            string? kind = (category, type) switch
            {
                ("SECURITY", "cpe22Type") => SbomIdentifierKinds.Cpe,
                ("SECURITY", "cpe23Type") => SbomIdentifierKinds.Cpe,
                ("PERSISTENT-ID", "swh") => SbomIdentifierKinds.Swhid,
                ("PERSISTENT-ID", "gitoid") => SbomIdentifierKinds.Omnibor,
                _ => null,
            };
            // Never Clip: see CycloneDxParser.ReadAdditionalIdentifiers and
            // SbomAdditionalIdentifiers' own doc comment for why an over-long identifier is
            // dropped whole rather than truncated into a different, wrong one.
            if (kind is not null && SbomAdditionalIdentifiers.AcceptValue(locator) is { } value)
            {
                identifiers.Add((kind, value));
            }
        }

        return SbomAdditionalIdentifiers.Serialize(identifiers);
    }

    // licenseConcluded is the SBOM author's own analysis of what a package's licence actually is;
    // licenseDeclared is what the package's own manifest states. Concluded is preferred as the
    // stronger claim, matching how tools that populate both intend them to be read — declared is
    // the fallback for a document that only ever asserts one. Either an SPDX expression already,
    // so it round-trips into license_spdx unchanged, same as CycloneDX's licenses[].expression.
    //
    // D16c's URL fallback (sbom_components.license_url/license_is_named) is deliberately NOT
    // wired for SPDX ingest — a documented scope decision, not an oversight. licenseConcluded/
    // licenseDeclared are always LicenseExpression strings (they may contain a SPDX LicenseRef-
    // token for a non-listed licence, but the field itself has no separate name+url structure the
    // way CycloneDX's licenses[].license object does), so there is nothing in THIS pair of fields
    // to wire. SPDX 2.3 DOES have a real analogue — hasExtractedLicensingInfos[], which pairs a
    // LicenseRef- licenseId with a name and crossRef[].url entries, exactly CycloneDX's
    // license.name/url shape — but reading it requires cross-referencing a LicenseRef- token back
    // to that array, which this parser does not do. A future revision that wires it needs its own
    // SbomIngestVersion bump, the same as every other extraction change.
    //
    // The WasExplicitlyUnasserted flag is CISA X4/P4a's ingest-scoring signal
    // (SbomExplicitUnknownFields.License): true only when NEITHER field resolved to a real value
    // AND at least one of the two was explicitly NOASSERTION/NONE rather than simply absent —
    // a document that never mentions either property leaves the flag false, the silent-absence
    // case the flag exists to distinguish from.
    private static (string? Value, bool WasExplicitlyUnasserted) ReadLicenseTracked(JsonElement package)
    {
        var (concluded, concludedUnasserted) = ReadUnassertedTracked(package, "licenseConcluded");
        if (concluded is not null)
        {
            return (concluded, false);
        }

        var (declared, declaredUnasserted) = ReadUnassertedTracked(package, "licenseDeclared");
        return declared is not null ? (declared, false) : (null, concludedUnasserted || declaredUnasserted);
    }

    // supplier and originator are SPDX's own producer/author split: supplier identifies who
    // distributes the package (CISA's Component Producer, matching CycloneDX's publisher — see
    // CycloneDxParser.ReadProducer), originator identifies who created it (CISA's Component
    // Author, matching CycloneDX's authors[]/author — see CycloneDxParser.ReadAuthor). Neither
    // collapses into the other here, matching the same split component_producer and
    // component_author already keep on the CycloneDX side of this projection.
    //
    // Author (originator) never needs the explicit-unknown flag — it is not one of X4's
    // "indicate unknown" duty fields CISA's 2026 baseline names — so this wrapper discards it and
    // only Producer's call site (ReadEntityTracked directly) keeps it.
    private static string? ReadEntity(JsonElement package, string propertyName) =>
        ReadEntityTracked(package, propertyName).Value;

    // Producer's own call site (X4/D10e — SbomExplicitUnknownFields.Producer): true when
    // "supplier" itself resolved to NOASSERTION/NONE, false when it named a real entity or was
    // simply absent from the document.
    private static (string? Value, bool WasExplicitlyUnasserted) ReadEntityTracked(
        JsonElement package, string propertyName)
    {
        var (raw, unasserted) = ReadUnassertedTracked(package, propertyName);
        if (raw is null)
        {
            return (null, unasserted);
        }

        string? matchedPrefix = EntityPrefixes.FirstOrDefault(prefix => raw.StartsWith(prefix, StringComparison.Ordinal));
        if (matchedPrefix is not null)
        {
            raw = raw[matchedPrefix.Length..];
        }

        return (StripParentheticalSuffix(raw), false);
    }

    // SPDX's Person:/Organization: form optionally carries a parenthetical contact suffix —
    // "Jane Doe (jane@example.com)" — that CycloneDX's own author/publisher strings never carry.
    // Stripping it keeps the two formats' equivalent facts equal, and keeps an email address out
    // of component_producer/component_author, neither of which this table's privacy sweep covers.
    private static string StripParentheticalSuffix(string raw)
    {
        int parenIndex = raw.IndexOf(" (", StringComparison.Ordinal);
        return parenIndex >= 0 && raw.EndsWith(')') ? raw[..parenIndex] : raw;
    }

    private static readonly string[] EntityPrefixes = ["Organization: ", "Person: ", "Tool: "];

    // NOASSERTION and NONE are SPDX's own literal "not asserted" tokens; folded to the same null
    // an absent property already reads as. CISA's P4a two-state vocabulary — unknown to the
    // author vs withheld by the author — is now defined (DependablyExportProperties), and
    // NOASSERTION maps onto exactly one of those two states: it IS the author explicitly saying
    // "unknown", never "withheld" (SPDX has no withholding token at all). So the export-facing
    // signal for a NOASSERTION field and a field this package never mentioned is correctly THE
    // SAME "unknown" property either way — the vocabulary this parser folds toward already
    // represents what NOASSERTION asserts. What NOASSERTION does carry, and folding to null here
    // discards, is a QUALITY distinction: a producer that wrote NOASSERTION engaged with the
    // question and said so explicitly, where one that omitted the property never considered it at
    // all — a genuine signal for scoring an ingested document's trustworthiness, but a THIRD axis
    // (explicit-vs-silent), not a value on the unknown/withheld axis this parser's output feeds.
    // That axis belongs on the ingest-scoring surface that reads the raw document, not on this
    // projection, which is why it stays out of scope here rather than being invented as a second
    // vocabulary on this class's own return value — except at the two call sites
    // (ReadLicenseTracked, ReadEntityTracked's Producer use) CISA X4 actually names as
    // "indicate unknown" duty fields, which route through ReadUnassertedTracked below instead and
    // surface the axis on CycloneDxComponent.ExplicitUnknownFieldsJson for
    // SbomConformanceScorer to read. Every other call site here keeps discarding the distinction
    // via this wrapper, because copyrightText/homepage/downloadLocation/originator are not scored
    // duty fields and inventing a signal nothing reads would be exactly the kind of assumption
    // this codebase's own conventions warn against.
    private static string? ReadUnasserted(JsonElement package, string propertyName) =>
        ReadUnassertedTracked(package, propertyName).Value;

    // The shared primitive both ReadUnasserted and the two duty-field-tracked readers build on:
    // NOASSERTION and NONE are SPDX's own literal "not asserted" tokens. WasExplicitlyUnasserted
    // is true only when the property WAS PRESENT and spelled one of those tokens — a property the
    // document never wrote at all reads (null, false), the same silent-absence case a caller that
    // discards the flag already could not tell apart from an explicit one.
    private static (string? Value, bool WasExplicitlyUnasserted) ReadUnassertedTracked(
        JsonElement package, string propertyName)
    {
        string? raw = JsonRead.String(package, propertyName);
        if (raw is null)
        {
            return (null, false);
        }

        bool unasserted = UnassertedTokens.Contains(raw, StringComparer.Ordinal);
        return unasserted ? (null, true) : (raw, false);
    }

    // homepage and downloadLocation are the closest SPDX 2.3 package fields to CycloneDX's
    // externalReferences website/distribution types; SPDX has no vcs or issue-tracker equivalent
    // at the package level, so those two columns stay null for an SPDX-sourced component.
    private static string? ReadLinkedUrl(JsonElement package, string propertyName)
    {
        string? raw = ReadUnasserted(package, propertyName);
        return raw is not null && IsHttpUrl(raw) ? Clip(raw, SbomProjectionLimits.MaxTextLength) : null;
    }

    private static bool IsHttpUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var parsed)
        && (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps);

    // checksums[] rounds-trip into the same [{"alg","content"}] shape CycloneDxParser.ReadHashes
    // writes, so a component page and the exporter read one column regardless of which parser
    // populated it. The algorithm spelling itself is stored VERBATIM here — SPDX's "SHA256" is
    // not rewritten to CycloneDX's hyphenated "SHA-256" at ingest, so the column keeps saying
    // exactly what the document asserted. The two vocabularies are reconciled at the export
    // boundary instead (SbomExportService.AssertedAlgAliases), where the target format's own
    // closed enum is what decides an algorithm's exported spelling either way — ingest has no
    // reason to duplicate that decision for a value nothing here branches on.
    private static string? ReadHashesJson(JsonElement package)
    {
        var hashes = new List<Dictionary<string, string>>();
        foreach (var checksum in JsonRead.Array(package, "checksums"))
        {
            string? algorithm = JsonRead.String(checksum, "algorithm");
            string? value = JsonRead.String(checksum, "checksumValue");
            if (algorithm is not null && value is not null)
            {
                hashes.Add(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["alg"] = algorithm,
                    ["content"] = value,
                });
            }
        }

        if (hashes.Count == 0)
        {
            return null;
        }

        string json = JsonSerializer.Serialize(hashes);
        // Clipping would produce invalid JSON, so an oversized set is dropped whole, matching
        // CycloneDxParser.ReadHashes's posture.
        return json.Length <= SbomProjectionLimits.MaxHashesJsonLength ? json : null;
    }

    // relationships[] carries many unrelated relationship types (CONTAINS, DESCRIBES, …); only
    // types that assert an actual dependency edge feed this adjacency, because it becomes
    // SbomDependencyGraph's BFS input — the shortest-route walk that produces dependency_kind
    // (direct/transitive) AND dependency_path. DEPENDS_ON and its inverse DEPENDENCY_OF are the
    // base pair; the six scoped DEPENDENCY_OF forms SPDX 2.3 also defines
    // (BUILD_/RUNTIME_/DEV_/OPTIONAL_/PROVIDED_/TEST_DEPENDENCY_OF) carry the identical "is a
    // dependency of" semantics DEPENDENCY_OF does, only scoped to a build phase, so they take the
    // same to-is-parent/from-is-child direction. CONTAINS is DELIBERATELY EXCLUDED from this
    // adjacency — see ReadContainedRefs and CycloneDxComponent.ContainmentDeclared's own doc
    // comment for why folding a containment edge into a shortest-path depth/route walk mints a
    // false claim a document never made (a root-level CONTAINS to a component the document ALSO
    // declares as a genuine two-hop DEPENDS_ON dependency of something else would otherwise
    // overwrite that real depth with a false "direct"). Every other relationship type stays
    // unmapped and out of scope, the same narrow hand-picked subset this parser already keeps
    // elsewhere — SPDX's remaining vocabulary (DESCRIBES, GENERATED_FROM, PATCH_APPLIED, …)
    // genuinely does not describe a dependency edge at all. Both DEPENDS_ON/DEPENDENCY_OF
    // spellings are read because both appear in current producer output — a directory-scanning
    // cataloguer (Syft) writes DEPENDENCY_OF, a manifest-focused generator is as likely to write
    // DEPENDS_ON.
    private static readonly IReadOnlySet<string> DependencyOfDirectionTypes = new HashSet<string>(StringComparer.Ordinal)
    {
        "DEPENDENCY_OF",
        "BUILD_DEPENDENCY_OF",
        "RUNTIME_DEPENDENCY_OF",
        "DEV_DEPENDENCY_OF",
        "OPTIONAL_DEPENDENCY_OF",
        "PROVIDED_DEPENDENCY_OF",
        "TEST_DEPENDENCY_OF",
    };

    private static Dictionary<string, IReadOnlyList<string>> ReadRelationships(JsonElement root)
    {
        var graph = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var entry in JsonRead.Array(root, "relationships"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? type = JsonRead.String(entry, "relationshipType");
            string? from = JsonRead.String(entry, "spdxElementId");
            string? to = JsonRead.String(entry, "relatedSpdxElement");
            if (from is null || to is null)
            {
                continue;
            }

            string? parent = null;
            string? child = null;
            if (string.Equals(type, "DEPENDS_ON", StringComparison.Ordinal))
            {
                parent = from;
                child = to;
            }
            else if (type is not null && DependencyOfDirectionTypes.Contains(type))
            {
                parent = to;
                child = from;
            }

            if (parent is null || child is null)
            {
                continue;
            }

            if (!graph.TryGetValue(parent, out var children))
            {
                children = [];
                graph[parent] = children;
            }

            children.Add(child);
        }

        var resolved = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (parentRef, children) in graph)
        {
            resolved[parentRef] = children;
        }

        return resolved;
    }

    // CISA's Relationship attribute is defined as INCLUSION, not depth — so a CONTAINS edge
    // satisfies D17's "a relationship is asserted" duty for its target (see
    // CycloneDxComponent.ContainmentDeclared's own doc comment) without ever joining the
    // dependency-graph adjacency ReadRelationships builds. This is a document-wide set of
    // relatedSpdxElement refs, not a per-parent adjacency: D17 only needs to know a component WAS
    // named as contained by something, never by what or how deep.
    private static HashSet<string> ReadContainedRefs(JsonElement root)
    {
        var refs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in JsonRead.Array(root, "relationships"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? type = JsonRead.String(entry, "relationshipType");
            if (!string.Equals(type, "CONTAINS", StringComparison.Ordinal))
            {
                continue;
            }

            string? to = JsonRead.String(entry, "relatedSpdxElement");
            if (to is not null)
            {
                refs.Add(to);
            }
        }

        return refs;
    }

    private static string? Clip(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
