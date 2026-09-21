using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Reads the documented CycloneDX subset out of a JSON document with <c>System.Text.Json</c>.
///
/// <para>The parse is deliberately tolerant everywhere the specification allows a producer to
/// vary and strict only where a wrong answer would be silently wrong: the document must declare
/// <c>bomFormat: "CycloneDX"</c> and a specVersion inside <see cref="AcceptedSpecVersions"/>, and
/// a component must carry a name. <c>metadata.tools</c> is read in both its shapes — the 1.4
/// array of tool objects and the 1.5+ object holding a <c>components</c>/<c>services</c> array —
/// because a producer pinned to either shape is common in the wild.</para>
///
/// <para><c>scope</c> is kept only when it is one of the three values the column admits; a
/// producer inventing a fourth is treated as having declared none, which is what keeps a
/// display-only field from failing an upload.</para>
/// </summary>
public static class CycloneDxParser
{
    /// <summary>The specVersions ingest accepts. Anything else is a 422, never a best-effort parse.</summary>
    public static readonly IReadOnlySet<string> AcceptedSpecVersions =
        new HashSet<string>(StringComparer.Ordinal) { "1.4", "1.5", "1.6", "1.7" };

    /// <summary>components[].scope values the <c>sbom_scope</c> CHECK admits.</summary>
    private static readonly IReadOnlySet<string> AcceptedScopes =
        new HashSet<string>(StringComparer.Ordinal) { "required", "optional", "excluded" };

    /// <summary>
    /// metadata.lifecycles[].phase values CycloneDX 1.5+ defines. An entry naming one of these is
    /// kept as a defined phase; anything else falls back to the free-form name/description shape.
    /// </summary>
    private static readonly IReadOnlySet<string> DefinedLifecyclePhases =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "design", "pre-build", "build", "post-build", "operations", "discovery", "decommission",
        };

    /// <summary>
    /// components[].properties[] names read as the manifest dev-dependency marker: the CycloneDX
    /// taxonomy's own npm/PyPI/Go spellings (the ones a real producer like cdxgen writes), plus a
    /// NuGet spelling of this repo's own choosing — no official taxonomy entry exists for NuGet.
    /// </summary>
    private static readonly IReadOnlySet<string> ManifestDevPropertyNames =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "cdx:npm:package:development",
            "cdx:pypi:package:development",
            "cdx:gomod:package:development",
            "cdx:nuget:package:development",
        };

    /// <summary>
    /// CISA X4/P4a, read back: the FOUR component-scoped "indicate unknown" duty-field property
    /// names a dependably EXPORT writes, mapped to <see cref="SbomExplicitUnknownFields"/>'s
    /// storage vocabulary. No other CycloneDX producer emits these property names, so a document
    /// from any other tool never matches any of them — this is what lets a dependably-exported
    /// document, re-uploaded to another dependably instance, demonstrate the Explicit Unknowns
    /// practice instead of reading as silent absence for every component this registry itself
    /// already marked unknown.
    ///
    /// <para><b>Keys, not a hand-count: this dictionary's key set is asserted equal to every
    /// <c>DependablyExportProperties.*Status</c> constant minus <see cref="DependablyExportProperties.ToolVersionStatus"/>
    /// (document-level — read back separately by <see cref="ReadTool"/>, never through a
    /// component's <c>properties[]</c>) and <see cref="DependablyExportProperties.HashStatus"/>
    /// (deliberately not tracked — see <see cref="SbomExplicitUnknownFields"/>'s own class doc
    /// comment for why), by <c>CycloneDxParserStatusPropertyCoverageTests</c>.</b> That test is
    /// this map's compliance gate: a seventh <c>*Status</c> property landing in
    /// <see cref="DependablyExportProperties"/> without also landing here (or in that test's
    /// documented exclusion set) fails it, rather than silently exporting a duty-field marker this
    /// parser never reads back.</para>
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, string> ExplicitUnknownPropertyNames =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [DependablyExportProperties.ProducerStatus] = SbomExplicitUnknownFields.Producer,
            [DependablyExportProperties.LicenseStatus] = SbomExplicitUnknownFields.License,
            [DependablyExportProperties.VersionStatus] = SbomExplicitUnknownFields.Version,
            [DependablyExportProperties.IdentifierStatus] = SbomExplicitUnknownFields.Identifier,
        };

    /// <summary>
    /// The two values <see cref="DependablyExportProperties.AbsenceReason"/> ever writes. Matched
    /// defensively against both even though nothing emits <c>withheld</c> today (see that
    /// method's own doc comment) — this ingest-side vocabulary does not distinguish unknown from
    /// withheld, it only records that the duty field was addressed explicitly, either way.
    /// </summary>
    private static readonly IReadOnlySet<string> ExplicitUnknownValues =
        new HashSet<string>(StringComparer.Ordinal)
        {
            DependablyExportProperties.UnknownValue, DependablyExportProperties.WithheldValue,
        };

    /// <summary>Parses the whole document, or throws <see cref="SbomParseException"/>.</summary>
    public static CycloneDxDocument Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new SbomParseException(SbomParseFailure.Malformed);
        }

        string? bomFormat = JsonRead.String(root, "bomFormat");
        if (!string.Equals(bomFormat, "CycloneDX", StringComparison.Ordinal))
        {
            throw new SbomParseException(SbomParseFailure.WrongDocumentKind);
        }

        string specVersion = JsonRead.String(root, "specVersion")
            ?? throw new SbomParseException(SbomParseFailure.Malformed);
        if (!AcceptedSpecVersions.Contains(specVersion))
        {
            throw new SbomParseException(SbomParseFailure.UnsupportedSpecVersion, specVersion);
        }

        var metadata = JsonRead.Object(root, "metadata");
        var (toolName, toolVersion, toolVersionExplicitlyUnknown) = ReadTool(metadata);

        var components = ReadComponents(root);
        return new CycloneDxDocument(
            specVersion,
            toolName,
            toolVersion,
            ReadRootComponent(metadata),
            components,
            ReadDependencies(root),
            ReadStatements(root),
            ReadLifecycles(metadata),
            toolVersionExplicitlyUnknown);
    }

    /// <summary>True when the document declares itself CycloneDX, whatever else it carries.</summary>
    public static bool IsCycloneDx(JsonElement root) =>
        root.ValueKind == JsonValueKind.Object
        && string.Equals(JsonRead.String(root, "bomFormat"), "CycloneDX", StringComparison.Ordinal);

    private static CycloneDxRootComponent? ReadRootComponent(JsonElement? metadata)
    {
        if (metadata is null)
        {
            return null;
        }

        var component = JsonRead.Object(metadata.Value, "component");
        return component is null
            ? null
            : new CycloneDxRootComponent(
                JsonRead.String(component.Value, "bom-ref"),
                JsonRead.String(component.Value, "name"),
                JsonRead.String(component.Value, "version"),
                JsonRead.String(component.Value, "type"));
    }

    // metadata.tools is an array of {vendor,name,version} through 1.4 and an object holding
    // components[]/services[] from 1.5. Both shapes appear in current producer output, so both
    // are read; the first entry wins because the document row records one producing tool.
    //
    // X4/D8b read back: BuildToolsMetadata (SbomExportService) writes
    // dependably:tool-version-status=unknown as a properties[] entry on the SAME tool object when
    // it named a tool but not its version — never on dependably's own entry, whose version is
    // always known. Reading it off the SAME entry this method already resolved name/version from
    // is what keeps the two facts — "which tool" and "did it explicitly say unknown" — about one
    // document-described entity rather than two independently-matched ones.
    private static (string? Name, string? Version, bool VersionExplicitlyUnknown) ReadTool(JsonElement? metadata)
    {
        if (metadata is null)
        {
            return (null, null, false);
        }

        if (!metadata.Value.TryGetProperty("tools", out var tools))
        {
            return (null, null, false);
        }

        if (tools.ValueKind == JsonValueKind.Array)
        {
            foreach (var tool in tools.EnumerateArray())
            {
                if (tool.ValueKind == JsonValueKind.Object)
                {
                    return (JsonRead.String(tool, "name"), JsonRead.String(tool, "version"), IsToolVersionExplicitlyUnknown(tool));
                }
            }

            return (null, null, false);
        }

        if (tools.ValueKind != JsonValueKind.Object)
        {
            return (null, null, false);
        }

        foreach (string arrayName in new[] { "components", "services" })
        {
            foreach (var entry in JsonRead.Array(tools, arrayName))
            {
                if (entry.ValueKind == JsonValueKind.Object)
                {
                    return (JsonRead.String(entry, "name"), JsonRead.String(entry, "version"), IsToolVersionExplicitlyUnknown(entry));
                }
            }
        }

        return (null, null, false);
    }

    private static bool IsToolVersionExplicitlyUnknown(JsonElement toolEntry)
    {
        foreach (var property in JsonRead.Array(toolEntry, "properties"))
        {
            string? name = JsonRead.String(property, "name");
            if (!string.Equals(name, DependablyExportProperties.ToolVersionStatus, StringComparison.Ordinal))
            {
                continue;
            }

            string? value = JsonRead.String(property, "value");
            if (value is not null && ExplicitUnknownValues.Contains(value))
            {
                return true;
            }
        }

        return false;
    }

    private static List<CycloneDxComponent> ReadComponents(JsonElement root)
    {
        var components = new List<CycloneDxComponent>();
        foreach (var entry in JsonRead.Array(root, "components"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? name = JsonRead.String(entry, "name");
            if (string.IsNullOrWhiteSpace(name))
            {
                // name is the one field the specification makes mandatory on a component; a row
                // with no name has no identity to merge on and no label to render.
                continue;
            }

            if (components.Count >= SbomDocumentLimits.MaxComponents)
            {
                throw new SbomParseException(
                    SbomParseFailure.TooManyComponents,
                    SbomDocumentLimits.MaxComponents.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            string? scope = JsonRead.String(entry, "scope");
            var refs = ReadExternalReferences(entry);
            var (licenseSpdx, licenseUrl, licenseNamed) = ReadLicenses(entry);
            components.Add(new CycloneDxComponent(
                JsonRead.String(entry, "bom-ref"),
                name,
                JsonRead.String(entry, "version"),
                JsonRead.String(entry, "type"),
                JsonRead.String(entry, "purl"),
                scope is not null && AcceptedScopes.Contains(scope) ? scope : null,
                licenseSpdx,
                Description: Clip(JsonRead.String(entry, "description"), SbomProjectionLimits.MaxDescriptionLength),
                Author: Clip(ReadAuthor(entry), SbomProjectionLimits.MaxTextLength),
                Copyright: Clip(JsonRead.String(entry, "copyright"), SbomProjectionLimits.MaxTextLength),
                Group: Clip(JsonRead.String(entry, "group"), SbomProjectionLimits.MaxTextLength),
                WebsiteUrl: refs.GetValueOrDefault("website"),
                VcsUrl: refs.GetValueOrDefault("vcs"),
                IssueTrackerUrl: refs.GetValueOrDefault("issue-tracker"),
                DistributionUrl: refs.GetValueOrDefault("distribution"),
                HashesJson: ReadHashes(entry),
                VersionRange: Clip(JsonRead.String(entry, "versionRange"), SbomProjectionLimits.MaxTextLength),
                IsExternal: JsonRead.Bool(entry, "isExternal"),
                ManifestDevDeclared: ReadManifestDevDeclared(entry),
                Producer: Clip(ReadProducer(entry), SbomProjectionLimits.MaxTextLength),
                LicenseUrl: licenseUrl,
                LicenseNamed: licenseNamed,
                AdditionalIdentifiersJson: ReadAdditionalIdentifiers(entry),
                ExplicitUnknownFieldsJson: ReadExplicitUnknownFields(entry)));
        }

        return components;
    }

    /// <summary>
    /// The manifest dev-dependency marker, true/false/absent, from the first
    /// <see cref="ManifestDevPropertyNames"/> entry a component's properties[] carries. A document
    /// naming more than one is malformed input, not something worth a second read to reconcile —
    /// the first match wins and the rest of the array is ignored, same tolerance policy as
    /// everywhere else in this parser.
    /// </summary>
    private static bool? ReadManifestDevDeclared(JsonElement entry)
    {
        foreach (var property in JsonRead.Array(entry, "properties"))
        {
            string? name = JsonRead.String(property, "name");
            if (name is null || !ManifestDevPropertyNames.Contains(name))
            {
                continue;
            }

            string? value = JsonRead.String(property, "value");
            if (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(value, "false", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return null;
    }

    /// <summary>
    /// Scans properties[] for <see cref="ExplicitUnknownPropertyNames"/> entries carrying one of
    /// <see cref="ExplicitUnknownValues"/>, returning the matched duty fields serialized through
    /// <see cref="SbomExplicitUnknownFields"/> — null when the document carries neither property,
    /// which is every CycloneDX document not produced by this registry's own exporter.
    /// </summary>
    private static string? ReadExplicitUnknownFields(JsonElement entry)
    {
        List<string>? found = null;
        foreach (var property in JsonRead.Array(entry, "properties"))
        {
            string? name = JsonRead.String(property, "name");
            if (name is null || !ExplicitUnknownPropertyNames.TryGetValue(name, out string? field))
            {
                continue;
            }

            string? value = JsonRead.String(property, "value");
            if (value is null || !ExplicitUnknownValues.Contains(value))
            {
                continue;
            }

            found ??= [];
            if (!found.Contains(field))
            {
                found.Add(field);
            }
        }

        return SbomExplicitUnknownFields.Serialize(found ?? []);
    }

    // Presentation strings are clipped rather than refused. A component's description is the
    // producer's prose and has no specified bound, so a 50k-component document could otherwise
    // widen 50k rows without ever tripping the byte cap that governs the document as a whole.
    // Refusing the document over a long description would be worse: the field is display-only,
    // and losing the tail of one sentence is not a reason to reject an inventory. The verbatim
    // value survives in the stored blob either way. The bounds themselves are shared with
    // SpdxParser via SbomProjectionLimits, so the two front ends clip identically.

    /// <summary>The bound on the serialized lifecycles array. CycloneDX-only: SPDX 2.3 has no lifecycle element.</summary>
    private const int MaxLifecyclesJsonLength = 2000;

    /// <summary>externalReferences[].type values a component page has somewhere to render.</summary>
    private static readonly IReadOnlySet<string> LinkedReferenceTypes =
        new HashSet<string>(StringComparer.Ordinal) { "website", "vcs", "issue-tracker", "distribution" };

    private static string? Clip(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    // authors[] is the 1.5+ shape and author the string that preceded it. Producers in current
    // use write both — cyclonedx-npm emits author, the .NET generator emits authors[] — and a
    // component page that renders one and not the other would look empty for whichever half of
    // an inventory came from the other tool. manufacturer is CycloneDX's own automated-creation
    // analogue of authors[] — its schema says so explicitly ("Components created through
    // automated means may have @.manufacturer instead") — so it is the last fallback, never
    // publisher: publisher/supplier names the organization that SUPPLIES the component, a
    // distinct CISA element (Component Producer) from the person(s)/entity who created it — see
    // ReadProducer.
    private static string? ReadAuthor(JsonElement component)
    {
        var names = new List<string>();
        foreach (var author in JsonRead.Array(component, "authors"))
        {
            string? authorName = JsonRead.String(author, "name");
            if (authorName is not null)
            {
                names.Add(authorName);
            }
        }

        return names.Count > 0
            ? string.Join(", ", names)
            : JsonRead.String(component, "author") ?? ReadOrganizationName(component, "manufacturer");
    }

    // supplier (an organizationalEntity, present in the schema since CycloneDX 1.2) is CycloneDX's
    // own structurally correct carrier of CISA's Component Producer — its schema says so verbatim
    // ("The organization that supplied the component"), matching SPDX's own supplier field
    // exactly (see SpdxParser.ReadEntityTracked's supplier/originator split comment). publisher is
    // an older, string-only spelling of the same fact some producers still emit instead. supplier
    // wins when a document carries both, as the more structured, unambiguous field. manufacturer
    // is DELIBERATELY not read here — see ReadAuthor above for why it feeds Author, not Producer.
    private static string? ReadProducer(JsonElement component) =>
        ReadOrganizationName(component, "supplier") ?? JsonRead.String(component, "publisher");

    // organizationalEntity's only field this projection reads — bom-ref/url/contact carry no
    // presentation fact this table has a column for.
    private static string? ReadOrganizationName(JsonElement component, string propertyName)
    {
        var entity = JsonRead.Object(component, propertyName);
        return entity is null ? null : JsonRead.String(entity.Value, "name");
    }

    // The first entry of each linked type wins. A document may repeat a type — several
    // distribution URLs for one component is ordinary — and the column holds one, so the choice
    // is the document's own order rather than a sort this parser invents. Every entry, including
    // the types with no column, stays in the stored blob.
    private static Dictionary<string, string> ReadExternalReferences(JsonElement component)
    {
        var links = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var reference in JsonRead.Array(component, "externalReferences"))
        {
            string? type = JsonRead.String(reference, "type");
            string? url = JsonRead.String(reference, "url");
            if (type is null || url is null || !LinkedReferenceTypes.Contains(type))
            {
                continue;
            }

            // A reference URL is rendered as a link, so a scheme the browser would resolve
            // against this origin — javascript:, data:, or a bare path — is dropped here rather
            // than filtered in every renderer that reads the column.
            if (!IsHttpUrl(url))
            {
                continue;
            }

            links.TryAdd(type, Clip(url, SbomProjectionLimits.MaxTextLength)!);
        }

        return links;
    }

    /// <summary>
    /// metadata.lifecycles, previously dropped entirely — a strong ingest-time quality signal,
    /// because a source-phase document legitimately carries no component hashes and scoring it as
    /// hash-deficient without knowing its phase would be wrong. Each entry is either a defined
    /// phase (<see cref="DefinedLifecyclePhases"/>) or a free-form name/description pair; an entry
    /// shaped as neither is skipped rather than failing the whole document, the same tolerance
    /// policy as the rest of this parser. Display and scoring input only — nothing here is a
    /// trust input, matching <see cref="ReadHashes"/>'s posture.
    /// </summary>
    private static string? ReadLifecycles(JsonElement? metadata)
    {
        if (metadata is null)
        {
            return null;
        }

        var entries = new List<Dictionary<string, string>>();
        foreach (var entry in JsonRead.Array(metadata.Value, "lifecycles"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? phase = JsonRead.String(entry, "phase");
            if (phase is not null && DefinedLifecyclePhases.Contains(phase))
            {
                entries.Add(new Dictionary<string, string>(StringComparer.Ordinal) { ["phase"] = phase });
                continue;
            }

            string? name = JsonRead.String(entry, "name");
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var named = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["name"] = Clip(name, SbomProjectionLimits.MaxTextLength)!,
            };
            string? description = JsonRead.String(entry, "description");
            if (description is not null)
            {
                named["description"] = Clip(description, SbomProjectionLimits.MaxDescriptionLength)!;
            }

            entries.Add(named);
        }

        if (entries.Count == 0)
        {
            return null;
        }

        string json = JsonSerializer.Serialize(entries);
        // Clipping would produce invalid JSON, so an oversized set is dropped whole, matching
        // ReadHashes's posture: a reader that cannot parse the column is worse than one that
        // finds nothing in it.
        return json.Length <= MaxLifecyclesJsonLength ? json : null;
    }

    private static bool IsHttpUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var parsed)
        && (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps);

    // hashes[] round-trips as JSON rather than becoming columns: a component may declare several
    // digests and the set of algorithms is open. Display and export only — the registry verifies
    // artifacts against the digest it computed at ingest, never against one a third-party
    // document asserts, so nothing here is a trust input.
    private static string? ReadHashes(JsonElement component)
    {
        var hashes = new List<Dictionary<string, string>>();
        foreach (var hash in JsonRead.Array(component, "hashes"))
        {
            string? alg = JsonRead.String(hash, "alg");
            string? content = JsonRead.String(hash, "content");
            if (alg is not null && content is not null)
            {
                hashes.Add(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["alg"] = alg,
                    ["content"] = content,
                });
            }
        }

        if (hashes.Count == 0)
        {
            return null;
        }

        string json = JsonSerializer.Serialize(hashes);
        // Clipping would produce invalid JSON, so an oversized set is dropped whole: a reader
        // that cannot parse the column is worse than one that finds nothing in it.
        return json.Length <= SbomProjectionLimits.MaxHashesJsonLength ? json : null;
    }

    /// <summary>
    /// CISA D13c/D13d: every identifier the component asserts beside <c>purl</c>, folded into one
    /// <c>{"kind","value"}</c> array via <see cref="SbomAdditionalIdentifiers"/> — CycloneDX's
    /// native <c>cpe</c> (D13b: never synthesized — captured only when the document itself
    /// asserted one), <c>swhid</c> and <c>omniborId</c> (both arrays; every entry is kept, not
    /// just the first, per D13d), a commit hash from <c>pedigree.commits[].uid</c> (the ONE
    /// CycloneDX field this specification defines for a version-control commit reference — the
    /// rest of <c>pedigree</c>, ancestors/descendants/variants/patches, stays out of this
    /// projection's "narrow hand-written subset" the same way every other unread element does),
    /// and a UUID from an <c>externalReferences</c> entry whose <c>url</c> is a <c>urn:uuid:</c>
    /// URN — CycloneDX defines no dedicated component field for a bare UUID the way it does for
    /// the three above, but its own <c>externalReferences[].url</c> field explicitly documents
    /// accepting "formally registered URNs", and RFC 4122's <c>urn:uuid:</c> scheme is exactly
    /// that.
    /// </summary>
    private static string? ReadAdditionalIdentifiers(JsonElement component)
    {
        // Never Clip: an identifier truncated to a bound is a DIFFERENT, wrong identifier, not a
        // shorter version of the right one — SbomAdditionalIdentifiers.AcceptValue drops an
        // over-long value whole instead. See that class's doc comment.
        var identifiers = new List<(string Kind, string Value)>();

        if (SbomAdditionalIdentifiers.AcceptValue(JsonRead.String(component, "cpe")) is { } cpe)
        {
            identifiers.Add((SbomIdentifierKinds.Cpe, cpe));
        }

        AddStringArrayIdentifiers(identifiers, component, "swhid", SbomIdentifierKinds.Swhid);
        AddStringArrayIdentifiers(identifiers, component, "omniborId", SbomIdentifierKinds.Omnibor);
        AddCommitIdentifiers(identifiers, component);
        AddUuidIdentifiers(identifiers, component);

        return SbomAdditionalIdentifiers.Serialize(identifiers);
    }

    private static void AddStringArrayIdentifiers(
        List<(string Kind, string Value)> identifiers, JsonElement component, string property, string kind)
    {
        foreach (var entry in JsonRead.Array(component, property))
        {
            if (entry.ValueKind == JsonValueKind.String
                && SbomAdditionalIdentifiers.AcceptValue(entry.GetString()) is { } value)
            {
                identifiers.Add((kind, value));
            }
        }
    }

    private static void AddCommitIdentifiers(List<(string Kind, string Value)> identifiers, JsonElement component)
    {
        var pedigree = JsonRead.Object(component, "pedigree");
        if (pedigree is null)
        {
            return;
        }

        foreach (var commit in JsonRead.Array(pedigree.Value, "commits"))
        {
            if (SbomAdditionalIdentifiers.AcceptValue(JsonRead.String(commit, "uid")) is { } uid)
            {
                identifiers.Add((SbomIdentifierKinds.CommitHash, uid));
            }
        }
    }

    private static void AddUuidIdentifiers(List<(string Kind, string Value)> identifiers, JsonElement component)
    {
        foreach (var reference in JsonRead.Array(component, "externalReferences"))
        {
            string? url = JsonRead.String(reference, "url");
            if (url is not null && url.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase)
                && SbomAdditionalIdentifiers.AcceptValue(url) is { } uuid)
            {
                identifiers.Add((SbomIdentifierKinds.Uuid, uuid));
            }
        }
    }

    // licenses[] entries carry either an SPDX expression or a license object with an id or a
    // free-text name, and one array may mix the two: every entry is read on its own terms rather
    // than the array being classified once as "the expression form" or "the licence-list form".
    // Several entries are folded with OR, the permissive reading — an entry may itself be a
    // compound expression, and OR is the lowest-precedence operator in the grammar, so joining at
    // that level leaves each part's own AND/WITH structure intact. One entry is stored as written,
    // so a document that already carries a compound expression round-trips unchanged.
    //
    // CISA D16c: a licence with no SPDX identifier still needs to be representable, and — when
    // the document offers one — a URL so a recipient can find the full licence text. license.id
    // (or a bare expression) is already a real SPDX identifier and needs neither; license.name is
    // not, regardless of whether a url accompanies it (CycloneDX's own license object is legal
    // with name alone). LicenseNamed is the discriminator the export boundary reads to choose a
    // native "expression" versus a native "license.name" shape — it, not LicenseUrl, is what
    // makes a name-only licence (no url at all) representable at all, which a URL-presence-only
    // discriminator cannot do. Both are captured ONLY when the WHOLE array resolved to exactly
    // one name-only entry — a compound expression already identifies itself, an id-backed entry
    // does too, and more than one entry makes "the" name/URL for this component ambiguous, so
    // those cases fall back to the plain SPDX-expression shape rather than an arbitrary pick.
    private static (string? LicenseSpdx, string? LicenseUrl, bool? LicenseNamed) ReadLicenses(JsonElement component)
    {
        var parts = new List<string>();
        bool lastPartIsName = false;
        string? lastNameUrl = null;
        foreach (var entry in JsonRead.Array(component, "licenses"))
        {
            var (part, isName, url) = ReadLicenseEntry(entry);
            if (part is null)
            {
                continue;
            }

            parts.Add(part);
            lastPartIsName = isName;
            // Only a name-form entry carries a URL; an expression or id leaves the previous one
            // standing, exactly as the sole-name check below expects.
            lastNameUrl = isName ? url : lastNameUrl;
        }

        string? licenseSpdx = parts.Count switch
        {
            0 => null,
            1 => parts[0],
            _ => string.Join(" OR ", parts.Distinct(StringComparer.Ordinal)),
        };
        bool isSoleName = parts.Count == 1 && lastPartIsName;
        string? licenseUrl = isSoleName ? lastNameUrl : null;
        bool? licenseNamed = parts.Count == 0 ? null : isSoleName;
        return (licenseSpdx, licenseUrl, licenseNamed);
    }

    /// <summary>
    /// Classifies one <c>licenses[]</c> entry on its own terms. A null Part means the entry
    /// contributes nothing — a non-object, a license object that is absent, or a name-form entry
    /// whose name is blank — and the caller skips it without disturbing the running name/URL state.
    /// </summary>
    private static (string? Part, bool IsName, string? Url) ReadLicenseEntry(JsonElement entry)
    {
        if (entry.ValueKind != JsonValueKind.Object)
        {
            return (null, false, null);
        }

        string? expression = JsonRead.String(entry, "expression");
        if (!string.IsNullOrWhiteSpace(expression))
        {
            return (expression, false, null);
        }

        var license = JsonRead.Object(entry, "license");
        if (license is null)
        {
            return (null, false, null);
        }

        string? id = JsonRead.String(license.Value, "id");
        if (!string.IsNullOrWhiteSpace(id))
        {
            return (id, false, null);
        }

        string? name = JsonRead.String(license.Value, "name");
        if (string.IsNullOrWhiteSpace(name))
        {
            return (null, false, null);
        }

        string? url = JsonRead.String(license.Value, "url");
        return (name, true, url is not null && IsHttpUrl(url) ? Clip(url, SbomProjectionLimits.MaxTextLength) : null);
    }

    private static Dictionary<string, IReadOnlyList<string>> ReadDependencies(JsonElement root)
    {
        var graph = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var entry in JsonRead.Array(root, "dependencies"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? reference = JsonRead.String(entry, "ref");
            if (string.IsNullOrWhiteSpace(reference))
            {
                continue;
            }

            var dependsOn = JsonRead.Array(entry, "dependsOn")
                .Where(d => d.ValueKind == JsonValueKind.String)
                .Select(d => d.GetString()!)
                .ToList();
            graph[reference] = dependsOn;
        }

        return graph;
    }

    private static List<CycloneDxAnalysisStatement> ReadStatements(JsonElement root)
    {
        var statements = new List<CycloneDxAnalysisStatement>();
        int charged = 0;
        foreach (var entry in JsonRead.Array(root, "vulnerabilities"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? id = JsonRead.String(entry, "id");
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var products = JsonRead.Array(entry, "affects")
                .Where(a => a.ValueKind == JsonValueKind.Object)
                .Select(a => JsonRead.String(a, "ref"))
                .Where(r => !string.IsNullOrWhiteSpace(r))
                .Select(r => r!)
                .ToList();

            // Charged once per component the statement names, because that pair is what becomes
            // a row; a statement naming none still charges one. See SbomDocumentLimits.
            charged += Math.Max(1, products.Count);
            if (charged > SbomDocumentLimits.MaxComponentStatements)
            {
                throw new SbomParseException(
                    SbomParseFailure.TooManyStatements,
                    SbomDocumentLimits.MaxComponentStatements.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            var analysis = JsonRead.Object(entry, "analysis");
            statements.Add(new CycloneDxAnalysisStatement(
                id,
                products,
                analysis is null ? null : JsonRead.String(analysis.Value, "state"),
                analysis is null ? null : JsonRead.String(analysis.Value, "justification"),
                analysis is null ? null : JsonRead.FirstStringOfArray(analysis.Value, "response"),
                analysis is null ? null : JsonRead.String(analysis.Value, "detail")));
        }

        return statements;
    }
}
