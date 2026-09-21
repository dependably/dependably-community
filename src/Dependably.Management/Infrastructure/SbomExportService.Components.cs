using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Api;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// The component half of <see cref="SbomExportService"/>: the <c>components[]</c> array and every
/// per-component field that feeds it — identifiers, licences, hashes, the <c>dependably:</c>
/// disclosure properties, and the scope filter that decides which rows are rendered at all.
///
/// <para>Separated from the document assembly by file only — one partial class, one lifetime.</para>
/// </summary>
public sealed partial class SbomExportService
{
    private static JsonArray BuildComponentsArray(
        IReadOnlyList<ComponentRow> components, string? refPrefix = null,
        IReadOnlyDictionary<string, bool>? installScriptByComponentId = null, string specVersion = "1.7",
        IReadOnlyDictionary<string, string>? ownHashByComponentId = null)
    {
        var arr = new JsonArray();
        foreach (var c in components)
        {
            arr.Add(BuildComponentObject(c, refPrefix, installScriptByComponentId, specVersion, ownHashByComponentId));
        }

        return arr;
    }

    /// <summary>One CycloneDX component object.</summary>
    private static JsonObject BuildComponentObject(
        ComponentRow c, string? refPrefix,
        IReadOnlyDictionary<string, bool>? installScriptByComponentId, string specVersion,
        IReadOnlyDictionary<string, string>? ownHashByComponentId = null)
    {
        var obj = new JsonObject
        {
            ["type"] = c.ComponentType ?? "library",
            ["bom-ref"] = RefOf(c, refPrefix),
            ["name"] = c.Name,
        };
        // versionRange is what a component declares INSTEAD of a version; the specification
        // forbids both on one component, so the two arms exclude each other rather than both
        // being written. versionRange itself is a 1.7 field — under 1.6 the value survives as
        // the dependably:version-range property instead of the component silently losing its
        // only version-shaped fact (see BuildComponentProperties).
        if (c.Version is not null)
        {
            obj["version"] = c.Version;
        }
        else if (c.VersionRange is not null && specVersion != "1.6")
        {
            obj["versionRange"] = c.VersionRange;
        }

        // isExternal is a 1.7 field; a 1.6 document omits it rather than emitting a field the
        // spec does not define at that version.
        if (specVersion != "1.6" && c.IsExternal is bool isExternal)
        {
            obj["isExternal"] = isExternal;
        }

        if (c.Purl is not null)
        {
            obj["purl"] = c.Purl;
        }

        var identifiers = ParseAdditionalIdentifiers(c.AdditionalIdentifiers);
        AddIdentifierFields(obj, identifiers);

        // CONTRACT D1: component scope is written ONLY from sbom_scope (raw CycloneDX
        // scope, display-only) — never from dependency_scope, the SARIF-owned dev/prod
        // signal CycloneDX has no vocabulary for. Conflating them here is exactly what the
        // producer split exists to prevent.
        if (c.SbomScope is not null)
        {
            obj["scope"] = c.SbomScope;
        }

        AddLicenseField(obj, c);

        // D10 (Component Producer): the native publisher field, never dependably's own name —
        // for a proxied artefact this registry is a distributor, not the producer, and
        // component_producer is populated only from the uploaded document's own supplier/publisher
        // (CycloneDxParser.ReadProducer) or SPDX supplier (SpdxParser), never defaulted here. No
        // producer at all is left silent rather than invented; a dedicated unknown-provenance
        // vocabulary would let this state that explicitly once one exists.
        if (c.ComponentProducer is not null)
        {
            obj["publisher"] = c.ComponentProducer;
        }

        var (hashes, assertedHashesJson) = BuildComponentHashes(
            c.ComponentHashes, ownHashByComponentId?.GetValueOrDefault(c.Id), specVersion);
        if (hashes is not null)
        {
            obj["hashes"] = hashes;
        }

        bool hasNoHashAtAll = hashes is null && assertedHashesJson is null;
        var properties = BuildComponentProperties(
            c, installScriptByComponentId, specVersion, assertedHashesJson, hasNoHashAtAll, identifiers);
        if (properties.Count > 0)
        {
            obj["properties"] = properties;
        }

        return obj;
    }

    /// <summary>
    /// D13b/D13d. The FIRST asserted cpe goes natively — CycloneDX's own cpe field is singular
    /// (unlike swhid/omniborId), so a document that asserted more than one (an SPDX source with a
    /// cpe22Type AND a cpe23Type SECURITY ref side by side is standard practice) has no native
    /// place for the rest. Never synthesized. D13d still requires them: every cpe AFTER the first
    /// is disclosed via dependably:identifier:cpe instead of dropped — see
    /// <see cref="BuildComponentProperties"/>'s matching "first cpe seen" loop, which must pick
    /// the SAME first entry as this FirstOrDefault or the two would disagree about which one
    /// already has a native home. swhid/omniborId are native ARRAY fields, so every asserted entry
    /// is emitted, not just the first.
    /// </summary>
    private static void AddIdentifierFields(JsonObject obj, List<(string Kind, string Value)> identifiers)
    {
        string? cpe = identifiers.FirstOrDefault(i => i.Kind == SbomIdentifierKinds.Cpe).Value;
        if (cpe is not null)
        {
            obj["cpe"] = cpe;
        }

        AddIdentifierArray(obj, "swhid", identifiers, SbomIdentifierKinds.Swhid);
        AddIdentifierArray(obj, "omniborId", identifiers, SbomIdentifierKinds.Omnibor);
    }

    private static void AddIdentifierArray(
        JsonObject obj, string field, List<(string Kind, string Value)> identifiers, string kind)
    {
        var values = identifiers.Where(i => i.Kind == kind).Select(i => i.Value).ToList();
        if (values.Count > 0)
        {
            obj[field] = new JsonArray(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
        }
    }

    /// <summary>
    /// D16c: license_is_named is the discriminator, not license_url — CycloneDX's license.name
    /// object is legal with NO url at all, so "no url" cannot itself mean "must be an SPDX
    /// expression" (a name-only licence with no url falling through to the expression arm is what
    /// puts free text into a field the schema defines as a valid SPDX license expression). The two
    /// arms are mutually exclusive shapes of the SAME licenseChoice array entry, never both for
    /// one component.
    /// </summary>
    private static void AddLicenseField(JsonObject obj, ComponentRow c)
    {
        if (c.LicenseSpdx is null)
        {
            return;
        }

        if (c.LicenseNamed != true)
        {
            obj["licenses"] = new JsonArray(new JsonObject { ["expression"] = c.LicenseSpdx });
            return;
        }

        var licenseObj = new JsonObject { ["name"] = c.LicenseSpdx };
        if (c.LicenseUrl is not null)
        {
            licenseObj["url"] = c.LicenseUrl;
        }

        obj["licenses"] = new JsonArray(new JsonObject { ["license"] = licenseObj });
    }

    /// <summary>
    /// D14/D15 (Component Hash Value/Algorithm). Precedence: dependably's own ingest-time SHA-256
    /// (<paramref name="ownSha256"/>), when we hold one AND it validates as ASCII hex, is the SOLE
    /// entry in the returned <c>hashes[]</c> — it is a stronger claim than a third party's
    /// assertion (computed by this registry over the specific artefact it can attribute to this
    /// component, not merely relayed from an uploaded document — see
    /// <see cref="LoadOwnHashFactsAsync"/> for what "attribute" excludes), and the project rule
    /// against per-request integrity re-checks means nothing here compares the two. In that case
    /// the document's own asserted hash(es), if any, are returned separately (the tuple's
    /// <c>AssertedHashesJson</c>) for the caller to disclose as a <c>dependably:</c> property —
    /// distinguishable from dependably's own claim rather than silently dropped, so a future
    /// mismatch check (a documented, deferred finding) has something to compare against.
    ///
    /// <para>An empty or non-hex <paramref name="ownSha256"/> is treated as no digest at all — a
    /// blank value can reach this method legitimately (a proxy first-fetch that staged bytes
    /// without hashing them writes an empty, NOT NULL <c>cache_artifact.content_hash</c>; nothing
    /// upstream of this method may assume every non-null value it sees is well-formed), and
    /// emitting it verbatim would both produce an empty <c>hashes[].content</c> — invalid
    /// CycloneDX — and wrongly displace a genuine asserted hash into the disclosure property.</para>
    ///
    /// <para>When dependably holds no usable digest, the document's own asserted hash(es) are
    /// emitted natively instead — but ONLY the ones whose <c>alg</c> is a member of the
    /// <c>hash-alg</c> enum for <paramref name="specVersion"/> (see
    /// <see cref="IsHashAlgEnumMember"/>); CISA's own suggested spelling (lowercase
    /// <c>sha-256</c>) and 1.7-only values asserted under a 1.6 render are both real documents
    /// this registry ingests without complaint, and emitting either into a closed enum field
    /// produces an invalid document exactly like dependably's own claim would. An asserted entry
    /// that cannot go natively is not dropped — it survives in the disclosure property, which
    /// exists precisely to carry an assertion display/export cannot represent as a native field
    /// (a property value is a free string; the CycloneDX schema imposes no vocabulary on it). A
    /// component with no native-eligible entries at all is left with no <c>hashes</c> field — a
    /// dedicated unknown-provenance vocabulary would let this state that explicitly once one
    /// exists.</para>
    ///
    /// <para><c>hashes[].alg</c> is ALWAYS the CycloneDX <c>hash-alg</c> enum spelling — dependably's
    /// own digest is emitted as <c>SHA-256</c>. D15's own text asks that the algorithm be
    /// identifiable; the enum value already answers that, so choosing the wire format's own closed
    /// vocabulary over IANA's is a stricter reading of the SAME requirement, not a shortfall
    /// against it — CISA's footnote on alternative encodings applies only "if the format allows
    /// them", and this one does not for <c>hashes[].alg</c>. An asserted algorithm spelled in
    /// another ingested format's own vocabulary is translated onto this enum's spelling first
    /// (<see cref="AssertedAlgAliases"/>) — SPDX's <c>checksumAlgorithm</c> spells the same
    /// algorithm <c>SHA256</c> where CycloneDX spells it <c>SHA-256</c>, and per
    /// <c>DESIGN-sbom-vex-sarif-projects</c> "the enumeration wins … the rule applies to asserted
    /// algorithms too" — an asserted algorithm this registry can recognise under another name is
    /// translated, not disclosed as though CycloneDX had no name for it. Anything the alias table
    /// does not recognise is still passed through byte-for-byte, never rewritten to IANA's Hash
    /// Function Textual Name spelling.</para>
    ///
    /// <para>Value content is validated as ASCII hex before being trusted as a hash at all — an
    /// uploaded document's assertion is never assumed well-formed. An entry that fails validation
    /// is dropped rather than exported (or disclosed) as a hash value it is not.</para>
    /// </summary>
    private static (JsonArray? Hashes, string? AssertedHashesJson) BuildComponentHashes(
        string? componentHashesJson, string? ownSha256, string specVersion)
    {
        var asserted = ParseAssertedHashes(componentHashesJson)
            .Select(h => (Alg: AssertedAlgAliases.GetValueOrDefault(h.Alg, h.Alg), h.Content))
            .ToList();
        string? validOwn = ownSha256 is not null && IsAsciiHex(ownSha256) ? ownSha256 : null;

        if (validOwn is not null)
        {
            var own = new JsonArray(new JsonObject { ["alg"] = "SHA-256", ["content"] = validOwn });
            string? disclosure = asserted.Count > 0
                ? JsonSerializer.Serialize(asserted.Select(h => new { alg = h.Alg, content = h.Content }))
                : null;
            return (own, disclosure);
        }

        var native = asserted.Where(h => IsHashAlgEnumMember(h.Alg, specVersion)).ToList();
        var disclosedOnly = asserted.Where(h => !IsHashAlgEnumMember(h.Alg, specVersion)).ToList();

        JsonArray? hashesArr = null;
        if (native.Count > 0)
        {
            hashesArr = [];
            foreach (var (alg, content) in native)
            {
                hashesArr.Add(new JsonObject { ["alg"] = alg, ["content"] = content });
            }
        }

        string? disclosedJson = disclosedOnly.Count > 0
            ? JsonSerializer.Serialize(disclosedOnly.Select(h => new { alg = h.Alg, content = h.Content }))
            : null;

        return (hashesArr, disclosedJson);
    }

    /// <summary>
    /// CycloneDX's closed <c>hash-alg</c> enum, per spec version — read verbatim from the same
    /// official schema <c>SbomExportSchemaValidationTests</c> validates against, so this table and
    /// that gate can never silently drift apart. 1.7 added <c>Streebog-256</c>/<c>Streebog-512</c>;
    /// every other member is common to both versions covered here (1.4–1.6 share 1.6's set).
    /// </summary>
    private static readonly IReadOnlySet<string> HashAlgEnum16 = new HashSet<string>(StringComparer.Ordinal)
    {
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-384", "SHA3-512",
        "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3",
    };

    private static readonly IReadOnlySet<string> HashAlgEnum17 = new HashSet<string>(
        HashAlgEnum16, StringComparer.Ordinal) { "Streebog-256", "Streebog-512" };

    /// <summary>
    /// Cross-format aliases for <see cref="HashAlgEnum16"/>/<see cref="HashAlgEnum17"/>'s own
    /// members, derived from those two declarations rather than hand-maintained as a third list.
    /// SPDX's <c>checksumAlgorithm</c> enum spells four algorithms without the hyphen CycloneDX's
    /// <c>hash-alg</c> enum uses (<c>SHA1</c>/<c>SHA256</c>/<c>SHA384</c>/<c>SHA512</c> vs
    /// <c>SHA-1</c>/<c>SHA-256</c>/<c>SHA-384</c>/<c>SHA-512</c>) — every other member the two
    /// vocabularies share (<c>MD5</c>, <c>SHA3-*</c>, <c>BLAKE2b-*</c>, <c>BLAKE3</c>) is already
    /// spelled identically, so only the hyphenated <c>SHA-</c> members need a de-hyphenated alias.
    /// SPDX's <c>SHA224</c> has no CycloneDX enum member at all (neither spec version defines
    /// <c>SHA-224</c>) and so has no alias here — it stays disclosure-only, correctly.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> AssertedAlgAliases = HashAlgEnum17
        .Where(member => member.StartsWith("SHA-", StringComparison.Ordinal))
        .ToDictionary(member => member.Replace("-", string.Empty, StringComparison.Ordinal), StringComparer.Ordinal);

    /// <summary>Whether <paramref name="alg"/> is a member of the <c>hash-alg</c> enum for <paramref name="specVersion"/>.</summary>
    private static bool IsHashAlgEnumMember(string alg, string specVersion) =>
        (specVersion == "1.6" ? HashAlgEnum16 : HashAlgEnum17).Contains(alg);

    /// <summary>
    /// Reads <c>sbom_components.component_hashes</c> (the ingested <c>[{"alg","content"}]</c>
    /// array, verbatim from the uploaded document) and returns every entry whose content
    /// validates as ASCII hex. The algorithm name is returned exactly as the document spelled it,
    /// UNVALIDATED against any enum — ingest applies no <c>hash-alg</c> vocabulary check, so a
    /// document may legitimately assert a spelling the target render's spec version does not
    /// admit (CISA's own suggested lowercase form, or a 1.7-only algorithm under a 1.6 render);
    /// see <see cref="BuildComponentHashes"/> for where that gets resolved into "emit natively" or
    /// "disclose only". An entry failing hex validation is dropped entirely — D14 asks for
    /// validation, not trust.
    /// </summary>
    private static List<(string Alg, string Content)> ParseAssertedHashes(string? componentHashesJson)
    {
        if (string.IsNullOrWhiteSpace(componentHashesJson))
        {
            return [];
        }

        List<Dictionary<string, string>>? raw;
        try
        {
            raw = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(componentHashesJson);
        }
        catch (JsonException)
        {
            return [];
        }

        if (raw is null)
        {
            return [];
        }

        var result = new List<(string, string)>();
        foreach (var entry in raw)
        {
            if (!entry.TryGetValue("alg", out string? alg) || !entry.TryGetValue("content", out string? content))
            {
                continue;
            }

            if (!IsAsciiHex(content))
            {
                continue;
            }

            result.Add((alg, content));
        }

        return result;
    }

    /// <summary>
    /// Reads <c>sbom_components.additional_identifiers</c> — the ingested <c>[{"kind","value"}]</c>
    /// array <see cref="SbomAdditionalIdentifiers"/> writes at ingest — into the (kind, value)
    /// pairs <see cref="BuildComponentObject"/> and <see cref="BuildComponentProperties"/> place
    /// natively (cpe/swhid/omniborId) or disclose as a property (commit-hash/uuid). An entry
    /// naming a kind neither of those methods recognises is kept, not dropped: a future ingest
    /// revision that widens <see cref="SbomIdentifierKinds"/> should not require re-parsing every
    /// already-stored row before the export boundary can place the new kind, and an unrecognised
    /// kind today simply contributes to nothing — the same "kept but unread" posture the rest of
    /// this parser's own stored blob already has for fields this projection does not surface.
    /// </summary>
    private static List<(string Kind, string Value)> ParseAdditionalIdentifiers(string? additionalIdentifiersJson)
    {
        if (string.IsNullOrWhiteSpace(additionalIdentifiersJson))
        {
            return [];
        }

        List<Dictionary<string, string>>? raw;
        try
        {
            raw = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(additionalIdentifiersJson);
        }
        catch (JsonException)
        {
            return [];
        }

        if (raw is null)
        {
            return [];
        }

        var result = new List<(string, string)>();
        foreach (var entry in raw)
        {
            if (entry.TryGetValue("kind", out string? kind) && entry.TryGetValue("value", out string? value)
                && !string.IsNullOrWhiteSpace(kind) && !string.IsNullOrWhiteSpace(value))
            {
                result.Add((kind, value));
            }
        }

        return result;
    }

    /// <summary>ASCII hex: a non-empty, even-length run of <c>0-9a-fA-F</c> — what a hex-encoded digest is.</summary>
    private static bool IsAsciiHex(string value) =>
        value.Length > 0 && value.Length % 2 == 0
        && value.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    /// <summary>
    /// SPDX's own convention for a licence outside the SPDX List — the best-effort D16d signal;
    /// see <see cref="DependablyExportProperties.NonSpdxListedLicense"/> for its limits.
    /// </summary>
    private const string SpdxLicenseRefToken = "LicenseRef-";

    /// <summary>The dependably: namespaced properties a component carries, if any.</summary>
    private static JsonArray BuildComponentProperties(
        ComponentRow c, IReadOnlyDictionary<string, bool>? installScriptByComponentId, string specVersion,
        string? assertedHashesJson, bool hasNoHashAtAll,
        IReadOnlyList<(string Kind, string Value)> additionalIdentifiers)
    {
        var properties = new JsonArray();
        if (c.DependencyKind is not null)
        {
            properties.Add(Prop(DependablyExportProperties.DependencyKind, c.DependencyKind));
        }

        if (c.DependencyScope is not null)
        {
            properties.Add(Prop(DependablyExportProperties.DependencyScope, c.DependencyScope));
        }

        // Under 1.6 the native versionRange field is omitted (BuildComponentObject); this
        // property is the only place the value survives that document.
        if (specVersion == "1.6" && c.Version is null && c.VersionRange is not null)
        {
            properties.Add(Prop(DependablyExportProperties.VersionRange, c.VersionRange));
        }

        // Under 1.6 the native isExternal field is omitted (BuildComponentObject); relocating the
        // same fact here — rather than dropping it — is what lets a 1.6 and a 1.7 render of
        // unchanged data assert the SAME set of facts, which is the precondition for specVersion
        // staying out of the revision-identity key (see SbomExportService.Revision.cs).
        if (specVersion == "1.6" && c.IsExternal is bool isExternalProp)
        {
            properties.Add(Prop(DependablyExportProperties.IsExternal, BoolValue(isExternalProp)));
        }

        // Positive-only: a miss (no dictionary, or a false/absent entry) means "unknown to
        // this registry", never "verified clean" — see DependablyExportProperties.InstallScript.
        if (installScriptByComponentId is not null && installScriptByComponentId.GetValueOrDefault(c.Id))
        {
            properties.Add(Prop(DependablyExportProperties.InstallScript, DependablyExportProperties.TrueValue));
        }

        // Only ever set when BuildComponentHashes could not (or chose not to) put an asserted
        // hash entry in the native hashes[] field — either dependably's own stronger digest
        // occupies it instead, or the entry's alg is not a hash-alg enum member for this
        // document's spec version — see that method's doc comment for the full rule.
        if (assertedHashesJson is not null)
        {
            properties.Add(Prop(DependablyExportProperties.AssertedHashes, assertedHashesJson));
        }

        AddIdentifierDisclosureProperties(properties, additionalIdentifiers);
        AddAbsenceProperties(properties, c, hasNoHashAtAll, additionalIdentifiers);
        return properties;
    }

    /// <summary>
    /// D13c/D13d: commit-hash and UUID have no native CycloneDX component field (unlike
    /// swhid/omniborId, emitted natively as arrays in <see cref="BuildComponentObject"/>), so every
    /// asserted entry of each kind is disclosed here — repeatable, not first-wins, per D13d. cpe
    /// DOES have a native field, but it is SINGULAR (unlike swhid/omniborId), so only the FIRST
    /// asserted cpe fits there — <see cref="AddIdentifierFields"/> picks that same first entry via
    /// identifiers.FirstOrDefault(kind == Cpe); every cpe AFTER that one has no native home and is
    /// disclosed here too, tracked by the same "first cpe seen" rule so this loop and that
    /// FirstOrDefault agree on which single entry was already emitted natively.
    /// </summary>
    private static void AddIdentifierDisclosureProperties(
        JsonArray properties, IReadOnlyList<(string Kind, string Value)> additionalIdentifiers)
    {
        bool firstCpeEmittedNatively = false;
        foreach (var (kind, value) in additionalIdentifiers)
        {
            if (kind == SbomIdentifierKinds.Cpe)
            {
                if (!firstCpeEmittedNatively)
                {
                    firstCpeEmittedNatively = true;
                    continue;
                }

                properties.Add(Prop(DependablyExportProperties.IdentifierCpe, value));
            }
            else if (kind == SbomIdentifierKinds.CommitHash)
            {
                properties.Add(Prop(DependablyExportProperties.IdentifierCommitHash, value));
            }
            else if (kind == SbomIdentifierKinds.Uuid)
            {
                properties.Add(Prop(DependablyExportProperties.IdentifierUuid, value));
            }
        }
    }

    /// <summary>
    /// X4: the five per-component "indicate unknown" duties. Each fires only when the corresponding
    /// native field is entirely absent — never alongside the real field, which is what keeps every
    /// pair mutually exclusive.
    /// </summary>
    private static void AddAbsenceProperties(
        JsonArray properties, ComponentRow c, bool hasNoHashAtAll,
        IReadOnlyList<(string Kind, string Value)> additionalIdentifiers)
    {
        if (c.ComponentProducer is null)
        {
            properties.Add(Prop(DependablyExportProperties.ProducerStatus, DependablyExportProperties.AbsenceReason()));
        }

        // D13a: an identifier is purl OR any additional-identifier entry (cpe/swhid/omnibor/
        // commit-hash/uuid) — a component with none of those has no identifier at all, which
        // fails D13 outright unless this property says so explicitly.
        if (c.Purl is null && additionalIdentifiers.Count == 0)
        {
            properties.Add(Prop(DependablyExportProperties.IdentifierStatus, DependablyExportProperties.AbsenceReason()));
        }

        if (c.Version is null && c.VersionRange is null)
        {
            properties.Add(Prop(DependablyExportProperties.VersionStatus, DependablyExportProperties.AbsenceReason()));
        }

        if (hasNoHashAtAll)
        {
            properties.Add(Prop(DependablyExportProperties.HashStatus, DependablyExportProperties.AbsenceReason()));
        }

        if (c.LicenseSpdx is null)
        {
            properties.Add(Prop(DependablyExportProperties.LicenseStatus, DependablyExportProperties.AbsenceReason()));
        }
        else if (c.LicenseSpdx.Contains(SpdxLicenseRefToken, StringComparison.Ordinal))
        {
            // D16d: an OBSERVATION (identifier outside the SPDX List), not a conclusion about
            // licence terms — see the property's own doc comment for why.
            properties.Add(Prop(
                DependablyExportProperties.NonSpdxListedLicense, DependablyExportProperties.TrueValue));
        }
    }

    /// <summary>
    /// Partitions <paramref name="components"/> under <paramref name="filter"/>, returning the
    /// kept rows plus how many were removed. Reads <see cref="SbomAnalysisProjection.IsProdScope"/>
    /// and <see cref="SbomAnalysisProjection.IsDevScope"/> — the identical predicate the component
    /// table's own <c>scope=all|prod|dev</c> filter reads — rather than re-deriving the
    /// classification here, so an operator filtering the table to <c>prod</c> and exporting under
    /// <c>prod</c> sees the same component ids, not two answers to one apparent question.
    /// <c>unknown</c>-scoped rows are always kept under <c>prod</c>, since excluding them too
    /// would silently drop every component nothing has classified. Applied in memory rather than
    /// in SQL because the caller needs both the removed count (for the
    /// <c>dependably:filtered-out-count</c> disclosure) and the same kept rows to feed both the
    /// <c>components[]</c> array and the dependency graph — one filtered list, not two queries
    /// that could disagree. <c>dependency_path</c> is never rewritten: a kept component's path can
    /// still name a filtered-out ancestor, so the dependency graph may emit a ref with no matching
    /// <c>components[]</c> entry — the same shape it already produces for any path ancestor
    /// nothing was ever uploaded as its own component.
    /// </summary>
    private static (List<ComponentRow> Kept, int RemovedCount) ApplyComponentFilter(
        List<ComponentRow> components, SbomComponentFilter filter)
    {
        if (filter == SbomComponentFilter.All)
        {
            return (components, 0);
        }

        bool Keep(ComponentRow c) => filter == SbomComponentFilter.Prod
            ? SbomAnalysisProjection.IsProdScope(c.DependencyScope, c.SbomScope)
            : SbomAnalysisProjection.IsDevScope(c.DependencyScope);

        var kept = new List<ComponentRow>(components.Count);
        int removed = 0;
        foreach (var c in components)
        {
            if (Keep(c))
            {
                kept.Add(c);
            }
            else
            {
                removed++;
            }
        }

        return (kept, removed);
    }

    /// <summary>
    /// The <c>dependably:component-filter</c> disclosure value for <paramref name="filter"/> —
    /// the exact spelling <see cref="SbomAnalysisProjection.ScopeFilters"/> uses (<c>all</c>,
    /// <c>prod</c>, <c>dev</c>), not a second vocabulary for the same three states.
    /// </summary>
    private static string ScopeFilterValue(SbomComponentFilter filter) => filter switch
    {
        SbomComponentFilter.Prod => "prod",
        SbomComponentFilter.Dev => "dev",
        _ => "all",
    };

    /// <summary>
    /// Narrows <paramref name="vulnRows"/> to the ones whose owning component survived
    /// <see cref="ApplyComponentFilter"/>. A vulnerability row is loaded straight from
    /// <c>sbom_component_vulns</c> by <c>project_version_id</c>, independent of the component
    /// filter, so without this step a filtered-out component's advisories still ship in
    /// <c>vulnerabilities[]</c> — a dangling <c>affects[].ref</c> naming a component the same
    /// document's own <c>components[]</c> just declared removed. That is a stronger failure than
    /// the dependency graph's pre-existing dangling-ref shape: a consumer cannot attach the
    /// finding to anything, and a human reads an advisory against a component the inventory
    /// denies shipping. Filtering against the kept set is a no-op when nothing was filtered — the
    /// unfiltered branch's kept set is every loaded component — so this runs unconditionally
    /// rather than branching on <see cref="SbomComponentFilter"/> a second time.
    /// </summary>
    private static List<ComponentVulnRow> FilterVulnsToKeptComponents(
        List<ComponentVulnRow> vulnRows, IReadOnlyList<ComponentRow> keptComponents)
    {
        var keptIds = keptComponents.Select(c => c.Id).ToHashSet(StringComparer.Ordinal);
        return vulnRows.Where(v => keptIds.Contains(v.ComponentId)).ToList();
    }
}
