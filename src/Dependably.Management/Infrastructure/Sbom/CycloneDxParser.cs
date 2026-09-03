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
        var (toolName, toolVersion) = ReadTool(metadata);

        var components = ReadComponents(root);
        return new CycloneDxDocument(
            specVersion,
            toolName,
            toolVersion,
            ReadRootComponent(metadata),
            components,
            ReadDependencies(root),
            ReadStatements(root));
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
    private static (string? Name, string? Version) ReadTool(JsonElement? metadata)
    {
        if (metadata is null)
        {
            return (null, null);
        }

        if (!metadata.Value.TryGetProperty("tools", out var tools))
        {
            return (null, null);
        }

        if (tools.ValueKind == JsonValueKind.Array)
        {
            foreach (var tool in tools.EnumerateArray())
            {
                if (tool.ValueKind == JsonValueKind.Object)
                {
                    return (JsonRead.String(tool, "name"), JsonRead.String(tool, "version"));
                }
            }

            return (null, null);
        }

        if (tools.ValueKind != JsonValueKind.Object)
        {
            return (null, null);
        }

        foreach (string arrayName in new[] { "components", "services" })
        {
            foreach (var entry in JsonRead.Array(tools, arrayName))
            {
                if (entry.ValueKind == JsonValueKind.Object)
                {
                    return (JsonRead.String(entry, "name"), JsonRead.String(entry, "version"));
                }
            }
        }

        return (null, null);
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
            components.Add(new CycloneDxComponent(
                JsonRead.String(entry, "bom-ref"),
                name,
                JsonRead.String(entry, "version"),
                JsonRead.String(entry, "type"),
                JsonRead.String(entry, "purl"),
                scope is not null && AcceptedScopes.Contains(scope) ? scope : null,
                ReadLicenses(entry),
                Clip(JsonRead.String(entry, "description"), MaxDescriptionLength),
                Clip(ReadAuthor(entry), MaxTextLength),
                Clip(JsonRead.String(entry, "copyright"), MaxTextLength),
                Clip(JsonRead.String(entry, "group"), MaxTextLength),
                refs.GetValueOrDefault("website"),
                refs.GetValueOrDefault("vcs"),
                refs.GetValueOrDefault("issue-tracker"),
                refs.GetValueOrDefault("distribution"),
                ReadHashes(entry),
                Clip(JsonRead.String(entry, "versionRange"), MaxTextLength),
                JsonRead.Bool(entry, "isExternal"),
                ReadManifestDevDeclared(entry)));
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
    /// Presentation strings are clipped rather than refused. A component's description is the
    /// producer's prose and has no specified bound, so a 50k-component document could otherwise
    /// widen 50k rows without ever tripping the byte cap that governs the document as a whole.
    /// Refusing the document over a long description would be worse: the field is display-only,
    /// and losing the tail of one sentence is not a reason to reject an inventory. The verbatim
    /// value survives in the stored blob either way.
    /// </summary>
    private const int MaxDescriptionLength = 1000;

    /// <summary>The bound on the shorter presentation fields — author, copyright, group.</summary>
    private const int MaxTextLength = 400;

    /// <summary>The bound on the serialized hashes array.</summary>
    private const int MaxHashesJsonLength = 2000;

    /// <summary>externalReferences[].type values a component page has somewhere to render.</summary>
    private static readonly IReadOnlySet<string> LinkedReferenceTypes =
        new HashSet<string>(StringComparer.Ordinal) { "website", "vcs", "issue-tracker", "distribution" };

    private static string? Clip(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    // authors[] is the 1.5+ shape and author the string that preceded it; publisher is the
    // organization rather than the person, so it answers last. Producers in current use write
    // all three — cyclonedx-npm emits author, the .NET generator emits authors[] — and a
    // component page that renders one of them and not the others would look empty for whichever
    // half of an inventory came from the other tool.
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
            : JsonRead.String(component, "author") ?? JsonRead.String(component, "publisher");
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

            links.TryAdd(type, Clip(url, MaxTextLength)!);
        }

        return links;
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
        return json.Length <= MaxHashesJsonLength ? json : null;
    }

    // licenses[] entries carry either an SPDX expression or a license object with an id or a
    // free-text name, and one array may mix the two: every entry is read on its own terms rather
    // than the array being classified once as "the expression form" or "the licence-list form".
    // Several entries are folded with OR, the permissive reading — an entry may itself be a
    // compound expression, and OR is the lowest-precedence operator in the grammar, so joining at
    // that level leaves each part's own AND/WITH structure intact. One entry is stored as written,
    // so a document that already carries a compound expression round-trips unchanged.
    private static string? ReadLicenses(JsonElement component)
    {
        var parts = new List<string>();
        foreach (var entry in JsonRead.Array(component, "licenses"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? expression = JsonRead.String(entry, "expression");
            if (!string.IsNullOrWhiteSpace(expression))
            {
                parts.Add(expression);
                continue;
            }

            var license = JsonRead.Object(entry, "license");
            if (license is null)
            {
                continue;
            }

            string? value = JsonRead.String(license.Value, "id") ?? JsonRead.String(license.Value, "name");
            if (!string.IsNullOrWhiteSpace(value))
            {
                parts.Add(value);
            }
        }

        return parts.Count switch
        {
            0 => null,
            1 => parts[0],
            _ => string.Join(" OR ", parts.Distinct(StringComparer.Ordinal)),
        };
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
