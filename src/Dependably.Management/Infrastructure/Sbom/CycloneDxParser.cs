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
        new HashSet<string>(StringComparer.Ordinal) { "1.4", "1.5", "1.6" };

    /// <summary>components[].scope values the <c>sbom_scope</c> CHECK admits.</summary>
    private static readonly IReadOnlySet<string> AcceptedScopes =
        new HashSet<string>(StringComparer.Ordinal) { "required", "optional", "excluded" };

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
            components.Add(new CycloneDxComponent(
                JsonRead.String(entry, "bom-ref"),
                name,
                JsonRead.String(entry, "version"),
                JsonRead.String(entry, "type"),
                JsonRead.String(entry, "purl"),
                scope is not null && AcceptedScopes.Contains(scope) ? scope : null,
                ReadLicenses(entry)));
        }

        return components;
    }

    // licenses[] entries carry either an SPDX expression or a license object with an id or a
    // free-text name. Several entries mean several licences apply as alternatives, which is how
    // the SPDX expression grammar spells OR; one entry is stored as written so a document that
    // already carries a compound expression round-trips unchanged.
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
