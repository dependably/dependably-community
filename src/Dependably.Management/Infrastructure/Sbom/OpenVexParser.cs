using System.Globalization;
using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>One OpenVEX statement, already normalized onto the CycloneDX analysis vocabulary.</summary>
public sealed record OpenVexStatement(
    string VulnId,
    IReadOnlyList<string> ProductRefs,
    string? State,
    string? Justification,
    string? Detail);

/// <summary>An OpenVEX document reduced to its statements plus the tool that wrote it.</summary>
public sealed record OpenVexDocument(
    string? ToolName,
    IReadOnlyList<OpenVexStatement> Statements);

/// <summary>
/// Reads OpenVEX with <c>System.Text.Json</c> and normalizes it onto the CycloneDX analysis
/// vocabulary at the boundary, so exactly one state machine, one triage editor and one renderer
/// serve both formats. The alternative — two vocabularies stored side by side — pushes the
/// mapping into every reader, where it is written differently each time.
/// </summary>
public static class OpenVexParser
{
    /// <summary>The <c>@context</c> prefix that identifies an OpenVEX document.</summary>
    public const string ContextPrefix = "https://openvex.dev/";

    /// <summary>True when the document declares the OpenVEX context.</summary>
    public static bool IsOpenVex(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        string? context = JsonRead.String(root, "@context");
        return context is not null && context.StartsWith(ContextPrefix, StringComparison.Ordinal);
    }

    /// <summary>Parses the whole document, or throws <see cref="SbomParseException"/>.</summary>
    public static OpenVexDocument Parse(JsonElement root)
    {
        if (!IsOpenVex(root))
        {
            throw new SbomParseException(SbomParseFailure.WrongDocumentKind);
        }

        var statements = new List<OpenVexStatement>();
        int charged = 0;
        foreach (var entry in JsonRead.Array(root, "statements"))
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string? vulnId = ReadVulnerabilityId(entry);
            if (vulnId is null)
            {
                continue;
            }

            var products = ReadProducts(entry);

            // Charged once per component the statement names, because that pair is what becomes
            // a row; a statement naming none still charges one. See SbomDocumentLimits.
            charged += Math.Max(1, products.Count);
            if (charged > SbomDocumentLimits.MaxComponentStatements)
            {
                throw new SbomParseException(
                    SbomParseFailure.TooManyStatements,
                    SbomDocumentLimits.MaxComponentStatements.ToString(CultureInfo.InvariantCulture));
            }

            string? status = JsonRead.String(entry, "status");
            statements.Add(new OpenVexStatement(
                vulnId,
                products,
                VexVocabulary.FromOpenVexStatus(status),
                VexVocabulary.FromOpenVexJustification(JsonRead.String(entry, "justification")),
                JsonRead.String(entry, "action_statement") ?? JsonRead.String(entry, "impact_statement")));
        }

        return new OpenVexDocument(JsonRead.String(root, "tooling"), statements);
    }

    // OpenVEX 0.2.0 carries the id as an object {"name": "CVE-…"}; earlier drafts and some
    // producers write a bare string. Both spellings name the same advisory.
    private static string? ReadVulnerabilityId(JsonElement statement)
    {
        string? bare = JsonRead.String(statement, "vulnerability");
        if (bare is not null)
        {
            return bare;
        }

        var nested = JsonRead.Object(statement, "vulnerability");
        return nested is null
            ? null
            : JsonRead.String(nested.Value, "name") ?? JsonRead.String(nested.Value, "@id");
    }

    // products[] entries are objects carrying an @id (a purl), with the same bare-string
    // tolerance as the vulnerability id. subcomponents are deliberately not descended into:
    // a statement about a subcomponent is a statement about a different product than the one
    // the component table keys on.
    private static List<string> ReadProducts(JsonElement statement)
    {
        var products = new List<string>();
        foreach (var entry in JsonRead.Array(statement, "products"))
        {
            string? id = entry.ValueKind switch
            {
                JsonValueKind.String => entry.GetString(),
                JsonValueKind.Object => JsonRead.String(entry, "@id") ?? JsonRead.String(entry, "purl"),
                _ => null,
            };

            if (!string.IsNullOrWhiteSpace(id))
            {
                products.Add(id);
            }
        }

        return products;
    }
}
