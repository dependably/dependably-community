using System.Globalization;
using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// One SARIF result reduced to the facts ingest binds. Every field except
/// <see cref="RuleId"/> is optional, because every one of them lives in a vendor property bag
/// that a producer other than the reachability scanner will simply not carry.
/// </summary>
/// <param name="RuleId">The advisory id, canonical CVE where the producer could resolve one.</param>
/// <param name="Purl">properties.purl — the join key onto the component table, when present.</param>
/// <param name="Reachability">properties.reachability, checked against the column vocabulary.</param>
/// <param name="Confidence">properties.confidence, checked against the column vocabulary.</param>
/// <param name="DependencyScope">properties.dependencyScope — the dev/prod signal.</param>
/// <param name="SbomScope">properties.sbomScope — the SBOM's own scope, echoed back, display only.</param>
/// <param name="DependencyKind">properties.dependencyKind.</param>
/// <param name="DependencyPath">properties.dependencyPath, root-first, empty when absent.</param>
/// <param name="SecuritySeverity">properties['security-severity'] parsed as a number.</param>
/// <param name="SeverityOrigin">properties.severityScoreOrigin.</param>
/// <param name="Fingerprint">partialFingerprints['sbomReach/v1'].</param>
/// <param name="Suppressed">True when the result carries at least one suppression.</param>
/// <param name="SuppressionJustification">The first suppression's justification.</param>
/// <param name="MessageText">message.text, the fallback source of a name@version coordinate.</param>
public sealed record SarifResult(
    string RuleId,
    string? Purl,
    string? Reachability,
    string? Confidence,
    string? DependencyScope,
    string? SbomScope,
    string? DependencyKind,
    IReadOnlyList<string> DependencyPath,
    double? SecuritySeverity,
    string? SeverityOrigin,
    string? Fingerprint,
    bool Suppressed,
    string? SuppressionJustification,
    string? MessageText);

/// <summary>A SARIF log reduced to its results plus the tool that wrote them.</summary>
public sealed record SarifDocument(
    string Version,
    string? ToolName,
    string? ToolVersion,
    IReadOnlyList<SarifResult> Results);

/// <summary>
/// Reads SARIF 2.1.0 with <c>System.Text.Json</c>, first-class for the reachability scanner's
/// documented property contract and defensive for everything else.
///
/// <para>The producer contract this parses is a property bag, not part of SARIF: it moved once
/// already, splitting a merged <c>scope</c> into <c>dependencyScope</c> (does this dependency
/// ship) and <c>sbomScope</c> (what the SBOM declared). Reading each bag independently, and
/// treating an unrecognised or missing bag as an absent fact, is what keeps the next such move
/// from failing an upload — a SARIF log from an unrelated analyzer ingests as results with no
/// reachability facts rather than as a rejected document.</para>
/// </summary>
public static class SarifParser
{
    /// <summary>The only SARIF version ingest accepts.</summary>
    public const string AcceptedVersion = "2.1.0";

    /// <summary>The partialFingerprints key the reachability scanner writes.</summary>
    public const string FingerprintKey = "sbomReach/v1";

    private static readonly IReadOnlySet<string> Reachabilities = new HashSet<string>(StringComparer.Ordinal)
    {
        "reachable", "not-observed", "unknown", "imported-not-called",
    };

    private static readonly IReadOnlySet<string> Confidences = new HashSet<string>(StringComparer.Ordinal)
    {
        "high", "medium", "low",
    };

    /// <summary>The <c>dependency_scope</c> vocabulary; the dev/prod signal.</summary>
    private static readonly IReadOnlySet<string> DependencyScopes = new HashSet<string>(StringComparer.Ordinal)
    {
        "dev", "runtime", "unknown",
    };

    private static readonly IReadOnlySet<string> DependencyKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        "direct", "transitive", "root", "graph-unknown",
    };

    private static readonly IReadOnlySet<string> SeverityOrigins = new HashSet<string>(StringComparer.Ordinal)
    {
        "asserted", "representative",
    };

    /// <summary>Parses the whole log, or throws <see cref="SbomParseException"/>.</summary>
    public static SarifDocument Parse(JsonElement root)
    {
        var runs = ReadRuns(root, out string version);

        string? toolName = null;
        string? toolVersion = null;
        var results = new List<SarifResult>();

        foreach (var run in runs.EnumerateArray())
        {
            if (run.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            // The first run carrying a driver names the tool for the whole document. A later run
            // without one leaves what was already read alone.
            if (toolName is null && ReadTool(run) is { } tool)
            {
                (toolName, toolVersion) = tool;
            }

            ReadRunResults(run, results);
        }

        return new SarifDocument(version, toolName, toolVersion, results);
    }

    /// <summary>
    /// The <c>runs</c> array, once the envelope has been confirmed to be a SARIF log of the one
    /// specification version this build accepts. Throws rather than returning a failure, because
    /// every arm here is a refusal of the whole document.
    /// </summary>
    private static JsonElement ReadRuns(JsonElement root, out string version)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new SbomParseException(SbomParseFailure.Malformed);
        }

        string? declared = JsonRead.String(root, "version");
        if (declared is null || !root.TryGetProperty("runs", out var runs) || runs.ValueKind != JsonValueKind.Array)
        {
            throw new SbomParseException(SbomParseFailure.WrongDocumentKind);
        }

        if (!string.Equals(declared, AcceptedVersion, StringComparison.Ordinal))
        {
            throw new SbomParseException(SbomParseFailure.UnsupportedSpecVersion, declared);
        }

        version = declared;
        return runs;
    }

    /// <summary>The run's driver name and version, or null when the run declares no driver.</summary>
    private static (string? Name, string? Version)? ReadTool(JsonElement run) =>
        JsonRead.Object(JsonRead.Object(run, "tool") ?? default, "driver") is { } driver
            ? (JsonRead.String(driver, "name"),
               JsonRead.String(driver, "version") ?? JsonRead.String(driver, "semanticVersion"))
            : null;

    /// <summary>
    /// Appends one run's results to the document-wide list. The ceiling is checked against that
    /// running total, not per run, because it bounds the rows one upload commits the instance to
    /// and a producer is free to split them over any number of runs.
    /// </summary>
    private static void ReadRunResults(JsonElement run, List<SarifResult> results)
    {
        foreach (var result in JsonRead.Array(run, "results"))
        {
            var parsed = ReadResult(result);
            if (parsed is null)
            {
                continue;
            }

            if (results.Count >= SbomDocumentLimits.MaxResults)
            {
                throw new SbomParseException(
                    SbomParseFailure.TooManyResults,
                    SbomDocumentLimits.MaxResults.ToString(CultureInfo.InvariantCulture));
            }

            results.Add(parsed);
        }
    }

    private static SarifResult? ReadResult(JsonElement result)
    {
        if (result.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        string? ruleId = JsonRead.String(result, "ruleId");
        if (ruleId is null)
        {
            // A result with no rule id names no advisory, so there is nothing to key an
            // analysis row on. Counted as unmatched by the caller, never invented.
            return null;
        }

        var properties = JsonRead.Object(result, "properties") ?? default;
        var (suppressed, justification) = ReadSuppression(result);

        return new SarifResult(
            ruleId,
            JsonRead.String(properties, "purl"),
            Admit(JsonRead.String(properties, "reachability"), Reachabilities),
            Admit(JsonRead.String(properties, "confidence"), Confidences),
            Admit(JsonRead.String(properties, "dependencyScope"), DependencyScopes),
            Admit(JsonRead.String(properties, "sbomScope"), CycloneDxScopes),
            Admit(JsonRead.String(properties, "dependencyKind"), DependencyKinds),
            JsonRead.StringArray(properties, "dependencyPath"),
            ParseSeverity(JsonRead.StringOrNumber(properties, "security-severity")),
            Admit(JsonRead.String(properties, "severityScoreOrigin"), SeverityOrigins),
            ReadFingerprint(result),
            suppressed,
            justification,
            JsonRead.String(JsonRead.Object(result, "message") ?? default, "text"));
    }

    /// <summary>The CycloneDX scope vocabulary the producer echoes back in <c>sbomScope</c>.</summary>
    private static readonly IReadOnlySet<string> CycloneDxScopes = new HashSet<string>(StringComparer.Ordinal)
    {
        "required", "optional", "excluded",
    };

    private static string? Admit(string? value, IReadOnlySet<string> vocabulary) =>
        value is not null && vocabulary.Contains(value) ? value : null;

    private static double? ParseSeverity(string? raw) =>
        raw is not null && double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed)
            ? parsed
            : null;

    private static string? ReadFingerprint(JsonElement result)
    {
        var fingerprints = JsonRead.Object(result, "partialFingerprints");
        return fingerprints is null ? null : JsonRead.String(fingerprints.Value, FingerprintKey);
    }

    // A suppressed result stays a result: it is recorded with the flag set rather than dropped,
    // so a reader can tell "the analyzer accepted a VEX statement here" from "the analyzer never
    // looked". Only the first justification is kept — the column holds one.
    private static (bool Suppressed, string? Justification) ReadSuppression(JsonElement result)
    {
        foreach (var suppression in JsonRead.Array(result, "suppressions"))
        {
            if (suppression.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            return (true, JsonRead.String(suppression, "justification"));
        }

        return (false, null);
    }
}
