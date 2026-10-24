using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Protocol;

/// <summary>
/// Parses one complete OSV record (the osv-schema JSON object) into an <see cref="OsvAdvisory"/>,
/// for records that reach Dependably from outside its own OSV sources: the OCI image scanner
/// posts the full record for every advisory it matched.
///
/// <para>Severity and CVSS selection go through <see cref="OsvScoring"/>, as in
/// <see cref="OsvClient"/> and <see cref="LocalOsvSource"/>, so an advisory scores the same
/// whichever path brought it in. The record is hydrated by definition (it is the whole record),
/// and <see cref="OsvAdvisory.RawJson"/> keeps it verbatim for persistence.</para>
/// </summary>
public static class OsvRecordParser
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// The advisory, or null when <paramref name="record"/> is not an OSV record: not an object,
    /// or missing a non-empty <c>id</c>.
    /// </summary>
    public static OsvAdvisory? TryParse(JsonElement record)
    {
        if (record.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        Raw? raw;
        try
        {
            raw = record.Deserialize<Raw>(Options);
        }
        catch (JsonException)
        {
            return null;
        }

        if (raw is null || string.IsNullOrWhiteSpace(raw.Id))
        {
            return null;
        }

        var affected = raw.Affected?
            .Where(a => a.Package is not null)
            .Select(a => new OsvAffectedPackage(
                Purl: a.Package!.Purl,
                Ecosystem: a.Package.Ecosystem,
                Name: a.Package.Name,
                Versions: a.Versions?.Distinct().ToArray() ?? []))
            .ToArray() ?? [];

        (double? cvssScore, string? severity) = OsvScoring.SelectCvssBaseScore(
            raw.Severity?.Select(s => (s.Type, s.Score)));
        if (severity is null && raw.DatabaseSpecific?.TryGetValue("severity", out var dbSeverity) == true
            && dbSeverity.ValueKind == JsonValueKind.String)
        {
            severity = dbSeverity.GetString();
        }

        return new OsvAdvisory(
            Id: raw.Id,
            Aliases: raw.Aliases?.Where(a => !string.IsNullOrWhiteSpace(a)).ToArray() ?? [],
            Summary: raw.Summary,
            Severity: OsvScoring.NormalizeSeverity(severity),
            CvssScore: cvssScore,
            AffectedPackages: affected,
            Published: raw.Published,
            Modified: raw.Modified,
            IsHydrated: true,
            RawJson: record.GetRawText());
    }

    private sealed record Raw(
        string? Id,
        List<string>? Aliases,
        string? Summary,
        List<RawSeverity>? Severity,
        List<RawAffected>? Affected,
        string? Published,
        string? Modified,
        [property: JsonPropertyName("database_specific")] Dictionary<string, JsonElement>? DatabaseSpecific);

    private sealed record RawSeverity(string? Type, string? Score);

    private sealed record RawAffected(RawPackage? Package, List<string>? Versions);

    private sealed record RawPackage(string? Ecosystem, string? Name, string? Purl);
}
