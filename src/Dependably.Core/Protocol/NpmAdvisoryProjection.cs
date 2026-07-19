using System.Text.Json;
using System.Text.Json.Serialization;
using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// One advisory in npm's bulk-advisories wire format. Property names are pinned with explicit
/// <see cref="JsonPropertyNameAttribute"/> rather than a serializer naming policy because the
/// shape is not uniformly cased: the top level is snake_case (<c>vulnerable_versions</c>) while
/// the nested CVSS object is camelCase (<c>vectorString</c>). The consumer is
/// <c>@npmcli/metavuln-calculator</c>'s <c>Advisory</c> constructor, which reads exactly these
/// keys off each element.
/// </summary>
public sealed record NpmAuditAdvisory(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("url")] string? Url,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("vulnerable_versions")] string VulnerableVersions,
    [property: JsonPropertyName("cwe")] string[] Cwe,
    [property: JsonPropertyName("cvss")] NpmAuditCvss Cvss);

/// <summary>
/// npm's CVSS sub-object. <see cref="Score"/> is null — never 0 — when the advisory carries no
/// CVSS vector: 0 is a real CVSS value meaning "None", so emitting it for an unscored advisory
/// would assert a score OSV never assigned.
/// </summary>
public sealed record NpmAuditCvss(
    [property: JsonPropertyName("score")] double? Score,
    [property: JsonPropertyName("vectorString")] string? VectorString);

/// <summary>
/// Projects OSV advisories into npm's bulk-advisories wire format.
///
/// Severity mapping — npm's vocabulary is exactly <c>info|low|moderate|high|critical</c>
/// (npm's <c>audit-level</c> config type, and <c>npm-audit-report</c>'s exit-code table, which
/// silently ignores any severity outside that set). OSV's CVSS bands map
/// CRITICAL→critical, HIGH→high, MEDIUM→<b>moderate</b>, LOW→low, NONE→info. Two deliberate
/// cases sit outside the band mapping:
/// <list type="bullet">
///   <item><b>Unscored</b> advisories (no CVSS vector, no recognised
///   <c>database_specific.severity</c>) project to <c>info</c>, npm's lowest bucket. This mirrors
///   <see cref="OsvScoring.SeverityRank"/>, where an unscored advisory ranks 0 and never meets a
///   threshold: <c>info</c> is below the default <c>audit-level</c> of <c>low</c>, so it is
///   surfaced in the report but never silently asserts a severity the data does not support.
///   Omitting the field instead is not an option — metavuln-calculator defaults a missing
///   severity to <c>high</c>, inventing a rating outright.</item>
///   <item><b>Malicious-package</b> reports (OSV <c>MAL-</c> ids from the OpenSSF
///   malicious-packages feed) project to <c>critical</c>. They almost never carry a CVSS vector,
///   and the block gate already treats them as a signal independent of any score
///   (<see cref="Infrastructure.VulnGateSignals.HasMalicious"/>) — reporting confirmed malware as
///   <c>info</c> would bury it.</item>
/// </list>
/// </summary>
public static class NpmAdvisoryProjection
{
    /// <summary>The npm ecosystem key for <see cref="EcosystemVersionOrdering"/> comparisons.</summary>
    private const string NpmEcosystem = "npm";

    /// <summary>OSV's "since the first release" lower bound; deliberately never version-parsed.</summary>
    private const string IntroducedFromStart = "0";

    private static readonly JsonSerializerOptions OsvJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    /// <summary>
    /// Parses an advisory's captured raw OSV JSON into the full schema shape, which carries the
    /// <c>affected[].ranges[].events[]</c> data <see cref="OsvAdvisory"/> itself does not model.
    /// Returns null when the advisory has no raw JSON or it does not parse — callers degrade to
    /// the querying source's own verdict rather than dropping the advisory.
    /// </summary>
    public static OsvDetail? TryParseDetail(string? rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<OsvDetail>(rawJson, OsvJsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// True when <paramref name="version"/> falls inside one of the advisory's affected intervals
    /// for <paramref name="packageName"/>.
    ///
    /// This is a filter applied on top of the source's own matching, and it is what keeps a
    /// version at a <c>fixed</c> boundary out of the report: <c>LocalOsvSource</c> deliberately
    /// returns range-only advisories for <i>every</i> version of a package (it matches only
    /// enumerated <c>versions[]</c>), so without an interval check an air-gapped audit would
    /// flag already-patched versions.
    ///
    /// Fail-safe, never fail-open: when the advisory carries no usable interval data for this
    /// package (no raw JSON, no <c>versions[]</c>, no non-GIT ranges) the source's verdict stands
    /// and the advisory is reported.
    /// </summary>
    public static bool Affects(OsvDetail? detail, string packageName, string version)
    {
        var entries = MatchingEntries(detail, packageName);
        if (entries.Count == 0)
        {
            return true;
        }

        bool sawUsableData = false;

        foreach (var entry in entries)
        {
            if (entry.Versions is { Length: > 0 } versions)
            {
                sawUsableData = true;
                if (versions.Any(v => string.Equals(v, version, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }

            foreach (var interval in Intervals(entry))
            {
                sawUsableData = true;
                if (interval.Contains(version))
                {
                    return true;
                }
            }
        }

        // No interval data at all for this package — defer to the source rather than hide it.
        return !sawUsableData;
    }

    /// <summary>
    /// Renders the advisory's affected intervals for <paramref name="packageName"/> as an npm
    /// semver range string (npm's <c>vulnerable_versions</c>).
    ///
    /// <paramref name="knownAffectedVersions"/> are the requested versions already proven affected
    /// by <see cref="Affects"/>; they are the fallback when nothing renders from the OSV data.
    /// The fallback matters: metavuln-calculator coerces a missing or empty
    /// <c>vulnerable_versions</c> to <c>*</c>, which would mark every version of the package
    /// vulnerable — so this never returns an empty string.
    /// </summary>
    public static string VulnerableVersions(
        OsvDetail? detail, string packageName, IReadOnlyList<string> knownAffectedVersions)
    {
        var clauses = new List<string>();

        foreach (var entry in MatchingEntries(detail, packageName))
        {
            foreach (var interval in Intervals(entry))
            {
                AddClause(clauses, interval.ToRangeString());
            }

            // An entry with no ranges but an enumerated versions[] pins exact versions.
            if (entry.Ranges is not { Length: > 0 } && entry.Versions is { Length: > 0 } versions)
            {
                foreach (string v in versions)
                {
                    AddClause(clauses, v);
                }
            }
        }

        if (clauses.Count > 0)
        {
            return string.Join(" || ", clauses);
        }

        // Nothing renderable: name the exact versions this request proved affected. Honest for
        // this answer and, unlike an empty string, never widens to "*".
        return knownAffectedVersions.Count > 0
            ? string.Join(" || ", knownAffectedVersions.Distinct(StringComparer.Ordinal))
            : "*";
    }

    /// <summary>
    /// Maps an advisory to npm's severity vocabulary. See the type-level remarks for why unscored
    /// projects to <c>info</c> and <c>MAL-</c> to <c>critical</c>.
    /// </summary>
    public static string Severity(OsvAdvisory advisory) =>
        IsMalicious(advisory.Id)
            ? "critical"
            : advisory.Severity?.ToUpperInvariant() switch
            {
                "CRITICAL" => "critical",
                "HIGH" => "high",
                "MEDIUM" => "moderate",
                "LOW" => "low",
                // "NONE" is a real CVSS band (score 0.0); everything else — including a null or
                // unrecognised severity — is genuinely unscored. Both are informational, never "low".
                _ => "info",
            };

    /// <summary>
    /// Projects one advisory into npm's wire shape. <paramref name="knownAffectedVersions"/> are
    /// the requested versions this advisory was proven to affect.
    /// </summary>
    public static NpmAuditAdvisory Project(
        OsvAdvisory advisory, OsvDetail? detail, string packageName,
        IReadOnlyList<string> knownAffectedVersions)
    {
        return new NpmAuditAdvisory(
            Id: advisory.Id,
            Url: AdvisoryUrl(advisory.Id),
            Title: advisory.Summary,
            Severity: Severity(advisory),
            VulnerableVersions: VulnerableVersions(detail, packageName, knownAffectedVersions),
            Cwe: ExtractCweIds(detail?.DatabaseSpecific),
            Cvss: new NpmAuditCvss(advisory.CvssScore, CvssVector(detail)));
    }

    /// <summary>
    /// Extracts <c>database_specific.cwe_ids</c> (the GHSA-carried CWE signal). Malformed or
    /// absent input degrades to an empty array, never an error.
    /// </summary>
    public static string[] ExtractCweIds(JsonElement? databaseSpecific)
    {
        if (databaseSpecific is not { ValueKind: JsonValueKind.Object } de
            || !de.TryGetProperty("cwe_ids", out var cweIds)
            || cweIds.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var result = new List<string>();
        foreach (var item in cweIds.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } s)
            {
                result.Add(s);
            }
        }

        return [.. result];
    }

    private static bool IsMalicious(string id) => id.StartsWith("MAL-", StringComparison.Ordinal);

    // OSV ids resolve at osv.dev regardless of the advisory's home database, which keeps the
    // link honest for GHSA-, CVE-, and MAL- ids alike without guessing per-database URLs.
    private static string? AdvisoryUrl(string id) =>
        string.IsNullOrEmpty(id) ? null : "https://osv.dev/vulnerability/" + Uri.EscapeDataString(id);

    private static string? CvssVector(OsvDetail? detail) =>
        detail?.Severity?.FirstOrDefault(s =>
            s.Type?.StartsWith("CVSS", StringComparison.OrdinalIgnoreCase) == true)?.Score;

    private static void AddClause(List<string> clauses, string clause)
    {
        if (!string.IsNullOrWhiteSpace(clause) && !clauses.Contains(clause, StringComparer.Ordinal))
        {
            clauses.Add(clause);
        }
    }

    // Entries whose package name matches are preferred; when none match (OSV name spellings can
    // diverge from ours) every entry is considered, so projection degrades rather than vanishes —
    // the same fallback FixedVersionResolver applies.
    private static List<OsvAffectedDetail> MatchingEntries(OsvDetail? detail, string packageName)
    {
        var affected = detail?.Affected;
        if (affected is not { Length: > 0 })
        {
            return [];
        }

        var matching = affected.Where(a => MatchesPackage(a.Package, packageName)).ToList();
        return matching.Count > 0 ? matching : affected.ToList();
    }

    private static bool MatchesPackage(OsvAffectedPackageRef? pkg, string packageName)
    {
        if (pkg is null)
        {
            return false;
        }

        if (string.Equals(pkg.Name, packageName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // OSV purls are versionless base purls (pkg:npm/left-pad); match on the name tail. Scoped
        // names are percent-encoded in a purl (pkg:npm/%40scope/pkg), so compare both spellings.
        if (pkg.Purl is null)
        {
            return false;
        }

        string encoded = packageName.StartsWith('@')
            ? "%40" + packageName[1..]
            : packageName;

        return pkg.Purl.EndsWith("/" + packageName, StringComparison.OrdinalIgnoreCase)
            || pkg.Purl.EndsWith(":" + packageName, StringComparison.OrdinalIgnoreCase)
            || pkg.Purl.EndsWith("/" + encoded, StringComparison.OrdinalIgnoreCase)
            || pkg.Purl.EndsWith(":" + encoded, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Walks an affected entry's ranges into closed-open intervals. OSV orders events ascending:
    /// each <c>introduced</c> opens an interval and the next <c>fixed</c>/<c>last_affected</c>
    /// closes it. GIT ranges hold commit hashes, never package versions, and are skipped.
    /// </summary>
    private static IEnumerable<AffectedInterval> Intervals(OsvAffectedDetail entry)
    {
        foreach (var range in entry.Ranges ?? [])
        {
            if (range.Events is not { Length: > 0 }
                || string.Equals(range.Type, "GIT", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var interval in IntervalsForRange(range))
            {
                yield return interval;
            }
        }
    }

    // Walks one range's ascending introduced/fixed/last_affected events into closed-open
    // intervals — see Intervals above for the OSV event-ordering contract.
    private static IEnumerable<AffectedInterval> IntervalsForRange(OsvRange range)
    {
        string? introduced = null;
        bool open = false;

        foreach (var ev in range.Events!)
        {
            if (ev.Introduced is not null)
            {
                introduced = ev.Introduced;
                open = true;
                continue;
            }

            if (!open)
            {
                continue; // closing event before any introduced — malformed; skip it
            }

            if (ev.Fixed is not null)
            {
                yield return new AffectedInterval(introduced, ev.Fixed, null);
                open = false;
            }
            else if (ev.LastAffected is not null)
            {
                yield return new AffectedInterval(introduced, null, ev.LastAffected);
                open = false;
            }
            // `limit` events only bound GIT ranges; irrelevant here.
        }

        if (open)
        {
            yield return new AffectedInterval(introduced, null, null);
        }
    }

    /// <summary>
    /// One affected interval: <c>[Introduced, Fixed)</c> — half-open, so a version exactly at
    /// <c>Fixed</c> is patched and not affected — or <c>[Introduced, LastAffected]</c>, which is
    /// closed at both ends. An interval with neither upper bound runs to the latest version.
    /// </summary>
    private readonly record struct AffectedInterval(string? Introduced, string? Fixed, string? LastAffected)
    {
        internal bool Contains(string version)
        {
            if (!AboveLowerBound(version))
            {
                return false;
            }

            if (Fixed is not null)
            {
                // Half-open upper bound: version < fixed. An unparseable comparison yields null,
                // which fails closed here (not affected) only for this bound.
                return EcosystemVersionOrdering.Compare(NpmEcosystem, version, Fixed) is < 0;
            }

            return LastAffected is null
                || EcosystemVersionOrdering.Compare(NpmEcosystem, version, LastAffected) is <= 0;
        }

        // OSV uses introduced: "0" for "since the beginning" — below any real version, and
        // deliberately not parsed ("0" is not a valid semver).
        private bool AboveLowerBound(string version) =>
            Introduced is null
            || Introduced == IntroducedFromStart
            || EcosystemVersionOrdering.Compare(NpmEcosystem, version, Introduced) is >= 0;

        internal string ToRangeString()
        {
            string? lower = Introduced is null or IntroducedFromStart ? null : ">=" + Introduced;
            string? upper = Fixed is not null ? "<" + Fixed
                : LastAffected is not null ? "<=" + LastAffected
                : null;

            return (lower, upper) switch
            {
                (null, null) => "*",
                (not null, null) => lower,
                (null, not null) => upper,
                _ => lower + " " + upper,
            };
        }
    }
}
