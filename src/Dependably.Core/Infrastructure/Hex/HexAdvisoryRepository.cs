using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Protocol;
using Dependably.Protocol.Hex;

namespace Dependably.Infrastructure.Hex;

/// <summary>An advisory as the Hex registry index carries it, with the owners (version or cache rows) it touches.</summary>
public sealed record HexAdvisoryRow(
    string OsvId,
    string? Summary,
    string? Severity,
    double? CvssScore,
    IReadOnlyList<string> Aliases,
    IReadOnlyList<string> OwnerIds);

/// <summary>
/// Projects this registry's recorded vulnerabilities into the <c>SecurityAdvisory</c> entries a
/// Hex <c>Package</c> resource carries — the one ecosystem whose native protocol shows a client
/// the advisories the registry knows about, before resolution, with no extra tooling. Only
/// versions this org actually holds (hosted or cached) have rows; an upstream-only release
/// carries no advisory here because nothing has been scanned.
/// </summary>
public sealed class HexAdvisoryRepository
{
    private readonly IMetadataStore _db;

    public HexAdvisoryRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Advisories touching any of the given owner ids (package_versions ids for hosted releases,
    /// cache_artifact ids for proxied ones), grouped by advisory. Withdrawn OSV entries are
    /// excluded the same way the block gate excludes them.
    /// </summary>
    public async Task<IReadOnlyList<HexAdvisoryRow>> ListForOwnersAsync(IReadOnlyList<string> ownerIds, CancellationToken ct = default)
    {
        if (ownerIds.Count == 0)
        {
            return Array.Empty<HexAdvisoryRow>();
        }

        var (pvClause, pvParams) = DapperInClause.Expand("pv", ownerIds);
        var (caClause, caParams) = DapperInClause.Expand("ca", ownerIds);
        var parameters = new DynamicParameters(pvParams);
        parameters.AddDynamicParams(caParams);

        await using var conn = await _db.OpenAsync(ct);
        // rawsql: the two IN (...) clauses come from DapperInClause.Expand — parameter names only,
        // never a caller value.
        // xtenant: package_version_vulns is keyed by owner ids the caller already resolved through
        // its own org-scoped release listing; no id here can name another tenant's row.
        var rows = await conn.QueryAsync<RawRow>(
            $"""
            SELECT v.osv_id AS OsvId, v.summary AS Summary, v.severity AS Severity, v.cvss_score AS CvssScore,
                   v.aliases AS AliasesJson, v.osv_json AS OsvJson,
                   COALESCE(pvv.package_version_id, pvv.cache_artifact_id) AS OwnerId
            FROM package_version_vulns pvv
            JOIN vulnerabilities v ON v.id = pvv.vuln_id
            WHERE (pvv.owner_kind = 'package_version' AND pvv.package_version_id IN {pvClause})
               OR (pvv.owner_kind = 'cache_artifact' AND pvv.cache_artifact_id IN {caClause})
            """,
            parameters);

        var byId = new Dictionary<string, (RawRow Row, List<string> Owners)>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (row.OwnerId is null || IsWithdrawn(row.OsvJson))
            {
                continue;
            }

            if (!byId.TryGetValue(row.OsvId, out var entry))
            {
                entry = (row, new List<string>());
                byId[row.OsvId] = entry;
            }

            if (!entry.Owners.Contains(row.OwnerId, StringComparer.Ordinal))
            {
                entry.Owners.Add(row.OwnerId);
            }
        }

        return byId.Values
            .OrderBy(e => e.Row.OsvId, StringComparer.Ordinal)
            .Select(e => new HexAdvisoryRow(
                e.Row.OsvId, e.Row.Summary, OsvScoring.NormalizeSeverity(e.Row.Severity), e.Row.CvssScore,
                ParseAliases(e.Row.AliasesJson), e.Owners))
            .ToList();
    }

    /// <summary>The wire form of one advisory, with the OSV URLs a Hex client links to.</summary>
    public static HexSecurityAdvisory ToWire(HexAdvisoryRow row) => new(
        row.OsvId,
        string.IsNullOrWhiteSpace(row.Summary) ? row.OsvId : row.Summary,
        $"https://osv.dev/vulnerability/{Uri.EscapeDataString(row.OsvId)}",
        $"https://api.osv.dev/v1/vulns/{Uri.EscapeDataString(row.OsvId)}",
        SeverityToWire(row.Severity),
        row.CvssScore is { } s ? (float)s : null,
        row.Aliases.Count > 0 ? row.Aliases : null);

    /// <summary>Maps this registry's severity band onto the protocol enum; an unscored advisory carries no band rather than a fabricated one.</summary>
    public static HexAdvisorySeverity? SeverityToWire(string? severity) => severity switch
    {
        "CRITICAL" => HexAdvisorySeverity.Critical,
        "HIGH" => HexAdvisorySeverity.High,
        "MEDIUM" or "MODERATE" => HexAdvisorySeverity.Medium,
        "LOW" => HexAdvisorySeverity.Low,
        "NONE" => HexAdvisorySeverity.None,
        _ => null,
    };

    private static bool IsWithdrawn(string? osvJson)
    {
        if (string.IsNullOrEmpty(osvJson))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(osvJson);
            return doc.RootElement.TryGetProperty("withdrawn", out var w) && w.ValueKind == JsonValueKind.String;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static IReadOnlyList<string> ParseAliases(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return Array.Empty<string>();
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return Array.Empty<string>();
        }
    }

    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection.")]
    private sealed class RawRow
    {
        public string OsvId { get; set; } = "";
        public string? Summary { get; set; }
        public string? Severity { get; set; }
        public double? CvssScore { get; set; }
        public string? AliasesJson { get; set; }
        public string? OsvJson { get; set; }
        public string? OwnerId { get; set; }
    }
}
