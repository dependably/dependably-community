using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Protocol.Hex;

namespace Dependably.Infrastructure.Hex;

/// <summary>The per-release facts a Hex registry index is built from, as stored on <c>hex_release</c>.</summary>
public sealed record HexReleaseFacts(
    string InnerChecksumHex,
    IReadOnlyList<HexRequirement> Requirements,
    string? App,
    IReadOnlyList<string> BuildTools,
    string? Elixir,
    HexRetirementReason? RetiredReason,
    string? RetiredMessage,
    bool HasDocs,
    string? MetadataConfig);

/// <summary>One release as the index sees it: the stored facts plus the version and the plane it lives on.</summary>
public sealed record HexIndexedRelease(
    string Version,
    HexReleaseFacts Facts,
    string OuterChecksumHex,
    DateTimeOffset? PublishedAt,
    bool Hosted,
    string OwnerId);

/// <summary>
/// Reads and writes <c>hex_release</c>, the polymorphic-owner table beside <c>package_versions</c>
/// (hosted releases) and <c>cache_artifact</c> (proxied ones). Same shape as
/// <c>CargoMetadataRepository</c>: the hosted arm is tenant-gated through <c>packages.org_id</c>,
/// the cached arm through <c>tenant_artifact_access.org_id</c>, and on a version collision the
/// hosted release shadows the cached one.
/// </summary>
public sealed class HexReleaseRepository
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly IMetadataStore _db;

    public HexReleaseRepository(IMetadataStore db) => _db = db;

    /// <summary>Every release of <paramref name="name"/> this org can serve, hosted first, newest last within each plane.</summary>
    // The `seen` set is both the filter and the accumulator, and it carries ACROSS the two
    // loops — a hosted release shadows the cached row of the same version. A LINQ rewrite would
    // put that mutation inside a lazily-evaluated Where predicate, where the shadowing depends on
    // enumeration order and timing rather than on the statement order written here.
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "The loop body mutates the dedup set shared with the following loop; a Where predicate with that side "
            + "effect would make hosted-shadows-cached depend on lazy enumeration order.")]
    public async Task<IReadOnlyList<HexIndexedRelease>> ListForPackageAsync(string orgId, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // plane-ok: PV-plane releases; global-plane releases are UNIONed via the sibling cache_artifact SELECT in this method.
        var hosted = await conn.QueryAsync<Row>(
            """
            SELECT hr.inner_checksum AS InnerChecksum, hr.requirements_json AS RequirementsJson, hr.app AS App,
                   hr.build_tools_json AS BuildToolsJson, hr.elixir AS Elixir, hr.retired_reason AS RetiredReason,
                   hr.retired_message AS RetiredMessage, hr.has_docs AS HasDocs, hr.metadata_config AS MetadataConfig,
                   pv.version AS Version, pv.checksum_sha256 AS OuterChecksum, pv.created_at AS PublishedAt,
                   pv.id AS OwnerId
            FROM hex_release hr
            JOIN package_versions pv ON pv.id = hr.version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE hr.owner_kind = 'package_version'
              AND p.org_id = @orgId
              AND p.ecosystem = 'hex'
              AND p.name = @name
            ORDER BY pv.created_at, pv.id
            """,
            new { orgId, name });

        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var cached = await conn.QueryAsync<Row>(
            """
            SELECT hr.inner_checksum AS InnerChecksum, hr.requirements_json AS RequirementsJson, hr.app AS App,
                   hr.build_tools_json AS BuildToolsJson, hr.elixir AS Elixir, hr.retired_reason AS RetiredReason,
                   hr.retired_message AS RetiredMessage, hr.has_docs AS HasDocs, hr.metadata_config AS MetadataConfig,
                   ca.version AS Version, ca.content_hash AS OuterChecksum, ca.published_at AS PublishedAt,
                   ca.id AS OwnerId
            FROM hex_release hr
            JOIN cache_artifact ca ON ca.id = hr.cache_artifact_id
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE hr.owner_kind = 'cache_artifact'
              AND ca.ecosystem = 'hex'
              AND ca.name = @name
            ORDER BY ca.first_cached_at, ca.id
            """,
            new { orgId, name });

        var result = new List<HexIndexedRelease>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in hosted)
        {
            if (seen.Add(row.Version))
            {
                result.Add(Map(row, hosted: true));
            }
        }

        foreach (var row in cached)
        {
            if (seen.Add(row.Version))
            {
                result.Add(Map(row, hosted: false));
            }
        }

        return result;
    }

    /// <summary>Every (name, version) pair this org can serve, for <c>/names</c> and <c>/versions</c>.</summary>
    // The `seen` set is both the filter and the accumulator, and it carries ACROSS the two
    // loops — a hosted release shadows the cached row of the same version. A LINQ rewrite would
    // put that mutation inside a lazily-evaluated Where predicate, where the shadowing depends on
    // enumeration order and timing rather than on the statement order written here.
    [SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with LINQ expressions",
        Justification = "The loop body mutates the dedup set shared with the following loop; a Where predicate with that side "
            + "effect would make hosted-shadows-cached depend on lazy enumeration order.")]
    public async Task<IReadOnlyList<(string Name, HexIndexedRelease Release)>> ListAllAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // plane-ok: PV-plane releases; global-plane releases are UNIONed via the sibling cache_artifact SELECT in this method.
        var hosted = await conn.QueryAsync<NamedRow>(
            """
            SELECT p.name AS Name,
                   hr.inner_checksum AS InnerChecksum, hr.requirements_json AS RequirementsJson, hr.app AS App,
                   hr.build_tools_json AS BuildToolsJson, hr.elixir AS Elixir, hr.retired_reason AS RetiredReason,
                   hr.retired_message AS RetiredMessage, hr.has_docs AS HasDocs, NULL AS MetadataConfig,
                   pv.version AS Version, pv.checksum_sha256 AS OuterChecksum, pv.created_at AS PublishedAt,
                   pv.id AS OwnerId
            FROM hex_release hr
            JOIN package_versions pv ON pv.id = hr.version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE hr.owner_kind = 'package_version'
              AND p.org_id = @orgId
              AND p.ecosystem = 'hex'
            ORDER BY p.name, pv.created_at, pv.id
            """,
            new { orgId });

        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var cached = await conn.QueryAsync<NamedRow>(
            """
            SELECT ca.name AS Name,
                   hr.inner_checksum AS InnerChecksum, hr.requirements_json AS RequirementsJson, hr.app AS App,
                   hr.build_tools_json AS BuildToolsJson, hr.elixir AS Elixir, hr.retired_reason AS RetiredReason,
                   hr.retired_message AS RetiredMessage, hr.has_docs AS HasDocs, NULL AS MetadataConfig,
                   ca.version AS Version, ca.content_hash AS OuterChecksum, ca.published_at AS PublishedAt,
                   ca.id AS OwnerId
            FROM hex_release hr
            JOIN cache_artifact ca ON ca.id = hr.cache_artifact_id
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE hr.owner_kind = 'cache_artifact'
              AND ca.ecosystem = 'hex'
            ORDER BY ca.name, ca.first_cached_at, ca.id
            """,
            new { orgId });

        var result = new List<(string, HexIndexedRelease)>();
        var seen = new HashSet<(string, string)>();
        foreach (var row in hosted)
        {
            if (seen.Add((row.Name, row.Version)))
            {
                result.Add((row.Name, Map(row, hosted: true)));
            }
        }

        foreach (var row in cached)
        {
            if (seen.Add((row.Name, row.Version)))
            {
                result.Add((row.Name, Map(row, hosted: false)));
            }
        }

        return result;
    }

    /// <summary>The hosted release facts for one version, or null when this org holds no such hosted release.</summary>
    public async Task<HexIndexedRelease?> GetHostedAsync(string orgId, string name, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // plane-ok: a hosted-only lookup by contract — the API plane answers for releases this org
        // published; a proxied release is read through ListForPackageAsync's cache_artifact arm.
        var row = await conn.QuerySingleOrDefaultAsync<Row>(
            """
            SELECT hr.inner_checksum AS InnerChecksum, hr.requirements_json AS RequirementsJson, hr.app AS App,
                   hr.build_tools_json AS BuildToolsJson, hr.elixir AS Elixir, hr.retired_reason AS RetiredReason,
                   hr.retired_message AS RetiredMessage, hr.has_docs AS HasDocs, hr.metadata_config AS MetadataConfig,
                   pv.version AS Version, pv.checksum_sha256 AS OuterChecksum, pv.created_at AS PublishedAt,
                   pv.id AS OwnerId
            FROM hex_release hr
            JOIN package_versions pv ON pv.id = hr.version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE hr.owner_kind = 'package_version'
              AND p.org_id = @orgId
              AND p.ecosystem = 'hex'
              AND p.name = @name
              AND pv.version = @version
            """,
            new { orgId, name, version });
        return row is null ? null : Map(row, hosted: true);
    }

    /// <summary>Writes the facts of a hosted release, keyed on its package_versions row.</summary>
    // xtenant: version_id is an FK to an org-scoped package_versions row created by the caller's own publish.
    public async Task UpsertHostedAsync(string versionId, HexReleaseFacts facts, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO hex_release (id, version_id, owner_kind, inner_checksum, requirements_json, app, build_tools_json,
                                     elixir, retired_reason, retired_message, has_docs, metadata_config)
            VALUES (@id, @versionId, 'package_version', @inner, @requirements, @app, @buildTools,
                    @elixir, @retiredReason, @retiredMessage, @hasDocs, @metadataConfig)
            ON CONFLICT (version_id) WHERE owner_kind = 'package_version' DO UPDATE SET
                inner_checksum = excluded.inner_checksum, requirements_json = excluded.requirements_json,
                app = excluded.app, build_tools_json = excluded.build_tools_json, elixir = excluded.elixir,
                retired_reason = excluded.retired_reason, retired_message = excluded.retired_message,
                has_docs = excluded.has_docs, metadata_config = excluded.metadata_config
            """,
            Parameters(Guid.NewGuid().ToString("N"), versionId, null, facts));
    }

    /// <summary>Writes the facts of a proxied release, keyed on the cache_artifact row the first fetch recorded.</summary>
    // xtenant: cache_artifact is global; the id comes from CacheAccessRecorder, never from a caller-supplied value.
    public async Task UpsertCachedAsync(string cacheArtifactId, HexReleaseFacts facts, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO hex_release (id, cache_artifact_id, owner_kind, inner_checksum, requirements_json, app, build_tools_json,
                                     elixir, retired_reason, retired_message, has_docs, metadata_config)
            VALUES (@id, @cacheArtifactId, 'cache_artifact', @inner, @requirements, @app, @buildTools,
                    @elixir, @retiredReason, @retiredMessage, @hasDocs, NULL)
            ON CONFLICT (cache_artifact_id) WHERE owner_kind = 'cache_artifact' DO UPDATE SET
                inner_checksum = excluded.inner_checksum, requirements_json = excluded.requirements_json,
                app = excluded.app, build_tools_json = excluded.build_tools_json, elixir = excluded.elixir,
                retired_reason = excluded.retired_reason, retired_message = excluded.retired_message,
                has_docs = excluded.has_docs
            """,
            Parameters(Guid.NewGuid().ToString("N"), null, cacheArtifactId, facts));
    }

    /// <summary>Sets or clears a hosted release's retirement. Returns false when this org holds no such hosted release.</summary>
    public async Task<bool> SetRetirementAsync(
        string orgId, string name, string version, HexRetirementReason? reason, string? message, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE hex_release SET retired_reason = @reason, retired_message = @message
            WHERE owner_kind = 'package_version'
              AND version_id IN (
                  SELECT pv.id FROM package_versions pv
                  JOIN packages p ON p.id = pv.package_id
                  WHERE p.org_id = @orgId AND p.ecosystem = 'hex' AND p.name = @name AND pv.version = @version)
            """,
            new { orgId, name, version, reason = reason is { } r ? ReasonToWire(r) : null, message });
        return rows > 0;
    }

    /// <summary>Marks whether a hosted release has a docs tarball stored beside it.</summary>
    public async Task<bool> SetHasDocsAsync(string orgId, string name, string version, bool hasDocs, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE hex_release SET has_docs = @hasDocs
            WHERE owner_kind = 'package_version'
              AND version_id IN (
                  SELECT pv.id FROM package_versions pv
                  JOIN packages p ON p.id = pv.package_id
                  WHERE p.org_id = @orgId AND p.ecosystem = 'hex' AND p.name = @name AND pv.version = @version)
            """,
            new { orgId, name, version, hasDocs = hasDocs ? 1 : 0 });
        return rows > 0;
    }

    private static object Parameters(string id, string? versionId, string? cacheArtifactId, HexReleaseFacts f) => new
    {
        id,
        versionId,
        cacheArtifactId,
        inner = f.InnerChecksumHex.ToUpperInvariant(),
        requirements = JsonSerializer.Serialize(f.Requirements, Json),
        app = f.App,
        buildTools = f.BuildTools.Count == 0 ? null : JsonSerializer.Serialize(f.BuildTools, Json),
        elixir = f.Elixir,
        retiredReason = f.RetiredReason is { } r ? ReasonToWire(r) : null,
        retiredMessage = f.RetiredMessage,
        hasDocs = f.HasDocs ? 1 : 0,
        metadataConfig = f.MetadataConfig,
    };

    /// <summary>The API-plane spelling of a retirement reason (<c>other</c>, <c>invalid</c>, …), as the stored column and the Hex API use it.</summary>
    public static string ReasonToWire(HexRetirementReason reason) => reason switch
    {
        HexRetirementReason.Invalid => "invalid",
        HexRetirementReason.Security => "security",
        HexRetirementReason.Deprecated => "deprecated",
        HexRetirementReason.Renamed => "renamed",
        _ => "other",
    };

    public static HexRetirementReason? ReasonFromWire(string? value) => value switch
    {
        null => null,
        "invalid" => HexRetirementReason.Invalid,
        "security" => HexRetirementReason.Security,
        "deprecated" => HexRetirementReason.Deprecated,
        "renamed" => HexRetirementReason.Renamed,
        _ => HexRetirementReason.Other,
    };

    private static HexIndexedRelease Map(Row r, bool hosted)
    {
        var requirements = JsonSerializer.Deserialize<List<HexRequirement>>(r.RequirementsJson ?? "[]", Json) ?? [];
        var buildTools = r.BuildToolsJson is null ? [] : JsonSerializer.Deserialize<List<string>>(r.BuildToolsJson, Json) ?? [];
        var facts = new HexReleaseFacts(r.InnerChecksum, requirements, r.App, buildTools, r.Elixir,
            ReasonFromWire(r.RetiredReason), r.RetiredMessage, r.HasDocs != 0, r.MetadataConfig);
        DateTimeOffset? publishedAt = r.PublishedAt is null ? null
            : DateTimeOffset.TryParse(r.PublishedAt, null,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var p) ? p : null;
        return new HexIndexedRelease(r.Version, facts, r.OuterChecksum ?? "", publishedAt, hosted, r.OwnerId);
    }

    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection.")]
    private class Row
    {
        public string InnerChecksum { get; set; } = "";
        public string? RequirementsJson { get; set; }
        public string? App { get; set; }
        public string? BuildToolsJson { get; set; }
        public string? Elixir { get; set; }
        public string? RetiredReason { get; set; }
        public string? RetiredMessage { get; set; }
        public long HasDocs { get; set; }
        public string? MetadataConfig { get; set; }
        public string Version { get; set; } = "";
        public string? OuterChecksum { get; set; }
        public string? PublishedAt { get; set; }
        public string OwnerId { get; set; } = "";
    }

    private sealed class NamedRow : Row
    {
        public string Name { get; set; } = "";
    }
}
