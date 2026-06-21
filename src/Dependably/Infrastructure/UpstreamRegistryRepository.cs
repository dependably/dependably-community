using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Configuration;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-org upstream proxy registries. Each (org, ecosystem) owns a priority-ordered list
/// (ascending <c>position</c>, lowest tried first). The proxy fetch path walks the list and
/// falls through to the next entry on miss/unreachable; an empty list disables proxying for
/// that ecosystem. Mirrors the shape of <see cref="AllowlistRepository"/>.
/// </summary>
public sealed class UpstreamRegistryRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public UpstreamRegistryRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// All ecosystems whose upstream lists are user-configurable through this table.
    /// OCI upstreams are DB-backed per-org (same table); the legacy config-file approach
    /// (<c>Oci:Upstreams</c>) is no longer used.
    /// </summary>
    public static readonly IReadOnlyList<string> SupportedEcosystems =
        ["pypi", "npm", "nuget", "maven", "rpm", "cargo", "golang", "oci"];

    public static bool IsSupportedEcosystem(string? ecosystem) =>
        ecosystem is not null && SupportedEcosystems.Contains(ecosystem);

    /// <summary>All entries for an org, ordered by ecosystem then priority.</summary>
    public async Task<IReadOnlyList<UpstreamRegistryEntry>> ListAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<RawRegistryRow>(
            """
            SELECT id, org_id AS OrgId, ecosystem AS Ecosystem, name AS Name,
                   url AS Url, position AS Position, created_at AS CreatedAt,
                   auth_type AS AuthType, username AS Username,
                   token_endpoint AS TokenEndpoint, prefixes AS PrefixesJson,
                   CASE WHEN secret IS NOT NULL THEN 1 ELSE 0 END AS HasSecret
            FROM upstream_registry
            WHERE org_id = @orgId
            ORDER BY ecosystem, position, created_at
            """,
            new { orgId });
        return rows.Select(MapRow).ToList();
    }

    /// <summary>The configured registry URLs for one (org, ecosystem) in priority order.</summary>
    public async Task<IReadOnlyList<string>> ListUrlsForEcosystemAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<string>(
            """
            SELECT url
            FROM upstream_registry
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            ORDER BY position, created_at
            """,
            new { orgId, ecosystem });
        return rows.ToList();
    }

    /// <summary>
    /// Appends a non-OCI registry at the bottom of the (org, ecosystem) priority list.
    /// The new <c>position</c> is one past the current max so the entry is tried last.
    /// For OCI registries use <see cref="AddOciAsync"/>.
    /// </summary>
    public async Task<UpstreamRegistryEntry> AddAsync(
        string orgId, string ecosystem, string url, string? name, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        int nextPosition = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COALESCE(MAX(position), -1) + 1
            FROM upstream_registry
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            """,
            new { orgId, ecosystem });

        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, name, url, position)
            VALUES (@id, @orgId, @ecosystem, @name, @url, @position)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, ecosystem, name, url, position = nextPosition });

        return new UpstreamRegistryEntry
        {
            Id = id,
            OrgId = orgId,
            Ecosystem = ecosystem,
            Name = name,
            Url = url,
            Position = nextPosition,
            CreatedAt = _time.GetUtcNow(),
        };
    }

    /// <summary>
    /// Appends an OCI upstream registry at the bottom of the org's OCI priority list.
    /// Accepts the full OCI-specific field set via <see cref="NewOciUpstreamRegistry"/>.
    /// </summary>
    public async Task<UpstreamRegistryEntry> AddOciAsync(
        string orgId, NewOciUpstreamRegistry req, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string prefixesJson = JsonSerializer.Serialize(req.Prefixes);
        string authTypeStr = OciAuthTypeToString(req.AuthType);

        await using var conn = await _db.OpenAsync(ct);
        int nextPosition = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COALESCE(MAX(position), -1) + 1
            FROM upstream_registry
            WHERE org_id = @orgId AND ecosystem = 'oci'
            """,
            new { orgId });

        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry
                (id, org_id, ecosystem, name, url, position, auth_type, username, secret, token_endpoint, prefixes)
            VALUES
                (@id, @orgId, 'oci', @name, @url, @position, @authType, @username, @secret, @tokenEndpoint, @prefixes)
            ON CONFLICT DO NOTHING
            """,
            new
            {
                id,
                orgId,
                name = req.Name,
                url = req.Host,
                position = nextPosition,
                authType = authTypeStr,
                username = req.Username,
                secret = req.Secret,
                tokenEndpoint = req.TokenEndpoint,
                prefixes = prefixesJson,
            });

        return new UpstreamRegistryEntry
        {
            Id = id,
            OrgId = orgId,
            Ecosystem = "oci",
            Name = req.Name,
            Url = req.Host,
            Position = nextPosition,
            CreatedAt = _time.GetUtcNow(),
            AuthType = authTypeStr,
            Username = req.Username,
            TokenEndpoint = req.TokenEndpoint,
            Prefixes = req.Prefixes,
            HasSecret = req.Secret is not null,
        };
    }

    /// <summary>Deletes a registry, scoped to its owning org (BOLA-safe).</summary>
    public async Task DeleteAsync(string orgId, string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE id = @id AND org_id = @orgId",
            new { id = entryId, orgId });
    }

    /// <summary>
    /// Reassigns <c>position</c> across the (org, ecosystem) list to match <paramref name="orderedIds"/>.
    /// Only ids that belong to this (org, ecosystem) are repositioned; unknown ids are ignored, and
    /// any entries omitted from the list keep their relative order after the supplied ones.
    /// </summary>
    public async Task ReorderAsync(
        string orgId, string ecosystem, IReadOnlyList<string> orderedIds, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            var existing = (await conn.QueryAsync<string>(
                "SELECT id FROM upstream_registry WHERE org_id = @orgId AND ecosystem = @ecosystem",
                new { orgId, ecosystem }, dbTx)).ToHashSet();

            // Honour the requested order first, then append any entries the caller left out so no
            // row loses its position.
            var ordered = orderedIds.Where(existing.Contains).ToList();
            ordered.AddRange(existing.Where(id => !ordered.Contains(id)));

            for (int i = 0; i < ordered.Count; i++)
            {
                await conn.ExecuteAsync(
                    "UPDATE upstream_registry SET position = @position WHERE id = @id AND org_id = @orgId",
                    new { position = i, id = ordered[i], orgId }, dbTx);
            }

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    /// <summary>
    /// Builds the ordered OCI upstream list for one org, selecting the secret into Password
    /// for use by the resolver and auth service. Never called on the API-facing read path —
    /// this is the internal resolver bridge only.
    /// </summary>
    public async Task<IReadOnlyList<OciUpstreamRegistryOptions>> BuildOciUpstreamsForOrgAsync(
        string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<RawRegistryRow>(
            """
            SELECT id, url AS Url, auth_type AS AuthType, username AS Username,
                   secret AS Secret, token_endpoint AS TokenEndpoint, prefixes AS PrefixesJson
            FROM upstream_registry
            WHERE org_id = @orgId AND ecosystem = 'oci'
            ORDER BY position, created_at
            """,
            new { orgId });

        return rows.Select(r => new OciUpstreamRegistryOptions
        {
            Name = r.Url ?? "",
            Host = r.Url ?? "",
            AuthType = StringToOciAuthType(r.AuthType),
            Username = r.Username,
            Password = r.Secret,
            TokenEndpoint = r.TokenEndpoint,
            Prefixes = ParsePrefixes(r.PrefixesJson),
        }).ToList();
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static UpstreamRegistryEntry MapRow(RawRegistryRow r) => new()
    {
        Id = r.Id ?? "",
        OrgId = r.OrgId ?? "",
        Ecosystem = r.Ecosystem ?? "",
        Name = r.Name,
        Url = r.Url ?? "",
        Position = r.Position,
        CreatedAt = r.CreatedAt,
        AuthType = r.AuthType,
        Username = r.Username,
        TokenEndpoint = r.TokenEndpoint,
        Prefixes = ParsePrefixes(r.PrefixesJson),
        HasSecret = r.HasSecret,
    };

    private static List<string> ParsePrefixes(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    internal static string OciAuthTypeToString(OciAuthType authType) => authType switch
    {
        OciAuthType.Anonymous => "anonymous",
        OciAuthType.Basic => "basic",
        OciAuthType.DockerHubTokenExchange => "dockerhub_token_exchange",
        OciAuthType.AwsEcr => "aws_ecr",
        _ => "anonymous",
    };

    internal static OciAuthType StringToOciAuthType(string? value) => value switch
    {
        "basic" => OciAuthType.Basic,
        "dockerhub_token_exchange" => OciAuthType.DockerHubTokenExchange,
        "aws_ecr" => OciAuthType.AwsEcr,
        _ => OciAuthType.Anonymous,
    };

    // Internal DTO for raw DB rows (Dapper-mapped before deserialization of JSON columns).
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these row-mapping props by reflection at the QueryAsync<RawRegistryRow> mapping site; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these row-mapping props by reflection at the QueryAsync<RawRegistryRow> mapping site; not statically visible as used.")]
    private sealed class RawRegistryRow
    {
        public string? Id { get; set; }
        public string? OrgId { get; set; }
        public string? Ecosystem { get; set; }
        public string? Name { get; set; }
        public string? Url { get; set; }
        public int Position { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        // Auth fields
        public string? AuthType { get; set; }
        public string? Username { get; set; }
        public string? Secret { get; set; }
        public string? TokenEndpoint { get; set; }
        // Prefixes as raw JSON TEXT (parsed by ParsePrefixes)
        public string? PrefixesJson { get; set; }
        public bool HasSecret { get; set; }
    }
}

/// <summary>Input record for adding a new OCI upstream registry.</summary>
public sealed record NewOciUpstreamRegistry(
    string Host,
    OciAuthType AuthType,
    IReadOnlyList<string> Prefixes,
    string? Name = null,
    string? Username = null,
    string? Secret = null,
    string? TokenEndpoint = null);
