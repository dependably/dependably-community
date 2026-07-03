using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-org signature trust anchors. Each (org, ecosystem) may have multiple anchors — the
/// verifier resolves all rows for a pair and accepts a signature verified by any of them.
/// Mirrors the shape of <see cref="UpstreamRegistryRepository"/>: parameterized Dapper only,
/// org_id-filtered on every query, BOLA-safe delete.
/// </summary>
public sealed class TrustAnchorRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public TrustAnchorRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>The set of ecosystems that support per-org trust anchors.</summary>
    public static readonly IReadOnlyList<string> SupportedEcosystems =
        ["rpm", "npm", "nuget", "pypi", "maven"];

    /// <summary>Allowed anchor_kind discriminator values.</summary>
    public static readonly IReadOnlyList<string> AllowedAnchorKinds =
        ["pgp", "spki", "x509", "sigstore_root", "trusted_publisher", "rekor_key"];

    public static bool IsSupportedEcosystem(string? ecosystem) =>
        ecosystem is not null && SupportedEcosystems.Contains(ecosystem);

    public static bool IsAllowedAnchorKind(string? kind) =>
        kind is not null && AllowedAnchorKinds.Contains(kind);

    /// <summary>
    /// All anchors for an org, ordered by ecosystem then created_at. The <c>material</c>
    /// column is excluded — callers use this for display and IsConfiguredFor checks only.
    /// </summary>
    public async Task<IReadOnlyList<TrustAnchorEntry>> ListAsync(
        string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<RawAnchorRow>(
            """
            SELECT id, org_id AS OrgId, ecosystem AS Ecosystem, anchor_kind AS AnchorKind,
                   key_id AS KeyId, label AS Label, created_at AS CreatedAt, created_by AS CreatedBy
            FROM signature_trust_anchor
            WHERE org_id = @orgId
            ORDER BY ecosystem, created_at
            """,
            new { orgId });
        return rows.Select(MapRow).ToList();
    }

    /// <summary>
    /// All anchors for one (org, ecosystem), including the raw <c>material</c> text — used
    /// by the per-ecosystem verifier store at verify time.
    /// </summary>
    public async Task<IReadOnlyList<TrustAnchorMaterial>> ListForEcosystemAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<TrustAnchorMaterial>(
            """
            SELECT id AS Id, anchor_kind AS AnchorKind, key_id AS KeyId,
                   label AS Label, material AS Material
            FROM signature_trust_anchor
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            ORDER BY created_at
            """,
            new { orgId, ecosystem });
        return rows.ToList();
    }

    /// <summary>
    /// Returns true when at least one anchor exists for the given (org, ecosystem). Used by
    /// the IsConfiguredFor gate without fetching the full material.
    /// </summary>
    public async Task<bool> AnyAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int count = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(1) FROM signature_trust_anchor
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            """,
            new { orgId, ecosystem });
        return count > 0;
    }

    /// <summary>
    /// Inserts a new trust anchor and returns the hydrated entry (without material).
    /// The caller is responsible for validating ecosystem and anchorKind beforehand.
    /// </summary>
    public async Task<TrustAnchorEntry> AddAsync(
        string orgId, NewTrustAnchor req, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        var now = _time.GetUtcNow();
        string nowStr = now.ToString("yyyy-MM-ddTHH:mm:ssZ");
        string ecosystem = req.Ecosystem;
        string anchorKind = req.AnchorKind;
        string material = req.Material;
        string? keyId = req.KeyId;
        string? label = req.Label;
        string? createdBy = req.CreatedBy;

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO signature_trust_anchor
                (id, org_id, ecosystem, anchor_kind, key_id, material, label, created_at, created_by)
            VALUES (@id, @orgId, @ecosystem, @anchorKind, @keyId, @material, @label, @createdAt, @createdBy)
            """,
            new { id, orgId, ecosystem, anchorKind, keyId, material, label, createdAt = nowStr, createdBy });

        return new TrustAnchorEntry
        {
            Id = id,
            OrgId = orgId,
            Ecosystem = ecosystem,
            AnchorKind = anchorKind,
            KeyId = keyId,
            Label = label,
            CreatedAt = now,
            CreatedBy = createdBy,
        };
    }

    /// <summary>Deletes an anchor, scoped to its owning org (BOLA-safe).</summary>
    public async Task DeleteAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM signature_trust_anchor WHERE id = @id AND org_id = @orgId",
            new { id, orgId });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static TrustAnchorEntry MapRow(RawAnchorRow r) => new()
    {
        Id = r.Id ?? "",
        OrgId = r.OrgId ?? "",
        Ecosystem = r.Ecosystem ?? "",
        AnchorKind = r.AnchorKind ?? "",
        KeyId = r.KeyId,
        Label = r.Label,
        CreatedAt = r.CreatedAt,
        CreatedBy = r.CreatedBy,
    };

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class RawAnchorRow
    {
        public string? Id { get; set; }
        public string? OrgId { get; set; }
        public string? Ecosystem { get; set; }
        public string? AnchorKind { get; set; }
        public string? KeyId { get; set; }
        public string? Label { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public string? CreatedBy { get; set; }
    }
}

/// <summary>
/// Full material row returned by <see cref="TrustAnchorRepository.ListForEcosystemAsync"/>.
/// Contains the raw <c>material</c> text used by verifiers at request time; never surfaced
/// by the API list endpoint.
/// </summary>
public sealed class TrustAnchorMaterial
{
    public string Id { get; set; } = "";
    public string AnchorKind { get; set; } = "";
    public string? KeyId { get; set; }
    public string? Label { get; set; }
    public string Material { get; set; } = "";
}

/// <summary>Input record for adding a new per-org trust anchor.</summary>
public sealed record NewTrustAnchor(
    string Ecosystem,
    string AnchorKind,
    string Material,
    string? KeyId = null,
    string? Label = null,
    string? CreatedBy = null);
