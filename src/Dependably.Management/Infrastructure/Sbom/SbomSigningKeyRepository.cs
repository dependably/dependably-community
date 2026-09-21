using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure.Sbom;

/// <summary>An org's active SBOM signing key: the private half ready to sign, the fingerprint that is the signature's <c>keyId</c>.</summary>
public sealed record SbomSigningKey(string Id, string OrgId, ECDsa PrivateKey) : IDisposable
{
    public void Dispose() => PrivateKey.Dispose();
}

/// <summary>One published public half, for <c>GET /api/v1/sbom-signing-keys</c> and Settings.</summary>
public sealed record SbomSigningPublicKey(
    string Id, string Algorithm, string PublicKeyPem,
    DateTimeOffset CreatedAt, DateTimeOffset? RetiredAt, DateTimeOffset? RevokedAt);

/// <summary>
/// The per-org ECDSA P-256 keypair that signs an exported CycloneDX document's enveloped JSF
/// signature (ADR-sbom-author-signature). Reuses everything about the Hex signing-key path
/// except the key itself: generation on first use, <see cref="EnvelopeProtector"/> for the
/// private half, <see cref="CanSign"/> gating on the master key, and the
/// SHA-256-over-DER-SubjectPublicKeyInfo fingerprint spelling
/// (<see cref="Dependably.Infrastructure.Hex.HexSigningKeyRepository.ComputeFingerprint"/>'s ECDSA
/// counterpart). It is a distinct table and a distinct key: SBOM signing and Hex registry
/// signing are independent lifecycles (see the ADR's "key separation" section), and unlike
/// <c>hex_signing_key</c>, rows here accumulate — rotation retires the current row rather than
/// deleting it, so a document signed under a retired key stays verifiable indefinitely.
/// </summary>
public sealed class SbomSigningKeyRepository
{
    private readonly IMetadataStore _db;
    private readonly EnvelopeProtector _envelope;
    private readonly TimeProvider _time;
    private readonly IEdgeMode _edge;

    public SbomSigningKeyRepository(IMetadataStore db, EnvelopeProtector envelope, TimeProvider time, IEdgeMode edge)
    {
        _db = db;
        _envelope = envelope;
        _time = time;
        _edge = edge;
    }

    /// <summary>
    /// True when a private key can be stored and read back: the master key is configured and
    /// this node is one that signs at all. The projects/SBOM plane does not exist on an edge
    /// node at all (management-only), so this is never even reached there in practice — but the
    /// same explicit check Hex uses is kept for defense in depth.
    /// </summary>
    public bool CanSign => _envelope.IsConfigured && !_edge.IsEdge;

    /// <summary>
    /// The org's active (non-retired) key, generated on first call. Returns null when signing is
    /// not possible (<see cref="CanSign"/> is false), which callers answer by emitting an
    /// unsigned document with <c>dependably:signature-state</c> = <c>unsigned-no-master-key</c>.
    /// The caller owns the returned key and disposes it.
    /// </summary>
    public async Task<SbomSigningKey?> GetOrCreateAsync(string orgId, CancellationToken ct = default)
    {
        if (!CanSign)
        {
            return null;
        }

        var existing = await GetActiveAsync(orgId, ct);
        if (existing is not null)
        {
            return existing;
        }

        // Two replicas creating the org's first key at once must converge on one: the partial
        // unique index on (org_id) WHERE retired_at IS NULL makes the loser's INSERT a no-op, and
        // both re-read the winner.
        using var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await InsertAsync(orgId, generated, ct);
        return await GetActiveAsync(orgId, ct);
    }

    /// <summary>
    /// Whether the org has an active (non-retired) signing key row at all — an org-scoped fact
    /// deliberately independent of <see cref="CanSign"/>: it reads only the row's existence, not
    /// its private key material, so it answers correctly even on a replica whose own
    /// <c>DEPENDABLY_MASTER_KEY</c> is unset. This is what lets <see cref="SbomAuthorSigner"/>
    /// tell "this org has never had a key" from "this org has a key this replica cannot read
    /// right now" — see <c>SbomExportService.Revision.cs</c>'s class doc comment.
    /// </summary>
    public async Task<bool> HasActiveKeyAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? id = await conn.QuerySingleOrDefaultAsync<string?>(
            new CommandDefinition(
                "SELECT id FROM sbom_signing_key WHERE org_id = @orgId AND retired_at IS NULL",
                new { orgId },
                cancellationToken: ct));
        return id is not null;
    }

    /// <summary>The org's active key, or null when none exists yet or signing is not possible.</summary>
    public async Task<SbomSigningKey?> GetActiveAsync(string orgId, CancellationToken ct = default)
    {
        if (!CanSign)
        {
            return null;
        }

        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<KeyRow>(
            """
            SELECT id AS Id, org_id AS OrgId, private_key AS PrivateKey
            FROM sbom_signing_key
            WHERE org_id = @orgId AND retired_at IS NULL
            """,
            new { orgId });
        if (row is null)
        {
            return null;
        }

        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(_envelope.Unprotect(row.PrivateKey));
        return new SbomSigningKey(row.Id, row.OrgId, ecdsa);
    }

    /// <summary>
    /// Every key the org has ever used — active, retired and revoked — in <c>created_at</c>
    /// order, for <c>GET /api/v1/sbom-signing-keys</c> and Settings. A retired key's public half
    /// stays listed indefinitely: an SBOM is a file someone saved, and deleting the public half
    /// would make every document signed under it permanently unverifiable.
    /// </summary>
    public async Task<IReadOnlyList<SbomSigningPublicKey>> ListPublicAsync(
        string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<PublicKeyRow>(
            """
            SELECT id AS Id, algorithm AS Algorithm, public_key_pem AS PublicKeyPem,
                   created_at AS CreatedAt, retired_at AS RetiredAt, revoked_at AS RevokedAt
            FROM sbom_signing_key
            WHERE org_id = @orgId
            ORDER BY created_at
            """,
            new { orgId });
        return rows.Select(r => new SbomSigningPublicKey(
            r.Id, r.Algorithm, r.PublicKeyPem,
            ParseTimestamp(r.CreatedAt)!.Value, ParseTimestamp(r.RetiredAt), ParseTimestamp(r.RevokedAt)))
            .ToList();
    }

    /// <summary>
    /// Retires the org's current active key (stamps <c>retired_at</c>; the row and its public
    /// half stay published) and mints a fresh one, which becomes the active key for every
    /// export from this point on. An explicit operator action, never automatic — a key that
    /// changes on its own breaks verification for a consumer who pinned the old fingerprint and
    /// was doing everything right.
    /// </summary>
    public async Task<SbomSigningKey> RotateAsync(string orgId, CancellationToken ct = default)
    {
        if (!CanSign)
        {
            throw new InvalidOperationException("SBOM signing requires DEPENDABLY_MASTER_KEY.");
        }

        using var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string id = ComputeFingerprint(generated);
        string publicPem = generated.ExportSubjectPublicKeyInfoPem();
        string protectedPem = _envelope.Protect(generated.ExportPkcs8PrivateKeyPem());
        string nowIso = _time.GetUtcNow().ToUtcIso();

        // Retiring the current key and inserting its replacement run in ONE transaction, not two
        // separate statements: split across separate connections, a concurrent export reading in
        // the gap between them would see zero active keys — read as "no master key" by
        // GetOrCreateAsync's caller even though the master key IS configured — and could race its
        // own Insert into the same partial-unique slot this one is about to fill, leaving whichever
        // insert loses silently discarded by ON CONFLICT DO NOTHING. That is a correctness bug, not
        // just a wrong signature-state string: this method could return a key that was never
        // actually written, because the final re-read resolves to whatever DID win.
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            await conn.ExecuteAsync(
                new CommandDefinition(
                    "UPDATE sbom_signing_key SET retired_at = @now WHERE org_id = @orgId AND retired_at IS NULL",
                    new { orgId, now = nowIso },
                    tx, cancellationToken: ct));

            // Matches InsertAsync's own ON CONFLICT shape: harmless if nothing is actually racing
            // for the slot inside this transaction, and still the correct fallback if something is.
            await conn.ExecuteAsync(
                new CommandDefinition(
                    """
                    INSERT INTO sbom_signing_key (id, org_id, algorithm, private_key, public_key_pem, created_at)
                    VALUES (@id, @orgId, 'ES256', @privateKey, @publicKeyPem, @createdAt)
                    ON CONFLICT (org_id) WHERE retired_at IS NULL DO NOTHING
                    """,
                    new { id, orgId, privateKey = protectedPem, publicKeyPem = publicPem, createdAt = nowIso },
                    tx, cancellationToken: ct));

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        return await GetActiveAsync(orgId, ct)
            ?? throw new InvalidOperationException("SBOM signing key vanished after rotation.");
    }

    /// <summary>
    /// Announces compromise of a specific key (stamps <c>revoked_at</c>). Not a mechanism — there
    /// is no CRL/OCSP/transparency log — but a consumer resolving this key afterward sees the
    /// instant from which signatures under it are no longer trusted. Scoped to the owning org
    /// (BOLA-safe); a no-op if the id does not belong to this org or is already revoked.
    /// </summary>
    public async Task RevokeAsync(string orgId, string keyId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE sbom_signing_key SET revoked_at = @now WHERE id = @keyId AND org_id = @orgId AND revoked_at IS NULL",
            new { keyId, orgId, now = _time.GetUtcNow().ToUtcIso() });
    }

    private async Task InsertAsync(string orgId, ECDsa key, CancellationToken ct)
    {
        string id = ComputeFingerprint(key);
        string publicPem = key.ExportSubjectPublicKeyInfoPem();
        string privatePem = key.ExportPkcs8PrivateKeyPem();
        string protectedPem = _envelope.Protect(privatePem);
        string nowIso = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        // Two replicas each mint a genuinely different random keypair, so their fingerprints
        // (the `id`) essentially never collide — the race this guards against is two replicas
        // BOTH trying to become the org's active key at once, which the partial unique index on
        // (org_id) WHERE retired_at IS NULL is what actually catches. The conflict target names
        // that index explicitly (its own WHERE clause repeated), matching the ON CONFLICT DO
        // NOTHING shape HexSigningKeyRepository uses for its own (non-partial) org_id PK.
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_signing_key (id, org_id, algorithm, private_key, public_key_pem, created_at)
            VALUES (@id, @orgId, 'ES256', @privateKey, @publicKeyPem, @createdAt)
            ON CONFLICT (org_id) WHERE retired_at IS NULL DO NOTHING
            """,
            new { id, orgId, privateKey = protectedPem, publicKeyPem = publicPem, createdAt = nowIso });
    }

    /// <summary>SHA-256 over the DER SubjectPublicKeyInfo, lower-case hex — the value that is both this row's id and the signature's <c>keyId</c>.</summary>
    public static string ComputeFingerprint(ECDsa key) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

    private static DateTimeOffset? ParseTimestamp(string? iso) =>
        iso is null
            ? null
            : DateTimeOffset.Parse(iso, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);

    private sealed class KeyRow
    {
        public string Id { get; set; } = "";
        public string OrgId { get; set; } = "";
        public string PrivateKey { get; set; } = "";
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class PublicKeyRow
    {
        public string Id { get; set; } = "";
        public string Algorithm { get; set; } = "";
        public string PublicKeyPem { get; set; } = "";
        public string CreatedAt { get; set; } = "";
        public string? RetiredAt { get; set; }
        public string? RevokedAt { get; set; }
    }
}
