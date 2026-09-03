using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure.Identity;
using Dependably.Protocol.Hex;

namespace Dependably.Infrastructure.Hex;

/// <summary>An org's Hex signing key: the private half ready to sign, the public half ready to serve.</summary>
public sealed record HexSigningKey(string OrgId, RSA PrivateKey, string PublicKeyPem, string Fingerprint, DateTimeOffset CreatedAt) : IDisposable
{
    public void Dispose() => PrivateKey.Dispose();
}

/// <summary>
/// The per-org RSA keypair that signs every Hex registry resource this org serves. The private
/// key is stored only as <see cref="EnvelopeProtector"/> ciphertext, so signing is possible only
/// when <c>DEPENDABLY_MASTER_KEY</c> is configured: with no master key there is no key to sign
/// with and the read plane refuses rather than serving an unsigned or plaintext-keyed index.
/// An edge node signs nothing and so never holds a key at all.
/// A key is created on first use and rotated by replacing the row; rotation is a client-visible
/// event (every consumer re-registers the repository with the new public key), which is why it
/// is an explicit operator action and never automatic.
/// </summary>
public sealed class HexSigningKeyRepository
{
    private readonly IMetadataStore _db;
    private readonly EnvelopeProtector _envelope;
    private readonly TimeProvider _time;
    private readonly IEdgeMode _edge;

    public HexSigningKeyRepository(IMetadataStore db, EnvelopeProtector envelope, TimeProvider time, IEdgeMode edge)
    {
        _db = db;
        _envelope = envelope;
        _time = time;
        _edge = edge;
    }

    /// <summary>
    /// True when a private key can be stored and read back: the master key is configured and this
    /// node is one that signs at all. An edge node never does — it serves its master's signed
    /// resources unchanged — and a key minted there would be one no client has registered, so the
    /// refusal is structural rather than left to each call site remembering not to ask.
    /// </summary>
    public bool CanSign => _envelope.IsConfigured && !_edge.IsEdge;

    /// <summary>
    /// The org's key, generated and stored on first call. Returns null when signing is not
    /// possible (<see cref="CanSign"/> is false), which callers answer with a 503 that names
    /// the missing configuration. The caller owns the returned key and disposes it.
    /// </summary>
    public async Task<HexSigningKey?> GetOrCreateAsync(string orgId, CancellationToken ct = default)
    {
        if (!CanSign)
        {
            return null;
        }

        var existing = await GetAsync(orgId, ct);
        if (existing is not null)
        {
            return existing;
        }

        // Two replicas creating the org's first key at once must converge on one: the row is
        // keyed on org_id, so the loser's INSERT is ignored and both re-read the winner.
        using var generated = HexRegistrySigner.GenerateSigningKey();
        await InsertAsync(orgId, generated, ct);
        return await GetAsync(orgId, ct);
    }

    /// <summary>The org's key, or null when none exists yet or signing is not possible.</summary>
    public async Task<HexSigningKey?> GetAsync(string orgId, CancellationToken ct = default)
    {
        if (!CanSign)
        {
            return null;
        }

        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<KeyRow>(
            """
            SELECT org_id AS OrgId, private_key AS PrivateKey, public_key_pem AS PublicKeyPem,
                   fingerprint AS Fingerprint, created_at AS CreatedAt
            FROM hex_signing_key
            WHERE org_id = @orgId
            """,
            new { orgId });
        if (row is null)
        {
            return null;
        }

        var rsa = RSA.Create();
        rsa.ImportFromPem(_envelope.Unprotect(row.PrivateKey));
        return new HexSigningKey(row.OrgId, rsa, row.PublicKeyPem, row.Fingerprint,
            DateTimeOffset.Parse(row.CreatedAt, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal));
    }

    /// <summary>The public half only — what Settings shows and <c>/hex/public_key</c> serves — without touching the private key.</summary>
    public async Task<(string PublicKeyPem, string Fingerprint, string CreatedAt)?> GetPublicAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<KeyRow>(
            """
            SELECT org_id AS OrgId, '' AS PrivateKey, public_key_pem AS PublicKeyPem,
                   fingerprint AS Fingerprint, created_at AS CreatedAt
            FROM hex_signing_key
            WHERE org_id = @orgId
            """,
            new { orgId });
        return row is null ? null : (row.PublicKeyPem, row.Fingerprint, row.CreatedAt);
    }

    /// <summary>
    /// Replaces the org's key with a freshly generated one. Every resource served afterwards is
    /// signed by the new key and fails verification on a client still holding the old public key.
    /// </summary>
    public async Task<HexSigningKey> RotateAsync(string orgId, CancellationToken ct = default)
    {
        if (!CanSign)
        {
            throw new InvalidOperationException("Hex signing requires DEPENDABLY_MASTER_KEY.");
        }

        using var generated = HexRegistrySigner.GenerateSigningKey();
        await using (var conn = await _db.OpenAsync(ct))
        {
            await conn.ExecuteAsync("DELETE FROM hex_signing_key WHERE org_id = @orgId", new { orgId });
        }

        await InsertAsync(orgId, generated, ct);
        return await GetAsync(orgId, ct) ?? throw new InvalidOperationException("Hex signing key vanished after rotation.");
    }

    private async Task InsertAsync(string orgId, RSA key, CancellationToken ct)
    {
        string publicPem = HexRegistrySigner.ExportPublicKeyPem(key);
        string fingerprint = ComputeFingerprint(key);
        string privatePem = key.ExportPkcs8PrivateKeyPem();
        string protectedPem = _envelope.Protect(privatePem);
        string now = _time.GetUtcNow().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO hex_signing_key (org_id, private_key, public_key_pem, fingerprint, created_at)
            VALUES (@orgId, @privateKey, @publicKeyPem, @fingerprint, @createdAt)
            ON CONFLICT (org_id) DO NOTHING
            """,
            new { orgId, privateKey = protectedPem, publicKeyPem = publicPem, fingerprint, createdAt = now });
    }

    /// <summary>SHA-256 over the DER SubjectPublicKeyInfo, lower-case hex — the value Settings shows beside the PEM.</summary>
    public static string ComputeFingerprint(RSA key) =>
        Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

    private sealed class KeyRow
    {
        public string OrgId { get; set; } = "";
        public string PrivateKey { get; set; } = "";
        public string PublicKeyPem { get; set; } = "";
        public string Fingerprint { get; set; } = "";
        public string CreatedAt { get; set; } = "";
    }
}
