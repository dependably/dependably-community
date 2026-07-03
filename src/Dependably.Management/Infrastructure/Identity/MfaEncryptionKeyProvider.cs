using System.Security.Cryptography;
using Dapper;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Resolves the 32-byte AES-GCM key used by <see cref="MfaSecretProtector"/> from
/// <c>instance_settings.mfa_encryption_key</c>. Generates and persists a new random key
/// when the row is absent, which handles instances upgraded from releases that pre-date
/// the MFA feature without requiring a separate manual setup step.
///
/// Resolution is lazy: the key is read from the DB on first use, then cached for the
/// lifetime of the singleton. The constructor performs no I/O.
///
/// When an <see cref="EnvelopeProtector"/> is configured, the stored value is wrapped with
/// the instance master key so the raw base64 MFA key is never at rest in plaintext.
/// Unprotect is called on every read and is safe for legacy plaintext rows (pass-through).
/// </summary>
internal sealed class MfaEncryptionKeyProvider
{
    private readonly IMetadataStore _db;
    private readonly ILogger<MfaEncryptionKeyProvider> _logger;
    private readonly EnvelopeProtector _envelope;
    private byte[]? _cachedKey;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public MfaEncryptionKeyProvider(IMetadataStore db, ILogger<MfaEncryptionKeyProvider> logger, EnvelopeProtector envelope)
    {
        _db = db;
        _logger = logger;
        _envelope = envelope;
    }

    /// <summary>
    /// Returns the 32-byte MFA encryption key, initializing and persisting it on first call
    /// when absent from <c>instance_settings</c>.
    /// </summary>
    public async Task<byte[]> GetKeyAsync(CancellationToken ct = default)
    {
        if (_cachedKey is not null)
        {
            return _cachedKey;
        }

        await _lock.WaitAsync(ct);
        try
        {
            if (_cachedKey is not null)
            {
                return _cachedKey;
            }

            _cachedKey = await ResolveOrCreateKeyAsync(ct);
            return _cachedKey;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<byte[]> ResolveOrCreateKeyAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: instance-global secret, not tenant-scoped.
        string? existing = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'mfa_encryption_key'");

        if (existing is not null)
        {
            string decoded = _envelope.Unprotect(existing);
            return Convert.FromBase64String(decoded);
        }

        // Generate a fresh key and persist it idempotently. ON CONFLICT DO NOTHING ensures
        // that a concurrent first-boot (two replicas racing) does not produce two different
        // keys; the re-read after the INSERT returns whichever value won.
        string newKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        string toStore = _envelope.IsConfigured ? _envelope.Protect(newKeyBase64) : newKeyBase64;
        // xtenant: instance-global secret, not tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO instance_settings (key, value) VALUES ('mfa_encryption_key', @value)
            ON CONFLICT(key) DO NOTHING
            """,
            new { value = toStore });

        // xtenant: instance-global secret, not tenant-scoped.
        string? committedRaw = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'mfa_encryption_key'") ?? throw new InvalidOperationException("Failed to persist or read mfa_encryption_key from instance_settings.");
        _logger.LogInformation("MFA encryption key initialized for this instance.");
        return Convert.FromBase64String(_envelope.Unprotect(committedRaw));
    }
}
