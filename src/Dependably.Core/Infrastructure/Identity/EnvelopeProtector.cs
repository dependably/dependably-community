namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Value-level protector that wraps the operator master key with the existing AES-256-GCM
/// primitive supplied by <see cref="MfaSecretProtector"/>. Encrypted values carry the
/// <c>enc:v1:</c> prefix, which serves as a discriminator between encrypted and legacy-plaintext
/// stored values and as a version anchor for future key rotation.
///
/// When no master key is configured the protector operates in detection mode:
/// <see cref="Protect"/> throws, and <see cref="Unprotect(string)"/> passes through non-prefixed legacy
/// values unchanged while failing closed on any prefixed value (a present-but-lost-key
/// scenario).
///
/// A single <see cref="MfaSecretProtector"/> instance is held for the lifetime of this
/// singleton and disposed alongside it.
/// </summary>
public sealed class EnvelopeProtector : IDisposable
{
    /// <summary>
    /// Discriminator prefix written by <see cref="Protect"/> and detected by
    /// <see cref="IsEncrypted"/> and <see cref="Unprotect(string)"/>.
    /// </summary>
    internal const string EncryptedPrefix = "enc:v1:";

    private readonly IMasterKeyProvider _provider;
    private readonly MfaSecretProtector? _inner;

    public EnvelopeProtector(IMasterKeyProvider provider)
    {
        _provider = provider;
        if (provider.IsConfigured)
        {
            _inner = new MfaSecretProtector(provider.GetMasterKey());
        }
    }

    /// <summary>
    /// True when a master key is present and <see cref="Protect"/> will succeed.
    /// </summary>
    public bool IsConfigured => _provider.IsConfigured;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and returns a value prefixed with
    /// <see cref="EncryptedPrefix"/>. Throws <see cref="InvalidOperationException"/> when no
    /// master key is configured.
    /// </summary>
    public string Protect(string plaintext) =>
        _inner is not null
            ? EncryptedPrefix + _inner.Protect(plaintext)
            : throw new InvalidOperationException(
                "DEPENDABLY_MASTER_KEY is not configured; cannot encrypt a value.");

    /// <summary>
    /// Decrypts a value produced by <see cref="Protect"/> and returns the original plaintext.
    /// Non-prefixed values are returned unchanged (legacy-plaintext pass-through). Throws
    /// <see cref="InvalidOperationException"/> when the value is prefixed but no master key is
    /// configured (lost-key fail-closed case).
    /// </summary>
    public string Unprotect(string stored) =>
        !IsEncrypted(stored)
            ? stored
            : _inner is not null
                ? _inner.Unprotect(stored[EncryptedPrefix.Length..])
                : throw new InvalidOperationException(
                    "The stored value is encrypted at rest but DEPENDABLY_MASTER_KEY is not configured.");

    /// <summary>
    /// Decrypts <paramref name="stored"/> for a caller that needs the one value and fails closed
    /// without it. A value that cannot be decrypted throws
    /// <see cref="ProtectedSecretUnreadableException"/> naming <paramref name="row"/> and the
    /// reason, so whatever logs the failure points at the record to repair.
    /// </summary>
    public string Unprotect(string stored, ProtectedSecretRow row) =>
        TryUnprotect(stored, out string? plaintext, out string? failureReason)
            ? plaintext
            : throw new ProtectedSecretUnreadableException(row, failureReason);

    /// <summary>
    /// Decrypts <paramref name="stored"/> like <see cref="Unprotect(string)"/>, but reports a value
    /// that cannot be decrypted instead of throwing. On failure <paramref name="failureReason"/> is
    /// one of <see cref="ProtectedSecretFailureReasons"/>. A caller reading a list uses this to
    /// drop only the record that fails.
    /// </summary>
    public bool TryUnprotect(
        string stored,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? plaintext,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(false)] out string? failureReason)
    {
        if (!IsEncrypted(stored))
        {
            plaintext = stored;
            failureReason = null;
            return true;
        }

        if (_inner is null)
        {
            plaintext = null;
            failureReason = ProtectedSecretFailureReasons.MasterKeyMissing;
            return false;
        }

        try
        {
            plaintext = _inner.Unprotect(stored[EncryptedPrefix.Length..]);
            failureReason = null;
            return true;
        }
        catch (MfaSecretProtectionException)
        {
            plaintext = null;
            failureReason = ProtectedSecretFailureReasons.AuthenticationFailed;
            return false;
        }
    }

    /// <summary>
    /// Returns true when <paramref name="stored"/> carries the <see cref="EncryptedPrefix"/>
    /// marker. This is a prefix-only check and requires no key material.
    /// </summary>
    public static bool IsEncrypted(string stored) =>
        stored.StartsWith(EncryptedPrefix, StringComparison.Ordinal);

    /// <inheritdoc/>
    public void Dispose() => _inner?.Dispose();
}
