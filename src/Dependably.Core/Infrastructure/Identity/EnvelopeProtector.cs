namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Value-level protector that wraps the operator master key with the existing AES-256-GCM
/// primitive supplied by <see cref="MfaSecretProtector"/>. Encrypted values carry the
/// <c>enc:v1:</c> prefix, which serves as a discriminator between encrypted and legacy-plaintext
/// stored values and as a version anchor for future key rotation.
///
/// When no master key is configured the protector operates in detection mode:
/// <see cref="Protect"/> throws, and <see cref="Unprotect"/> passes through non-prefixed legacy
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
    /// <see cref="IsEncrypted"/> and <see cref="Unprotect"/>.
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
    /// Returns true when <paramref name="stored"/> carries the <see cref="EncryptedPrefix"/>
    /// marker. This is a prefix-only check and requires no key material.
    /// </summary>
    public bool IsEncrypted(string stored) =>
        stored.StartsWith(EncryptedPrefix, StringComparison.Ordinal);

    /// <inheritdoc/>
    public void Dispose() => _inner?.Dispose();
}
