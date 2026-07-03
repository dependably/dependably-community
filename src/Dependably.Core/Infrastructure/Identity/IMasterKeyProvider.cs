namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Supplies the operator-managed key-encryption key (KEK) used to protect operator secrets at
/// rest. Synchronous by design: the env-file provider does no post-construction I/O, and the
/// Data Protection XML encryptor contract is also synchronous.
/// </summary>
public interface IMasterKeyProvider
{
    /// <summary>
    /// True when an operator master key is present and valid. Callers must check this before
    /// calling <see cref="GetMasterKey"/> when operating in an optional-encryption mode.
    /// </summary>
    bool IsConfigured { get; }

    /// <summary>
    /// Returns the 32-byte key-encryption key (KEK). Throws
    /// <see cref="InvalidOperationException"/> when <see cref="IsConfigured"/> is false.
    /// </summary>
    byte[] GetMasterKey();

    /// <summary>
    /// Identifies the key source for diagnostics and logging (e.g. "env-file"). Never
    /// includes the key material itself.
    /// </summary>
    string ProviderName { get; }
}
