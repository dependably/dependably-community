namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Encrypts and decrypts MFA authenticator keys at rest. Protects TOTP secrets stored in
/// <c>users.mfa_authenticator_key</c> and <c>system_admins.mfa_authenticator_key</c> using a
/// per-instance AES-GCM key held in <c>instance_settings.mfa_encryption_key</c>.
/// </summary>
internal interface IMfaSecretProtector
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using AES-GCM. Each call generates a fresh
    /// 12-byte random nonce so repeated encryptions of the same value produce distinct
    /// ciphertexts, preventing frequency analysis across user rows.
    /// Returns base64(nonce || tag || ciphertext).
    /// </summary>
    string Protect(string plaintext);

    /// <summary>
    /// Decrypts a value produced by <see cref="Protect"/>. Throws
    /// <see cref="MfaSecretProtectionException"/> when the input is tampered, has an
    /// unrecognised format, or was encrypted with a different key.
    /// </summary>
    string Unprotect(string ciphertext);
}
