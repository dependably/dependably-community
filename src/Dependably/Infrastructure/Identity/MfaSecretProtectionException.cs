namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Thrown by <see cref="MfaSecretProtector.Unprotect"/> when the ciphertext fails AES-GCM
/// authentication (tampered payload), has an unrecognised format, or was encrypted with a
/// different key. The caller treats this as an unrecoverable credential error and must not
/// leak the original ciphertext or the exception message to untrusted callers.
/// </summary>
public sealed class MfaSecretProtectionException : Exception
{
    internal MfaSecretProtectionException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}
