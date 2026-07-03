namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Thrown by <see cref="MfaSecretProtector.Unprotect"/> when the ciphertext fails AES-GCM
/// authentication (tampered payload), has an unrecognised format, or was encrypted with a
/// different key. The caller treats this as an unrecoverable credential error and must not
/// leak the original ciphertext or the exception message to untrusted callers.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization (SerializationInfo/StreamingContext) is obsolete in .NET 8+ and disabled by default; this exception is never serialized across processes.")]
public sealed class MfaSecretProtectionException : Exception
{
    internal MfaSecretProtectionException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}
