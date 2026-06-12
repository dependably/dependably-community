using System.Security.Cryptography;

namespace Dependably.Security;

/// <summary>
/// Generates cryptographically secure random tokens.
/// System.Random and Guid.NewGuid() are never used for security-sensitive values.
/// </summary>
public static class TokenGenerator
{
    /// <summary>
    /// Generates a 256-bit (32-byte) URL-safe base64 token.
    /// Suitable for registry API tokens, invite tokens, and CI/CD tokens.
    /// </summary>
    public static string Generate()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        // URL-safe base64: replace + with - and / with _
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
