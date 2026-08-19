using System.Security.Cryptography;

namespace Dependably.Security;

/// <summary>
/// Generates cryptographically secure random tokens.
/// System.Random and Guid.NewGuid() are never used for security-sensitive values.
/// </summary>
public static class TokenGenerator
{
    // Alphanumeric only — deliberately NOT base64url. The '-' and '_'
    // substitutions made roughly three in four generated secrets impossible to
    // store as masked GitLab CI/CD variables (masking accepts only the standard
    // Base64 alphabet plus @ : . ~), and a rejected save silently keeps the
    // variable's previous value, stranding token rotations. The
    // alphabet also survives URLs, HTTP Basic auth, .npmrc, and shell quoting
    // without escaping. 44 characters over 62 symbols carry ~262 bits of
    // entropy, preserving the previous 256-bit floor.
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const int TokenLength = 44;

    /// <summary>
    /// Generates an alphanumeric token carrying at least 256 bits of entropy.
    /// Suitable for registry API tokens, invite tokens, and CI/CD tokens.
    /// Tokens are stored only as SHA-256 hashes and never decoded, so the
    /// encoding change from base64url is invisible to existing tokens.
    /// </summary>
    public static string Generate()
    {
        return RandomNumberGenerator.GetString(Alphabet, TokenLength);
    }
}
