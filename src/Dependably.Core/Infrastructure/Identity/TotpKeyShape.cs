using System.Text.RegularExpressions;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Names why a stored TOTP key failed to decrypt. TOTP keys carry no envelope prefix: the user
/// stores only ever write <c>base64(nonce || tag || ciphertext)</c> under the instance MFA key,
/// so every stored value is ciphertext and nothing is ever accepted as plaintext. A value that
/// does not decrypt and has the shape of a bare Base32 authenticator key (upper-case letters
/// and the digits 2-7) was not written by the application: it is reported as
/// <see cref="ProtectedSecretFailureReasons.UnexpectedPlaintext"/>, because a known key planted
/// in the column would otherwise pass MFA. Anything else is
/// <see cref="ProtectedSecretFailureReasons.AuthenticationFailed"/>.
///
/// <para>Ciphertext is the base64 of at least 28 random bytes, so the chance that a genuine
/// ciphertext matches the Base32 shape is below 2^-40; the shape only chooses the reason, and
/// both reasons fail closed.</para>
/// </summary>
internal static partial class TotpKeyShape
{
    /// <summary>The failure reason for a stored TOTP value that does not decrypt.</summary>
    public static string FailureReason(string stored) =>
        Base32KeyRegex().IsMatch(stored)
            ? ProtectedSecretFailureReasons.UnexpectedPlaintext
            : ProtectedSecretFailureReasons.AuthenticationFailed;

    [GeneratedRegex(@"\A[A-Z2-7]+=*\z")]
    private static partial Regex Base32KeyRegex();
}
