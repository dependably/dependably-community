using Microsoft.AspNetCore.Identity;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// BCrypt-backed implementation of <see cref="IPasswordHasher{TUser}"/> for use with ASP.NET
/// Core Identity. Compatible with hashes produced by the rest of the application: the BCrypt
/// work factor (12) and the hash format match the existing <c>BCrypt.Net.BCrypt.HashPassword</c>
/// calls in <c>FirstBootService</c> and <c>UserService</c>, so Identity can verify any
/// pre-existing stored hash without a migration pass.
/// </summary>
internal sealed class BcryptPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    /// <summary>Returns a BCrypt hash of <paramref name="password"/> at work factor 12.</summary>
    public string HashPassword(TUser user, string password) =>
        BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

    /// <summary>
    /// Verifies <paramref name="providedPassword"/> against <paramref name="hashedPassword"/>.
    /// Returns <see cref="PasswordVerificationResult.Success"/> on a match, or
    /// <see cref="PasswordVerificationResult.Failed"/> on mismatch or when the stored hash
    /// is null or empty. Never returns <see cref="PasswordVerificationResult.SuccessRehashNeeded"/>
    /// — BCrypt embeds the work factor in the hash, so the caller always rehashes if needed
    /// outside this method.
    /// </summary>
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword))
        {
            return PasswordVerificationResult.Failed;
        }

        bool valid = BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword);
        return valid ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
    }
}
