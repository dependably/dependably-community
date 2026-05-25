using System.Globalization;
using System.Text;

namespace Dependably.Security;

/// <summary>
/// Gate for user-supplied passwords at set/reset time (not login). Follows
/// NIST SP 800-63B + OWASP ASVS v4.0.3 §V2.1: length floor, byte ceiling,
/// no composition rules, entropy gate via zxcvbn, context-dictionary block.
/// Breach-corpus check is deferred — see GitLab issue referenced in
/// docs/encryption.md gap §6.
/// </summary>
public sealed class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxBytesUtf8 = 72;  // BCrypt.Net-Next silently truncates above this
    public const int MinZxcvbnScore = 3;

    private static readonly string[] AlwaysBlockedSubstrings =
    {
        "dependably",
    };

    public PasswordPolicyResult Evaluate(string? password, PasswordContext ctx)
    {
        if (string.IsNullOrEmpty(password))
            return new PasswordPolicyResult(PasswordPolicyVerdict.TooShort, MinLength, null);

        if (password.Length < MinLength)
            return new PasswordPolicyResult(PasswordPolicyVerdict.TooShort, MinLength, null);

        var byteLength = Encoding.UTF8.GetByteCount(password);
        if (byteLength > MaxBytesUtf8)
            return new PasswordPolicyResult(PasswordPolicyVerdict.TooLong, MaxBytesUtf8, null);

        var matched = FindContextMatch(password, ctx);
        if (matched is not null)
            return new PasswordPolicyResult(PasswordPolicyVerdict.ContainsContext, 0, matched);

        var userInputs = BuildUserInputs(ctx);
        var zxcvbn = Zxcvbn.Core.EvaluatePassword(password, userInputs);
        if (zxcvbn.Score < MinZxcvbnScore)
            return new PasswordPolicyResult(
                PasswordPolicyVerdict.LowEntropy,
                zxcvbn.Score,
                zxcvbn.Feedback?.Warning);

        return PasswordPolicyResult.Ok;
    }

    private static string? FindContextMatch(string password, PasswordContext ctx)
    {
        // Normalize by lowercasing and stripping non-alphanumeric characters on both
        // sides so "alice.dev" (an email local-part) matches "AliceDevPassphrase",
        // and "john_doe" matches "JohnDoe2026". NIST/ASVS calls this matching
        // against "derivatives" of the username, not just the verbatim string.
        var normalizedPassword = Normalize(password);

        var blockedMatch = AlwaysBlockedSubstrings.FirstOrDefault(normalizedPassword.Contains);
        if (blockedMatch is not null)
            return blockedMatch;

        if (!string.IsNullOrWhiteSpace(ctx.Email))
        {
            var localPart = ExtractEmailLocalPart(ctx.Email);
            if (localPart is not null && localPart.Length >= 3 &&
                normalizedPassword.Contains(Normalize(localPart)))
                return localPart;
        }

        if (!string.IsNullOrWhiteSpace(ctx.TenantSlug) &&
            ctx.TenantSlug.Length >= 3 &&
            normalizedPassword.Contains(Normalize(ctx.TenantSlug)))
            return ctx.TenantSlug;

        return null;
    }

    private static string Normalize(string value)
    {
        var nfc = value.Normalize(NormalizationForm.FormC).ToLowerInvariant();
        return new string(nfc.Where(char.IsLetterOrDigit).ToArray());
    }

    private static string? ExtractEmailLocalPart(string email)
    {
        var at = email.IndexOf('@');
        return at <= 0 ? null : email[..at];
    }

    private static List<string> BuildUserInputs(PasswordContext ctx)
    {
        var inputs = new List<string>(AlwaysBlockedSubstrings);
        if (!string.IsNullOrWhiteSpace(ctx.Email))
        {
            inputs.Add(ctx.Email);
            var local = ExtractEmailLocalPart(ctx.Email);
            if (local is not null) inputs.Add(local);
        }
        if (!string.IsNullOrWhiteSpace(ctx.TenantSlug))
            inputs.Add(ctx.TenantSlug);
        return inputs;
    }
}

public readonly record struct PasswordContext(string? Email = null, string? TenantSlug = null);

public enum PasswordPolicyVerdict
{
    Ok,
    TooShort,
    TooLong,
    LowEntropy,
    ContainsContext,
}

/// <summary>
/// Result of evaluating a candidate password. <see cref="DiagnosticValue"/> carries
/// the verdict-specific number (minimum length, max bytes, achieved zxcvbn score).
/// <see cref="Detail"/> carries a human-readable hint (matched context term, or
/// the zxcvbn warning string when available) — safe to surface to the user.
/// </summary>
public readonly record struct PasswordPolicyResult(
    PasswordPolicyVerdict Verdict,
    int DiagnosticValue,
    string? Detail)
{
    public static readonly PasswordPolicyResult Ok = new(PasswordPolicyVerdict.Ok, 0, null);

    public bool IsOk => Verdict == PasswordPolicyVerdict.Ok;

    /// <summary>Human-readable English reason — controllers surface this in the
    /// problem-detail <c>detail</c> field. Localization happens at the response
    /// layer (or in the SPA via the i18n key embedded in the verdict).</summary>
    public string ToReason() => Verdict switch
    {
        PasswordPolicyVerdict.Ok => "ok",
        PasswordPolicyVerdict.TooShort => $"Password must be at least {DiagnosticValue} characters.",
        PasswordPolicyVerdict.TooLong => $"Password must be at most {DiagnosticValue} bytes (UTF-8). Very long passphrases above this limit are silently truncated by the hashing algorithm.",
        PasswordPolicyVerdict.LowEntropy => string.IsNullOrEmpty(Detail)
            ? $"Password is too easy to guess (score {DiagnosticValue}/{PasswordPolicy.MinZxcvbnScore - 1}). Try a longer or less predictable passphrase."
            : $"Password is too easy to guess: {Detail}",
        PasswordPolicyVerdict.ContainsContext => $"Password must not contain \"{Detail}\".",
        _ => "Password rejected.",
    };
}
