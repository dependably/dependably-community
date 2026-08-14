namespace Dependably.Infrastructure;

/// <summary>
/// Canonical form of an account email address, applied at every write that stores one
/// (<c>users.email</c>, <c>system_admins.email</c>, <c>invites.email</c>,
/// <c>email_change_tokens.new_email</c>).
///
/// <para>Every account lookup in the codebase resolves case-insensitively —
/// <c>WHERE lower(email) = lower(@email)</c> — so storage has to agree. Without a canonical write
/// form, <c>UNIQUE (tenant_id, email)</c> compares bytes while every reader compares folded case:
/// <c>Owner@corp.com</c> and <c>owner@corp.com</c> then coexist as two accounts that both satisfy
/// every lookup, and which one authenticates for that address is whichever row the query engine
/// happens to return first. Folding on write makes the existing uniqueness constraint mean what
/// the readers already assume.</para>
///
/// <para>Only the case is folded, and only invariantly — no Unicode normalization, no
/// plus-address or dot stripping. Folding matches SQL <c>lower()</c>, which is what the lookups
/// use; going further would collapse addresses that genuinely route to different mailboxes.
/// The local part is case-sensitive per RFC 5321 and case-insensitive in practice at essentially
/// every provider, and treating it as case-insensitive is what makes an account resolvable by the
/// address its owner types.</para>
/// </summary>
public static class EmailNormalizer
{
    /// <summary>
    /// Trims surrounding whitespace and lowercases invariantly. A null input returns null so a
    /// caller storing an optional address does not have to special-case it.
    /// </summary>
    [return: System.Diagnostics.CodeAnalysis.NotNullIfNotNull(nameof(email))]
    public static string? Normalize(string? email) => email?.Trim().ToLowerInvariant();
}
