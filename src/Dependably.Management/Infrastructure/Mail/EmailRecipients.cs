using System.Net.Mail;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Parses and validates the comma-separated recipient list stored in
/// <c>alert_settings.email_recipients</c>. Shared by the org email-settings PUT (validation) and
/// <c>AlertSettingsRepository.GetDecryptedEmailDeliveryConfigAsync</c> (parsing the stored value
/// back into a list for delivery).
/// </summary>
public static class EmailRecipients
{
    /// <summary>Maximum number of recipients a single org's alert email channel may target.</summary>
    public const int MaxRecipients = 20;

    /// <summary>
    /// Splits a comma-separated recipient string into trimmed, non-empty entries. Returns an
    /// empty array for a null/blank input — callers treat an empty result as "nothing configured".
    /// </summary>
    public static string[] Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Validates a comma-separated recipient string: every entry must parse as a valid email
    /// address (<see cref="MailAddress.TryCreate(string, out MailAddress?)"/> rejects embedded
    /// CR/LF, killing header-injection attempts), and the list is capped at
    /// <see cref="MaxRecipients"/>. A single invalid entry fails the whole list rather than
    /// silently dropping it. Returns the parsed, trimmed addresses and a null resource key on
    /// success, or a null array and the SharedResource key describing the failure.
    /// </summary>
    public static (string[]? Recipients, string? ResourceKey) Validate(string? raw)
    {
        string[] parts = Split(raw);
        if (parts.Length == 0)
        {
            return ([], null);
        }

        if (parts.Length > MaxRecipients)
        {
            return (null, "error.email.tooManyRecipients");
        }

        foreach (string part in parts)
        {
            if (!MailAddress.TryCreate(part, out _))
            {
                return (null, "error.email.invalidRecipient");
            }
        }

        return (parts, null);
    }
}
