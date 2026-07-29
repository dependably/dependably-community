namespace Dependably.Infrastructure;

/// <summary>
/// Single source of truth for the timezone identifiers a user or org may select. Identifiers
/// are IANA zone names (<c>America/Toronto</c>, <c>Europe/Paris</c>); the frontend offers them
/// from <c>Intl.supportedValuesOf('timeZone')</c>, and this validates whatever it sends.
///
/// The set is deliberately not enumerated here the way <see cref="LanguageCodes.Supported"/> is
/// — there are several hundred zones and they change as the tz database is updated, so the
/// authority is the runtime's own database rather than a list that would silently drift.
///
/// A timezone is a *display* preference only. Instants are stored in UTC (see
/// <see cref="UtcTimestamp"/>) regardless of any user's or org's zone; this decides how a
/// stored instant is rendered, never what is written.
/// </summary>
public static class TimeZoneCodes
{
    /// <summary>The instance-level fallback when neither the user nor the org has chosen one.</summary>
    public const string Default = "UTC";

    /// <summary>
    /// True when the runtime's tz database recognises the identifier. Rejects the empty/whitespace
    /// case explicitly: <see cref="TimeZoneInfo.TryFindSystemTimeZoneById"/> treats some inputs
    /// leniently, and an unrecognised zone must fail closed rather than be stored and then fall
    /// back silently on every render.
    /// </summary>
    public static bool IsSupported(string? id) =>
        !string.IsNullOrWhiteSpace(id) && TimeZoneInfo.TryFindSystemTimeZoneById(id, out _);

    /// <summary>
    /// Resolves the effective display zone: the per-user override when set and recognised, else
    /// the org default when set and recognised, else <see cref="Default"/>. Mirrors
    /// <see cref="LanguageCodes.ResolveEffective"/> — a per-user NULL means "inherit", so a later
    /// change to the org default reaches every user who never chose one.
    /// </summary>
    public static string ResolveEffective(string? userTimeZone, string? fallbackTimeZone = null) =>
        !string.IsNullOrEmpty(userTimeZone) && IsSupported(userTimeZone) ? userTimeZone
        : !string.IsNullOrEmpty(fallbackTimeZone) && IsSupported(fallbackTimeZone) ? fallbackTimeZone
        : Default;
}
