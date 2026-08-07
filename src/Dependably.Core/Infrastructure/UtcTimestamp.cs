using System.Globalization;

namespace Dependably.Infrastructure;

/// <summary>
/// The single place the canonical timestamp wire format is defined and applied.
///
/// Every timestamp column in <c>Schema.sql</c> / <c>Schema.pg.sql</c> is TEXT holding an
/// ISO-8601 instant in UTC — <c>2026-07-25T12:00:00Z</c> — regardless of the timezone of
/// the frontend, the backend host, or the database server. Those columns are compared
/// lexicographically (<c>WHERE starts_at &lt;= @now</c>), so a value in any other shape or
/// offset does not merely read oddly: it sorts wrong and silently breaks the comparison.
///
/// Formatting through <see cref="ToUtcIso(DateTimeOffset)"/> rather than an inline format
/// string is what keeps that true. In a .NET custom format string the trailing <c>Z</c> is
/// a literal, not a conversion: formatting a <c>+02:00</c> value against that pattern
/// directly emits that value's wall-clock time and labels it <c>Z</c>, leaving a
/// timestamp wrong by the offset that nothing downstream can detect. These helpers convert
/// to UTC first, so a non-UTC instant — parsed from upstream registry metadata, an X.509
/// certificate, a SAML assertion, or a request body — normalizes instead of corrupting.
/// </summary>
public static class UtcTimestamp
{
    /// <summary>
    /// The single permissive predicate every temporal TEXT column's CHECK constraint enforces
    /// in <c>Schema.sql</c> / <c>Schema.pg.sql</c> (as a GLOB tri-way OR on SQLite, since GLOB has
    /// no alternation) and that <see cref="SchemaInitializer"/>'s Postgres retrofit validates
    /// against on existing databases. Accepts exactly the three canonical shapes above —
    /// <see cref="Format"/>, <see cref="MillisecondFormat"/>, <see cref="PreciseFormat"/> — and
    /// nothing else. Deliberately one predicate for every column rather than a per-column exact
    /// precision: a single wrong entry in a hand-maintained 130-column precision map would reject
    /// legitimate production writes, where a too-permissive shared predicate merely fails to catch
    /// a wrong precision on one column — a far smaller blast radius.
    /// </summary>
    public const string TemporalCheckRegex = @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$";

    /// <summary>
    /// The canonical format. Second precision: it is what every existing row already uses,
    /// and sub-second digits would break the lexicographic ordering against those rows.
    /// </summary>
    public const string Format = "yyyy-MM-ddTHH:mm:ssZ";

    /// <summary>
    /// Millisecond precision, for the columns whose rows need a deterministic order within a
    /// single wall-clock second (audit and activity events). Distinct from
    /// <see cref="Format"/> so the extra digits stay confined to those columns: mixing the two
    /// precisions inside one column would break its lexicographic ordering, because <c>'.'</c>
    /// sorts before <c>'Z'</c>.
    /// </summary>
    public const string MillisecondFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

    /// <summary>Formats an instant as canonical UTC ISO-8601, converting from any offset.</summary>
    public static string ToUtcIso(this DateTimeOffset instant) =>
        instant.ToUniversalTime().ToString(Format, CultureInfo.InvariantCulture);

    /// <summary>
    /// Formats a <see cref="DateTime"/> as canonical UTC ISO-8601. A <see cref="DateTimeKind.Local"/>
    /// or <see cref="DateTimeKind.Unspecified"/> value is interpreted per
    /// <see cref="DateTime.ToUniversalTime"/> — prefer <see cref="DateTimeOffset"/> at call sites
    /// that carry a real offset.
    /// </summary>
    public static string ToUtcIso(this DateTime instant) =>
        instant.ToUniversalTime().ToString(Format, CultureInfo.InvariantCulture);

    /// <summary>
    /// Formats an instant at millisecond precision, converting from any offset. Use only for
    /// the columns documented on <see cref="MillisecondFormat"/>.
    /// </summary>
    public static string ToUtcIsoMillis(this DateTimeOffset instant) =>
        instant.ToUniversalTime().ToString(MillisecondFormat, CultureInfo.InvariantCulture);

    /// <summary>
    /// Microsecond precision, for columns holding an instant that was declared by an upstream
    /// registry rather than read from our own clock. <c>published_at</c> is the case: PyPI's
    /// <c>upload_time_iso_8601</c> carries sub-second digits and is re-served verbatim to
    /// clients, so truncating to seconds would change what the registry reports. Always emits
    /// all six digits, so values in such a column share one shape and still collate.
    /// </summary>
    public const string PreciseFormat = "yyyy-MM-ddTHH:mm:ss.ffffffZ";

    /// <summary>Formats an optional instant, returning <see langword="null"/> for <see langword="null"/>.</summary>
    public static string? ToUtcIsoOrNull(this DateTimeOffset? instant) =>
        instant?.ToUtcIso();

    /// <summary>
    /// Formats an instant at microsecond precision, converting from any offset. Use only for
    /// the columns documented on <see cref="PreciseFormat"/>.
    /// </summary>
    public static string ToUtcIsoPrecise(this DateTimeOffset instant) =>
        instant.ToUniversalTime().ToString(PreciseFormat, CultureInfo.InvariantCulture);

    /// <summary>Microsecond-precision form of <see cref="ToUtcIsoOrNull(DateTimeOffset?)"/>.</summary>
    public static string? ToUtcIsoPreciseOrNull(this DateTimeOffset? instant) =>
        instant?.ToUtcIsoPrecise();

    /// <summary>Reads the current instant from <paramref name="time"/> in canonical form.</summary>
    public static string Now(TimeProvider time) => time.GetUtcNow().ToUtcIso();

    /// <summary>
    /// Parses a client-supplied instant and re-emits it in canonical UTC form. Used at the
    /// edge — a controller — so an offset (or a missing offset) supplied by a caller never
    /// reaches a repository. A value with no offset is read as UTC rather than as server-local
    /// time, so the stored instant does not depend on the host's timezone.
    /// </summary>
    public static bool TryNormalize(string? raw, out string normalized)
    {
        if (DateTimeOffset.TryParse(
                raw,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind | DateTimeStyles.AssumeUniversal,
                out var parsed))
        {
            normalized = parsed.ToUtcIso();
            return true;
        }

        normalized = string.Empty;
        return false;
    }
}
