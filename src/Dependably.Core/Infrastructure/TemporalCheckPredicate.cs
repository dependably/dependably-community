namespace Dependably.Infrastructure;

/// <summary>
/// Builds the exact CHECK-constraint text every temporal TEXT column carries, for both providers,
/// from the single <see cref="UtcTimestamp.TemporalCheckRegex"/> source of truth. Used by:
/// <list type="bullet">
/// <item><description><c>Schema.sql</c> / <c>Schema.pg.sql</c> — the literal text embedded in each
/// column's <c>CREATE TABLE</c> declaration is <see cref="ForSqlite"/> / <see cref="ForPostgres"/>'s
/// output, so the schema files and the compliance test that checks them can never silently drift;</description></item>
/// <item><description><c>TemporalCheckConstraintComplianceTests</c> — asserts the schema files
/// contain this exact text for every structurally-identified temporal column.</description></item>
/// </list>
///
/// SQLite has no regex operator, so <see cref="ForSqlite"/> is a three-way <c>GLOB</c> disjunction
/// (GLOB has no alternation) — one arm per canonical precision (<see cref="UtcTimestamp.Format"/>,
/// <see cref="UtcTimestamp.MillisecondFormat"/>, <see cref="UtcTimestamp.PreciseFormat"/>). Each
/// <c>[0-9]</c> character class is the GLOB-syntax equivalent of the regex's <c>\d</c>, and GLOB
/// (like <c>LIKE</c>) always matches the whole string, so on paper the three arms accept exactly
/// what <see cref="UtcTimestamp.TemporalCheckRegex"/> accepts. <c>TemporalCheckPredicateTests</c>
/// checks this by modeling the Postgres side with .NET's <c>Regex</c> rather than a live Postgres
/// connection, which is not a perfect proxy (.NET's <c>$</c> matches before a trailing newline;
/// Postgres's <c>~</c> in the default non-newline-sensitive mode does not) — the two engines are
/// confirmed to agree, across 23 adversarial inputs including that exact trailing-newline case, by
/// the behavioral tests that run the real predicate against real SQLite and live Postgres
/// (<c>TemporalCheckConstraintSqliteTests</c> / <c>TemporalCheckConstraintPostgresTests</c>).
/// </summary>
public static class TemporalCheckPredicate
{
    private const string DigitGroup4 = "[0-9][0-9][0-9][0-9]";
    private const string DigitGroup2 = "[0-9][0-9]";
    private const string DigitGroup3 = "[0-9][0-9][0-9]";
    private const string DigitGroup6 = "[0-9][0-9][0-9][0-9][0-9][0-9]";

    private const string GlobBase =
        DigitGroup4 + "-" + DigitGroup2 + "-" + DigitGroup2 +
        "T" + DigitGroup2 + ":" + DigitGroup2 + ":" + DigitGroup2;

    /// <summary>
    /// <c>CHECK (col IS NULL OR col GLOB '&lt;seconds&gt;' OR col GLOB '&lt;milliseconds&gt;' OR
    /// col GLOB '&lt;microseconds&gt;')</c> — the SQLite form. NULL is always permitted; many of
    /// these columns are nullable, and the predicate is uniform across both nullable and NOT NULL
    /// columns rather than special-cased per column.
    /// </summary>
    public static string ForSqlite(string column) =>
        $"CHECK ({column} IS NULL OR {column} GLOB '{GlobBase}Z' " +
        $"OR {column} GLOB '{GlobBase}.{DigitGroup3}Z' " +
        $"OR {column} GLOB '{GlobBase}.{DigitGroup6}Z')";

    /// <summary>
    /// <c>CHECK (col IS NULL OR col ~ '&lt;TemporalCheckRegex&gt;')</c> — the Postgres form, using
    /// the <c>~</c> POSIX-ARE match operator (which supports <c>\d</c> shorthand classes).
    /// </summary>
    public static string ForPostgres(string column) =>
        $"CHECK ({column} IS NULL OR {column} ~ '{UtcTimestamp.TemporalCheckRegex}')";
}
