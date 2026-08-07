using System.Text.RegularExpressions;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins the canonical-timestamp CHECK predicate (<see cref="UtcTimestamp.TemporalCheckRegex"/> /
/// <see cref="TemporalCheckPredicate"/>) against every shape actually observed in this codebase:
/// the three canonical <see cref="UtcTimestamp"/> formats must be accepted, and the legacy
/// dead-handler / <c>ToString("o")</c> / empty / garbage / bare-integer shapes must be rejected.
///
/// Exercises the .NET <see cref="Regex"/> engine directly against
/// <see cref="UtcTimestamp.TemporalCheckRegex"/> (the Postgres <c>~</c> form) and a hand-rolled GLOB
/// interpreter against <see cref="TemporalCheckPredicate.ForSqlite"/>'s three arms, so this test
/// fails without either predicate rather than only failing once the schema files ship it.
/// </summary>
public sealed partial class TemporalCheckPredicateTests
{
    [GeneratedRegex(UtcTimestamp.TemporalCheckRegex)]
    private static partial Regex CompiledRegex();

    [GeneratedRegex("'([^']*)'")]
    private static partial Regex GlobLiteralRegex();

    public static TheoryData<string> AcceptedShapes() => new()
    {
        "2026-03-04T05:06:07Z",       // UtcTimestamp.Format (second precision)
        "2026-03-04T05:06:07.123Z",   // UtcTimestamp.MillisecondFormat
        "2026-03-04T05:06:07.123456Z", // UtcTimestamp.PreciseFormat
    };

    public static TheoryData<string> RejectedShapes() => new()
    {
        "2026-03-04 05:06:07+02:00",             // the dead-handler shape (space + offset)
        "2026-03-04T05:06:07.0000000+00:00",     // the ToString("o") shape
        "",
        "not a date",
        "20260304050607",                        // bare integer-looking text
        "2026-03-04T05:06:07.12Z",               // wrong fractional digit count (2)
        "2026-03-04T05:06:07",                   // missing trailing Z
    };

    [Theory]
    [MemberData(nameof(AcceptedShapes))]
    public void Regex_AcceptsEveryCanonicalShape(string value) =>
        Assert.Matches(CompiledRegex(), value);

    [Theory]
    [MemberData(nameof(RejectedShapes))]
    public void Regex_RejectsEveryObservedBadShape(string value) =>
        Assert.False(CompiledRegex().IsMatch(value), $"expected `{value}` to be rejected");

    [Theory]
    [MemberData(nameof(AcceptedShapes))]
    public void SqliteGlobForm_AcceptsEveryCanonicalShape(string value) =>
        Assert.True(MatchesAnySqliteArm(value), $"expected `{value}` to match one of the three GLOB arms");

    [Theory]
    [MemberData(nameof(RejectedShapes))]
    public void SqliteGlobForm_RejectsEveryObservedBadShape(string value) =>
        Assert.False(MatchesAnySqliteArm(value), $"expected `{value}` to be rejected by all three GLOB arms");

    // The three GLOB literals TemporalCheckPredicate.ForSqlite embeds for a column named "col",
    // converted to .NET regex equivalents. GLOB is always fully anchored (matches the whole
    // string, like LIKE), and its only non-literal construct here is the [0-9] character class
    // — which is already valid regex syntax — so every other character is escaped literally.
    private static bool MatchesAnySqliteArm(string value)
    {
        string check = TemporalCheckPredicate.ForSqlite("col");
        var globLiterals = GlobLiteralRegex().Matches(check).Select(m => m.Groups[1].Value);
        return globLiterals.Any(glob => Regex.IsMatch(value, GlobToAnchoredRegex(glob)));
    }

    private static string GlobToAnchoredRegex(string glob)
    {
        var sb = new System.Text.StringBuilder("^");
        int i = 0;
        while (i < glob.Length)
        {
            if (glob[i] == '[' && i + 5 <= glob.Length && string.CompareOrdinal(glob, i, "[0-9]", 0, 5) == 0)
            {
                sb.Append("[0-9]");
                i += 5;
            }
            else
            {
                sb.Append(Regex.Escape(glob[i].ToString()));
                i++;
            }
        }
        sb.Append('$');
        return sb.ToString();
    }

    [Fact]
    public void ForSqlite_PermitsNull()
    {
        string check = TemporalCheckPredicate.ForSqlite("created_at");
        Assert.Contains("created_at IS NULL OR", check, StringComparison.Ordinal);
    }

    [Fact]
    public void ForPostgres_PermitsNull()
    {
        string check = TemporalCheckPredicate.ForPostgres("created_at");
        Assert.Contains("created_at IS NULL OR", check, StringComparison.Ordinal);
    }

    [Fact]
    public void ForPostgres_UsesTheSharedRegexConstant()
    {
        string check = TemporalCheckPredicate.ForPostgres("created_at");
        Assert.Contains(UtcTimestamp.TemporalCheckRegex, check, StringComparison.Ordinal);
    }
}
