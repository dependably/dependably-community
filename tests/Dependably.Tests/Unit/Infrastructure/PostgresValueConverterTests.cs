using Dependably.Infrastructure.Migration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The per-column type rules the SQLite → Postgres copy depends on. SQLite is dynamically typed, so
/// a value read out of it can be any of long/double/string/byte[] regardless of the column's
/// declaration; these pin what each of those becomes on the Postgres side, and — just as
/// importantly — which combinations are refused outright rather than silently coerced.
/// </summary>
public sealed class PostgresValueConverterTests
{
    private static PostgresColumn Column(PostgresKind kind, bool nullable = true) =>
        new("c", kind, nullable);

    private static object? Convert(PostgresKind kind, object? raw) =>
        PostgresValueConverter.ToPostgresValue("t", Column(kind), raw);

    [Fact]
    public void Null_And_DbNull_BothBecomeNull()
    {
        Assert.Null(Convert(PostgresKind.Text, null));
        Assert.Null(Convert(PostgresKind.Text, DBNull.Value));
        Assert.Null(Convert(PostgresKind.Integer, DBNull.Value));
    }

    [Fact]
    public void Text_AcceptsAStringVerbatim_IncludingNonAsciiAndControlCharacters()
    {
        const string value = "naïve\u0001control\tline\nbreak é中 \"quoted\" back\\slash";
        Assert.Equal(value, Convert(PostgresKind.Text, value));
    }

    [Fact]
    public void Text_RendersAnIntegerStoredInATextColumn_InInvariantForm()
    {
        // SQLite lets an INTEGER value live in a TEXT-declared column; Postgres will not.
        Assert.Equal("42", Convert(PostgresKind.Text, 42L));
    }

    [Fact]
    public void Text_RefusesABlob_RatherThanGuessingAnEncoding()
    {
        var ex = Assert.Throws<MetadataMigrationException>(
            () => Convert(PostgresKind.Text, new byte[] { 0xFF, 0x00, 0x10 }));
        Assert.Contains("BLOB", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Booleans_RoundTripThroughSqlitesIntegerRepresentation()
    {
        Assert.Equal(true, Convert(PostgresKind.Boolean, 1L));
        Assert.Equal(false, Convert(PostgresKind.Boolean, 0L));
        Assert.Equal(true, Convert(PostgresKind.Boolean, "true"));
    }

    [Fact]
    public void Integer_RefusesAFractionalValue()
    {
        Assert.Throws<MetadataMigrationException>(() => Convert(PostgresKind.Integer, 1.5d));
    }

    [Fact]
    public void Integer_RefusesAValueTooLargeForTheTargetColumn()
    {
        // Postgres INTEGER is 4 bytes; SQLite INTEGER is 8. Overflow must abort, never wrap.
        Assert.Throws<MetadataMigrationException>(() => Convert(PostgresKind.Integer, long.MaxValue));
        Assert.Equal(9_000_000_000L, Convert(PostgresKind.BigInt, 9_000_000_000L));
    }

    [Fact]
    public void Real_NarrowsToFourBytes_MatchingThePostgresColumn()
    {
        // Postgres REAL is float4 while SQLite REAL is a double, so the narrowing happens on the
        // way in and the verification digest compares the narrowed value on both sides.
        object? converted = Convert(PostgresKind.Real, 0.15d);
        Assert.Equal(0.15f, Assert.IsType<float>(converted));
        Assert.Equal(10.0d, Assert.IsType<double>(Convert(PostgresKind.DoublePrecision, 10.0d)));
    }

    [Fact]
    public void TimestampTz_ParsesTheSecondPrecisionSchemaDefaultForm()
    {
        object? converted = Convert(PostgresKind.TimestampTz, "2026-07-25T12:34:56Z");
        var dt = Assert.IsType<DateTime>(converted);
        Assert.Equal(DateTimeKind.Utc, dt.Kind);
        Assert.Equal(new DateTime(2026, 7, 25, 12, 34, 56, DateTimeKind.Utc), dt);
    }

    [Fact]
    public void TimestampTz_ParsesTheRoundTripFormAndNormalisesAnOffsetToUtc()
    {
        object? converted = Convert(PostgresKind.TimestampTz, "2026-07-25T09:34:56.1234560-03:00");
        var dt = Assert.IsType<DateTime>(converted);
        Assert.Equal(DateTimeKind.Utc, dt.Kind);
        Assert.Equal(new DateTime(2026, 7, 25, 12, 34, 56, DateTimeKind.Utc).AddTicks(1234560), dt);
    }

    [Fact]
    public void TimestampTz_TruncatesBelowMicrosecond_SoTheServerNeverRoundsBehindTheVerifier()
    {
        // Postgres resolves timestamps to whole microseconds. Truncating on the way in makes the
        // written value identical to the value read back, which is what keeps verification exact.
        object? converted = Convert(PostgresKind.TimestampTz, "2026-07-25T12:34:56.1234567Z");
        var dt = Assert.IsType<DateTime>(converted);
        Assert.Equal(0, dt.Ticks % TimeSpan.TicksPerMicrosecond);
        Assert.Equal(new DateTime(2026, 7, 25, 12, 34, 56, DateTimeKind.Utc).AddTicks(1234560), dt);
    }

    [Fact]
    public void Bytea_TakesBinaryOnly()
    {
        byte[] payload = { 0x00, 0x01, 0xFE, 0xFF };
        Assert.Equal(payload, Convert(PostgresKind.Bytea, payload));
        Assert.Throws<MetadataMigrationException>(() => Convert(PostgresKind.Bytea, "not binary"));
    }

    [Fact]
    public void Uuid_ParsesTheTextFormSqliteStores()
    {
        var expected = Guid.Parse("2f1a4bb0-6a1a-4b0e-9e0a-1c2d3e4f5a6b");
        Assert.Equal(expected, Convert(PostgresKind.Uuid, expected.ToString()));
    }

    [Fact]
    public void ResolveKind_RefusesAnUnknownPostgresType()
    {
        Assert.Equal(PostgresKind.Text, PostgresValueConverter.ResolveKind("t", "c", "character varying"));
        Assert.Equal(PostgresKind.TimestampTz, PostgresValueConverter.ResolveKind("t", "c", "timestamp with time zone"));
        Assert.Throws<MetadataMigrationException>(
            () => PostgresValueConverter.ResolveKind("t", "c", "int4range"));
    }

    [Fact]
    public void Canonical_AgreesBetweenTheConvertedSourceValueAndTheTargetReadBack()
    {
        // The verification digest hashes the canonical form of the converted source value on one
        // side and of the value Postgres hands back on the other; they must agree exactly.
        Assert.Equal(
            PostgresValueConverter.Canonical(PostgresKind.Real, Convert(PostgresKind.Real, 0.15d)),
            PostgresValueConverter.Canonical(PostgresKind.Real, 0.15f));

        Assert.Equal(
            PostgresValueConverter.Canonical(PostgresKind.Integer, Convert(PostgresKind.Integer, 7L)),
            PostgresValueConverter.Canonical(PostgresKind.Integer, 7));

        Assert.Equal(
            PostgresValueConverter.Canonical(
                PostgresKind.TimestampTz, Convert(PostgresKind.TimestampTz, "2026-07-25T12:34:56Z")),
            PostgresValueConverter.Canonical(
                PostgresKind.TimestampTz, new DateTime(2026, 7, 25, 12, 34, 56, DateTimeKind.Utc)));
    }

    [Fact]
    public void Canonical_DistinguishesNullFromEmptyString()
    {
        Assert.NotEqual(
            PostgresValueConverter.Canonical(PostgresKind.Text, null),
            PostgresValueConverter.Canonical(PostgresKind.Text, ""));
    }

    [Fact]
    public void Quote_RefusesAnIdentifierThatIsNotAPlainName()
    {
        Assert.Equal("\"orgs\"", MigrationColumnPlanner.Quote("orgs"));
        Assert.Throws<MetadataMigrationException>(() => MigrationColumnPlanner.Quote("orgs; DROP TABLE users"));
        Assert.Throws<MetadataMigrationException>(() => MigrationColumnPlanner.Quote("\"quoted\""));
        Assert.Throws<MetadataMigrationException>(() => MigrationColumnPlanner.Quote(""));
    }
}
