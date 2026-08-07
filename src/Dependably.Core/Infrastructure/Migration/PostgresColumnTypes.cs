using System.Globalization;
using NpgsqlTypes;

namespace Dependably.Infrastructure.Migration;

/// <summary>
/// The Postgres storage classes the migrator knows how to write. Every target column is resolved to
/// exactly one of these from <c>information_schema</c>; an unrecognised type is a hard failure
/// rather than a best-effort guess, because the failure mode this whole path is designed against is
/// silent data corruption, not a noisy abort.
/// </summary>
public enum PostgresKind
{
    Text,
    SmallInt,
    Integer,
    BigInt,
    Real,
    DoublePrecision,
    Numeric,
    Boolean,
    TimestampTz,
    Timestamp,
    Date,
    Bytea,
    Json,
    Jsonb,
    Uuid,
}

/// <summary>One target column: its name, its resolved storage class, and whether it accepts NULL.</summary>
public sealed record PostgresColumn(string Name, PostgresKind Kind, bool IsNullable);

/// <summary>Raised when a value or a column type cannot be migrated faithfully.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class MetadataMigrationException : Exception
{
    public MetadataMigrationException(string message) : base(message) { }

    public MetadataMigrationException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Converts a value read out of SQLite into the exact CLR type the matching Postgres column expects,
/// and renders any value into a provider-independent canonical string for the verification digest.
///
/// <para>SQLite is dynamically typed: a column declared <c>TEXT</c> can hold an integer, and an
/// <c>INTEGER</c> column can hold a string. Microsoft.Data.Sqlite therefore hands back whatever the
/// stored value actually is (<see cref="long"/>, <see cref="double"/>, <see cref="string"/>,
/// <c>byte[]</c>), not what the declaration promised. Postgres is statically typed and rejects the
/// mismatch, so every value is coerced here against the <em>target</em> column's type, explicitly,
/// with a loud failure on anything ambiguous.</para>
///
/// <para>The same conversion feeds both the copy and the verification digest. Canonicalising the
/// converted value on the source side and the read-back value on the target side means the two
/// digests agree exactly when the copy was faithful — a digest computed off the raw SQLite value
/// would report a false mismatch on every column whose representation legitimately differs
/// (an ISO-8601 string landing in a <c>timestamptz</c>, a double landing in a 4-byte
/// <c>real</c>).</para>
/// </summary>
public static class PostgresValueConverter
{
    /// <summary>
    /// Sentinel canonical token for NULL. It is wrapped in NUL characters because Postgres text
    /// cannot contain one — so no real column value can render to this token and be mistaken for a
    /// NULL by the verification digest.
    /// </summary>
    private const string NullToken = "\u0000NULL\u0000";

    /// <summary>
    /// Resolves an <c>information_schema.columns.data_type</c> string to a <see cref="PostgresKind"/>.
    /// </summary>
    public static PostgresKind ResolveKind(string table, string column, string dataType)
    {
        ArgumentNullException.ThrowIfNull(dataType);
        return dataType.ToLowerInvariant() switch
        {
            "text" or "character varying" or "character" or "citext" or "name" => PostgresKind.Text,
            "smallint" => PostgresKind.SmallInt,
            "integer" => PostgresKind.Integer,
            "bigint" => PostgresKind.BigInt,
            "real" => PostgresKind.Real,
            "double precision" => PostgresKind.DoublePrecision,
            "numeric" or "decimal" => PostgresKind.Numeric,
            "boolean" => PostgresKind.Boolean,
            "timestamp with time zone" => PostgresKind.TimestampTz,
            "timestamp without time zone" => PostgresKind.Timestamp,
            "date" => PostgresKind.Date,
            "bytea" => PostgresKind.Bytea,
            "json" => PostgresKind.Json,
            "jsonb" => PostgresKind.Jsonb,
            "uuid" => PostgresKind.Uuid,
            _ => throw new MetadataMigrationException(
                $"{table}.{column}: Postgres type '{dataType}' has no migration rule. Add an explicit " +
                $"conversion to PostgresValueConverter rather than letting the value through unchecked."),
        };
    }

    /// <summary>The Npgsql wire type the binary COPY writer must be told for this storage class.</summary>
    public static NpgsqlDbType WireType(PostgresKind kind) => kind switch
    {
        PostgresKind.Text => NpgsqlDbType.Text,
        PostgresKind.SmallInt => NpgsqlDbType.Smallint,
        PostgresKind.Integer => NpgsqlDbType.Integer,
        PostgresKind.BigInt => NpgsqlDbType.Bigint,
        PostgresKind.Real => NpgsqlDbType.Real,
        PostgresKind.DoublePrecision => NpgsqlDbType.Double,
        PostgresKind.Numeric => NpgsqlDbType.Numeric,
        PostgresKind.Boolean => NpgsqlDbType.Boolean,
        PostgresKind.TimestampTz => NpgsqlDbType.TimestampTz,
        PostgresKind.Timestamp => NpgsqlDbType.Timestamp,
        PostgresKind.Date => NpgsqlDbType.Date,
        PostgresKind.Bytea => NpgsqlDbType.Bytea,
        PostgresKind.Json => NpgsqlDbType.Json,
        PostgresKind.Jsonb => NpgsqlDbType.Jsonb,
        PostgresKind.Uuid => NpgsqlDbType.Uuid,
        _ => throw new MetadataMigrationException($"No Npgsql wire type mapped for {kind}."),
    };

    /// <summary>
    /// Coerces one raw SQLite value into the CLR type the target column expects. Returns
    /// <see langword="null"/> for SQL NULL. Throws <see cref="MetadataMigrationException"/> rather
    /// than guessing whenever the value cannot be represented faithfully.
    /// </summary>
    public static object? ToPostgresValue(string table, PostgresColumn column, object? raw)
    {
        ArgumentNullException.ThrowIfNull(column);

        if (raw is null or DBNull)
        {
            return null;
        }

        try
        {
            return column.Kind switch
            {
                PostgresKind.Text or PostgresKind.Json or PostgresKind.Jsonb => AsText(raw),
                PostgresKind.SmallInt => checked((short)AsInteger(raw)),
                PostgresKind.Integer => checked((int)AsInteger(raw)),
                PostgresKind.BigInt => AsInteger(raw),
                PostgresKind.Real => (float)AsDouble(raw),
                PostgresKind.DoublePrecision => AsDouble(raw),
                PostgresKind.Numeric => AsDecimal(raw),
                PostgresKind.Boolean => AsBoolean(raw),
                PostgresKind.TimestampTz => AsInstant(raw).UtcDateTime,
                PostgresKind.Timestamp => DateTime.SpecifyKind(AsInstant(raw).UtcDateTime, DateTimeKind.Unspecified),
                PostgresKind.Date => DateOnly.FromDateTime(AsInstant(raw).UtcDateTime),
                PostgresKind.Bytea => AsBytes(raw),
                PostgresKind.Uuid => AsGuid(raw),
                _ => throw new MetadataMigrationException($"No conversion for {column.Kind}."),
            };
        }
        catch (MetadataMigrationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is OverflowException or FormatException or InvalidCastException)
        {
            throw new MetadataMigrationException(
                $"{table}.{column.Name}: SQLite value '{Describe(raw)}' cannot be represented as " +
                $"Postgres {column.Kind}. Refusing to write a lossy value.", ex);
        }
    }

    /// <summary>
    /// Renders a value into a provider-independent token for the verification digest. Feed it the
    /// <em>converted</em> value on the source side and the value read back on the target side.
    /// </summary>
    public static string Canonical(PostgresKind kind, object? value)
    {
        if (value is null or DBNull)
        {
            return NullToken;
        }

        var inv = CultureInfo.InvariantCulture;
        return kind switch
        {
            PostgresKind.Text or PostgresKind.Json or PostgresKind.Jsonb => Convert.ToString(value, inv) ?? NullToken,
            PostgresKind.SmallInt or PostgresKind.Integer or PostgresKind.BigInt =>
                Convert.ToInt64(value, inv).ToString(inv),
            PostgresKind.Real => Convert.ToSingle(value, inv).ToString("R", inv),
            PostgresKind.DoublePrecision => Convert.ToDouble(value, inv).ToString("R", inv),
            PostgresKind.Numeric => Convert.ToDecimal(value, inv).ToString(inv),
            PostgresKind.Boolean => Convert.ToBoolean(value, inv) ? "t" : "f",
            // timestamptz is compared as an instant (both sides normalised to UTC); timestamp has
            // no zone to normalise against, so its stored wall-clock value is compared verbatim.
            // utcformat-ok: a migration-comparison canonicalizer for Postgres-native temporal
            // types, at the microsecond precision those types carry. Not a stored Dependably
            // timestamp column, and deliberately unsuffixed — a `Z` would assert a zone that
            // the zone-less `timestamp` arm does not have.
            PostgresKind.TimestampTz => AsInstant(value).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.ffffff", inv),
            PostgresKind.Timestamp => Convert.ToDateTime(value, inv).ToString("yyyy-MM-ddTHH:mm:ss.ffffff", inv),
            PostgresKind.Date => value is DateOnly d
                ? d.ToString("yyyy-MM-dd", inv)
                : Convert.ToDateTime(value, inv).ToString("yyyy-MM-dd", inv),
            PostgresKind.Bytea => Convert.ToHexString((byte[])value),
            PostgresKind.Uuid => ((Guid)value).ToString("D", inv),
            _ => throw new MetadataMigrationException($"No canonical form for {kind}."),
        };
    }

    private static string AsText(object raw) => raw switch
    {
        string s => s,
        long l => l.ToString(CultureInfo.InvariantCulture),
        int i => i.ToString(CultureInfo.InvariantCulture),
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        decimal m => m.ToString(CultureInfo.InvariantCulture),
        bool b => b ? "1" : "0",
        // A byte[] sitting in a column Postgres declares TEXT has no lossless textual form: any
        // decoding we pick is a guess, and a wrong guess is exactly the silent corruption this
        // path exists to prevent. Fail and let an operator decide.
        byte[] bytes => throw new MetadataMigrationException(
            $"a {bytes.Length}-byte BLOB is stored in a column Postgres declares TEXT. There is no " +
            $"lossless conversion; migrate or remove the row before re-running."),
        _ => throw new MetadataMigrationException(
            $"unsupported SQLite value type {raw.GetType().Name} for a TEXT column."),
    };

    private static long AsInteger(object raw) => raw switch
    {
        long l => l,
        int i => i,
        short s => s,
        bool b => b ? 1L : 0L,
        // A stored double is only safe as an integer when it is exactly integral; 1.5 in an
        // INTEGER column is corrupt data, not a rounding opportunity.
        double d when Math.Abs(d % 1) < double.Epsilon && d is >= long.MinValue and <= long.MaxValue => (long)d,
        string s => long.Parse(s, CultureInfo.InvariantCulture),
        _ => throw new MetadataMigrationException(
            $"SQLite value '{Describe(raw)}' is not an integer."),
    };

    private static double AsDouble(object raw) => raw switch
    {
        double d => d,
        float f => f,
        long l => l,
        int i => i,
        decimal m => (double)m,
        string s => double.Parse(s, CultureInfo.InvariantCulture),
        _ => throw new MetadataMigrationException($"SQLite value '{Describe(raw)}' is not a number."),
    };

    private static decimal AsDecimal(object raw) => raw switch
    {
        decimal m => m,
        long l => l,
        int i => i,
        double d => (decimal)d,
        string s => decimal.Parse(s, CultureInfo.InvariantCulture),
        _ => throw new MetadataMigrationException($"SQLite value '{Describe(raw)}' is not a number."),
    };

    private static bool AsBoolean(object raw) => raw switch
    {
        bool b => b,
        long l => l != 0,
        int i => i != 0,
        string s when bool.TryParse(s, out bool parsed) => parsed,
        string s when long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n) => n != 0,
        _ => throw new MetadataMigrationException($"SQLite value '{Describe(raw)}' is not a boolean."),
    };

    private static byte[] AsBytes(object raw) => raw switch
    {
        byte[] b => b,
        _ => throw new MetadataMigrationException(
            $"SQLite value '{Describe(raw)}' is not binary and cannot be written to a bytea column."),
    };

    private static Guid AsGuid(object raw) => raw switch
    {
        Guid g => g,
        string s => Guid.Parse(s),
        _ => throw new MetadataMigrationException($"SQLite value '{Describe(raw)}' is not a UUID."),
    };

    /// <summary>
    /// Parses a stored timestamp. Timestamps live in SQLite as ISO-8601 TEXT — either the
    /// second-precision <c>strftime('%Y-%m-%dT%H:%M:%SZ')</c> form the schema defaults write, or the
    /// round-trip <c>"o"</c> form the <c>DateTimeOffset</c> Dapper handler writes. A value with no
    /// offset is UTC, matching how every writer in the codebase produces it.
    ///
    /// <para>The result is truncated to whole microseconds because that is Postgres's timestamp
    /// resolution. Truncating here (rather than letting the server round) is what makes the copy
    /// verifiable: the value written is bit-for-bit the value read back, so the digest comparison
    /// is exact instead of tolerant.</para>
    /// </summary>
    private static DateTimeOffset AsInstant(object raw)
    {
        var parsed = raw switch
        {
            DateTimeOffset dto => dto,
            DateTime dt => dt.Kind == DateTimeKind.Unspecified
                ? new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc))
                : new DateTimeOffset(dt),
            string s => DateTimeOffset.Parse(
                s,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal),
            _ => throw new MetadataMigrationException(
                $"SQLite value '{Describe(raw)}' is not an ISO-8601 timestamp."),
        };

        var utc = parsed.ToUniversalTime();
        return utc.AddTicks(-(utc.Ticks % TimeSpan.TicksPerMicrosecond));
    }

    private static string Describe(object raw)
    {
        string text = raw switch
        {
            byte[] b => $"0x{Convert.ToHexString(b)}",
            _ => Convert.ToString(raw, CultureInfo.InvariantCulture) ?? "",
        };
        return text.Length <= 64 ? text : text[..64] + "…";
    }
}
