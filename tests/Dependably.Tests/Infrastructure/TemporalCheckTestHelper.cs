using System.Data.Common;
using System.Globalization;
using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Lets a test seed a legacy, non-canonical timestamp shape directly into a column that now
/// carries the fresh-install canonical-timestamp CHECK (<see cref="TemporalCheckPredicate"/>) —
/// simulating a database whose rows predate that constraint, which is exactly what
/// <c>SchemaInitializerTimestampNormalizationTests</c> / <c>TimestampNormalizationPostgresTests</c>
/// need in order to exercise the repair sweep against a bad shape.
///
/// Real pre-existing databases get into this state simply by having been created before this
/// constraint shipped — neither provider retrofits it onto an existing database this release
/// (see <c>SchemaInitializer.TemporalColumnNaming.cs</c>). A fresh <see cref="TestMetadataStore"/>
/// / live-Postgres reset, by contrast, gets the constraint from <c>InitializeAsync()</c>
/// immediately (both providers declare it inline in their <c>CREATE TABLE</c> block), so a test
/// that wants to plant a legacy row has to remove the constraint first — these helpers are the
/// one place that does that removal, using the SAME provider-specific technique
/// <c>SchemaInitializer</c> itself uses elsewhere to rewrite a stored CHECK (SQLite:
/// <c>writable_schema</c> substring rewrite; Postgres: named-constraint drop).
/// </summary>
internal static class TemporalCheckTestHelper
{
    /// <summary>
    /// Removes the canonical-timestamp CHECK from <paramref name="column"/> on SQLite by
    /// rewriting the stored <c>CREATE TABLE</c> text — the exact literal
    /// <see cref="TemporalCheckPredicate.ForSqlite"/> emits, which is also exactly what
    /// <c>Schema.sql</c> embeds, so the substring match always finds it.
    /// </summary>
    public static async Task StripSqliteCheckAsync(DbConnection conn, string table, string column)
    {
        string check = TemporalCheckPredicate.ForSqlite(column);
        await conn.ExecuteAsync("PRAGMA writable_schema = ON");
        try
        {
            await conn.ExecuteAsync(
                """
                UPDATE sqlite_schema
                SET sql = REPLACE(sql, @check, '')
                WHERE type = 'table' AND name = @table
                """,
                new { check, table });
            long version = await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
            // rawsql: version is read back from PRAGMA schema_version immediately above, never
            // caller-supplied — SQLite's PRAGMA grammar has no parameter-binding syntax for it.
            await conn.ExecuteAsync(
                "PRAGMA schema_version = " + (version + 1).ToString(CultureInfo.InvariantCulture));
        }
        finally
        {
            await conn.ExecuteAsync("PRAGMA writable_schema = RESET");
        }
    }

    /// <summary>
    /// Drops the canonical-timestamp CHECK on Postgres, reusing the same
    /// <c>&lt;table&gt;_&lt;column&gt;_check</c> name Postgres auto-assigns the unnamed inline
    /// CHECK declared in <c>Schema.pg.sql</c>'s <c>CREATE TABLE</c> block.
    /// </summary>
    public static Task DropPostgresCheckAsync(DbConnection conn, string table, string column) =>
        conn.ExecuteAsync($"ALTER TABLE {table} DROP CONSTRAINT {table}_{column}_check");
}
