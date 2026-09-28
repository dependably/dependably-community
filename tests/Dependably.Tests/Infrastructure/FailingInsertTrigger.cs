using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Injects a database failure for tests: every INSERT into a table aborts until the trigger is
/// dropped, while reads and existing rows stay intact. Emitted per provider — SQLite's inline
/// <c>RAISE(ABORT)</c> trigger body has no Postgres equivalent, which needs a trigger function.
/// </summary>
internal static class FailingInsertTrigger
{
    public static Task InstallAsync(DbConnection conn, DbProvider provider, string name, string table, string message) =>
        provider == DbProvider.Postgres
            // rawsql: name, table and message are compile-time constants supplied by the test.
            ? conn.ExecuteAsync(
                $"""
                CREATE FUNCTION {name}_fn() RETURNS trigger LANGUAGE plpgsql AS $fn$
                BEGIN RAISE EXCEPTION '{message}'; END
                $fn$;
                CREATE TRIGGER {name} BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {name}_fn();
                """)
            // rawsql: name, table and message are compile-time constants supplied by the test.
            : conn.ExecuteAsync(
                $"""
                CREATE TRIGGER {name} BEFORE INSERT ON {table}
                BEGIN SELECT RAISE(ABORT, '{message}'); END
                """);

    public static Task DropAsync(DbConnection conn, DbProvider provider, string name, string table) =>
        provider == DbProvider.Postgres
            // rawsql: name and table are compile-time constants supplied by the test.
            ? conn.ExecuteAsync($"DROP TRIGGER IF EXISTS {name} ON {table}; DROP FUNCTION IF EXISTS {name}_fn()")
            // rawsql: name is a compile-time constant supplied by the test.
            : conn.ExecuteAsync($"DROP TRIGGER IF EXISTS {name}");
}
