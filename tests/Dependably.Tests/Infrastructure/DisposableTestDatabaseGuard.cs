using System.Text.RegularExpressions;
using Npgsql;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// The one check every destructive live-Postgres harness path runs before it touches the server
/// <c>TEST_POSTGRES_CONNECTION</c> names: the schema reset (<c>DROP SCHEMA public CASCADE</c>), the
/// per-host template and clone databases, and the row-level-security fixture databases. Those
/// paths drop data wholesale, so a connection string copied from a dev or staging
/// <c>DB_CONNECTION_STRING</c> must fail here, before any connection is opened, rather than wipe
/// that database.
///
/// <para>The rule reads only the connection string. The <c>Database</c> keyword must be set
/// explicitly (Npgsql otherwise falls back to <c>PGDATABASE</c> or the user name, which the
/// harness cannot see) and must be <c>dependably_test</c> or <c>dependably_test_&lt;suffix&gt;</c>.
/// A setup that cannot use such a name opts in by setting
/// <c>TEST_POSTGRES_DISPOSABLE_DATABASE</c> to the exact database name, so the opt-in authorizes
/// one named database rather than whatever the connection string happens to point at.</para>
/// </summary>
public static partial class DisposableTestDatabaseGuard
{
    public const string OptInVariable = "TEST_POSTGRES_DISPOSABLE_DATABASE";

    [GeneratedRegex("^dependably_test(_[a-z0-9_]+)?$")]
    private static partial Regex TestDatabaseName();

    /// <summary>
    /// Returns <paramref name="connectionString"/> unchanged when it targets a disposable test
    /// database; throws <see cref="UnsafeTestDatabaseException"/> otherwise.
    /// </summary>
    public static string EnsureDisposable(string connectionString) =>
        EnsureDisposable(connectionString, Environment.GetEnvironmentVariable(OptInVariable));

    internal static string EnsureDisposable(string connectionString, string? optInDatabase)
    {
        string? database = new NpgsqlConnectionStringBuilder(connectionString).Database;
        if (string.IsNullOrWhiteSpace(database))
        {
            throw new UnsafeTestDatabaseException(
                "TEST_POSTGRES_CONNECTION does not name a database. The live-Postgres harness drops "
                + "schemas and databases, so it needs an explicit Database=dependably_test (or "
                + "dependably_test_<suffix>) in the connection string.");
        }

        bool disposable = TestDatabaseName().IsMatch(database)
            || (!string.IsNullOrEmpty(optInDatabase) && string.Equals(optInDatabase, database, StringComparison.Ordinal));
        return disposable ? connectionString : throw new UnsafeTestDatabaseException(
            $"Refusing to run the live-Postgres harness against database '{database}': it drops the "
            + "public schema and creates and drops databases and roles on that server. Point "
            + "TEST_POSTGRES_CONNECTION at a disposable database named dependably_test or "
            + $"dependably_test_<suffix>, or set {OptInVariable}={database} if this database really is disposable.");
    }
}

/// <summary>Raised when <c>TEST_POSTGRES_CONNECTION</c> does not target a disposable test database.</summary>
public sealed class UnsafeTestDatabaseException(string message) : InvalidOperationException(message);
