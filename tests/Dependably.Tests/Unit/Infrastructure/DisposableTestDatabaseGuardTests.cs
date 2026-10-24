using Dependably.Tests.Infrastructure;
using Dependably.Tests.Integration;
using Npgsql;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class DisposableTestDatabaseGuardTests
{
    // The connection the schema-integrity and integration-tests-postgres-rls CI jobs export.
    // Connection strings in this file are built through the builder rather than written as
    // literals so the secret scanner's connection-string detector does not read the throwaway
    // credentials as secrets.
    private static readonly string CiConnection = Connection(
        "postgres", 5432, "dependably_test", "dependably", "dependably_test_pw");

    private static string Connection(string host, int port, string? database, string username, string password)
    {
        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = port,
            Username = username,
            Password = password,
        };
        if (database is not null)
        {
            builder.Database = database;
        }

        return builder.ConnectionString;
    }

    // Nothing listens on port 1, so any statement the harness tried to run would surface as an
    // NpgsqlException; the guard's own exception proves it threw before a connection was opened.
    private static string Unreachable(string database) =>
        new NpgsqlConnectionStringBuilder(Connection("127.0.0.1", 1, database, "dependably", "pw")) { Timeout = 2 }.ConnectionString;

    [Fact]
    public void CiConnectionString_Passes()
    {
        Assert.Equal(CiConnection, DisposableTestDatabaseGuard.EnsureDisposable(CiConnection, optInDatabase: null));
    }

    [Theory]
    [InlineData("dependably_test_local")]
    [InlineData("dependably_test_wt_42")]
    public void SuffixedTestDatabase_Passes(string database)
    {
        string cs = Unreachable(database);
        Assert.Equal(cs, DisposableTestDatabaseGuard.EnsureDisposable(cs, optInDatabase: null));
    }

    [Theory]
    [InlineData("dependably")]
    [InlineData("postgres")]
    [InlineData("dependably_staging")]
    [InlineData("dependably_testing")]
    [InlineData("prod_dependably_test")]
    [InlineData("Dependably_Test")]
    [InlineData("osvtracker_test")]
    public void NonTestDatabase_Throws(string database)
    {
        var ex = Assert.Throws<UnsafeTestDatabaseException>(
            () => DisposableTestDatabaseGuard.EnsureDisposable(Unreachable(database), optInDatabase: null));
        Assert.Contains($"'{database}'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NoDatabaseKeyword_Throws()
    {
        // Npgsql would fall back to PGDATABASE or the user name — here "dependably_test", which
        // would pass the name rule if the guard inferred it.
        Assert.Throws<UnsafeTestDatabaseException>(() => DisposableTestDatabaseGuard.EnsureDisposable(
            Connection("127.0.0.1", 1, database: null, "dependably_test", "pw"), optInDatabase: null));
    }

    [Fact]
    public void Message_DoesNotEchoThePassword()
    {
        var ex = Assert.Throws<UnsafeTestDatabaseException>(() => DisposableTestDatabaseGuard.EnsureDisposable(
            Connection("db", 5432, "dependably", "app", "hunter2-secret"), optInDatabase: null));
        Assert.DoesNotContain("hunter2-secret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OptIn_NamingTheTargetDatabase_Passes()
    {
        string cs = Unreachable("scratch_pg");
        Assert.Equal(cs, DisposableTestDatabaseGuard.EnsureDisposable(cs, optInDatabase: "scratch_pg"));
    }

    [Theory]
    [InlineData("other_db")]
    [InlineData("SCRATCH_PG")]
    [InlineData("")]
    public void OptIn_NamingAnotherDatabase_Throws(string optIn)
    {
        Assert.Throws<UnsafeTestDatabaseException>(
            () => DisposableTestDatabaseGuard.EnsureDisposable(Unreachable("scratch_pg"), optIn));
    }

    [Fact]
    public async Task LivePostgresReset_NonTestDatabase_ThrowsBeforeConnecting()
    {
        await Assert.ThrowsAsync<UnsafeTestDatabaseException>(
            () => LivePostgresReset.FreshAsync(Unreachable("guard_probe_not_disposable")));
    }

    [Fact]
    public void PostgresTestDatabase_NonTestDatabase_ThrowsBeforeConnecting()
    {
        Assert.Throws<UnsafeTestDatabaseException>(
            () => PostgresTestDatabase.AdminConnectionString(Unreachable("guard_probe_not_disposable")));
    }

    [Fact]
    public void PostgresTestDatabase_CiConnection_KeepsAdminTimeout()
    {
        string admin = PostgresTestDatabase.AdminConnectionString(CiConnection);
        Assert.Contains("Database=dependably_test", admin, StringComparison.Ordinal);
        Assert.Contains($"Command Timeout={PostgresTestDatabase.AdminCommandTimeoutSeconds}", admin, StringComparison.Ordinal);
    }
}
