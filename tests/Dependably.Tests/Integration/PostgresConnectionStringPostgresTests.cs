using Dapper;
using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves against a live server that a <c>DB_CONNECTION_STRING</c> carrying no password connects
/// once <c>DB_PASSWORD</c> supplies it, and — the adversarial twin — that the same string without
/// the override is refused, so the first test cannot pass on a trust-auth server.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresConnectionStringPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private static (string WithoutPassword, string Password) SplitCredential()
    {
        var builder = new NpgsqlConnectionStringBuilder(ConnectionString) { Pooling = false };
        string password = builder.Password
            ?? throw new InvalidOperationException("TEST_POSTGRES_CONNECTION must carry a password for this test.");
        builder.Password = null;
        return (builder.ConnectionString, password);
    }

    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    [Fact]
    public async Task PasswordFromDbPassword_Connects()
    {
        var (withoutPassword, password) = SplitCredential();

        string resolved = PostgresConnectionString.FromConfiguration(Config(
            ("DB_CONNECTION_STRING", withoutPassword),
            ("DB_PASSWORD", password)))!;

        await using var conn = await new NpgsqlMetadataStore(resolved).OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT 1"));
    }

    [Fact]
    public async Task NoDbPassword_PasswordlessConnectionString_IsRefused()
    {
        var (withoutPassword, _) = SplitCredential();

        string resolved = PostgresConnectionString.FromConfiguration(Config(
            ("DB_CONNECTION_STRING", withoutPassword)))!;

        await Assert.ThrowsAnyAsync<NpgsqlException>(async () =>
        {
            await using var conn = await new NpgsqlMetadataStore(resolved).OpenAsync();
        });
    }
}
