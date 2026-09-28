using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class PostgresConnectionStringTests
{
    private const string BaseWithoutPassword = "Host=db.internal;Port=5432;Database=dependably;Username=app";
    private const string BaseWithPassword = BaseWithoutPassword + ";Password=embedded-secret";

    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    [Fact]
    public void FromConfiguration_NoConnectionString_ReturnsNull()
    {
        Assert.Null(PostgresConnectionString.FromConfiguration(Config(("DB_PASSWORD", "pw"))));
        Assert.Null(PostgresConnectionString.FromConfiguration(Config(("DB_CONNECTION_STRING", "  "))));
    }

    [Fact]
    public void FromConfiguration_PasswordSuppliedSeparately_IsMergedIn()
    {
        string? merged = PostgresConnectionString.FromConfiguration(Config(
            ("DB_CONNECTION_STRING", BaseWithoutPassword),
            ("DB_PASSWORD", "rotated-secret")));

        var parsed = new NpgsqlConnectionStringBuilder(merged);
        Assert.Equal("rotated-secret", parsed.Password);
        Assert.Equal("db.internal", parsed.Host);
        Assert.Equal("dependably", parsed.Database);
        Assert.Equal("app", parsed.Username);
    }

    [Fact]
    public void FromConfiguration_PasswordOverride_WinsOverEmbeddedPassword()
    {
        string? merged = PostgresConnectionString.FromConfiguration(Config(
            ("DB_CONNECTION_STRING", BaseWithPassword),
            ("DB_PASSWORD", "rotated-secret")));

        var parsed = new NpgsqlConnectionStringBuilder(merged);
        Assert.Equal("rotated-secret", parsed.Password);
        Assert.DoesNotContain("embedded-secret", merged, StringComparison.Ordinal);
    }

    [Fact]
    public void FromConfiguration_UsernameOverride_WinsOverEmbeddedUsername()
    {
        string? merged = PostgresConnectionString.FromConfiguration(Config(
            ("DB_CONNECTION_STRING", BaseWithPassword),
            ("DB_USERNAME", "rotated_user")));

        var parsed = new NpgsqlConnectionStringBuilder(merged);
        Assert.Equal("rotated_user", parsed.Username);
        Assert.Equal("embedded-secret", parsed.Password);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FromConfiguration_NoOverrides_ReturnsConnectionStringVerbatim(string? emptyOverride)
    {
        string? resolved = PostgresConnectionString.FromConfiguration(Config(
            ("DB_CONNECTION_STRING", BaseWithPassword),
            ("DB_PASSWORD", emptyOverride),
            ("DB_USERNAME", emptyOverride)));

        Assert.Equal(BaseWithPassword, resolved);
    }

    [Fact]
    public void FromConfiguration_PasswordWithConnectionStringMetacharacters_RoundTrips()
    {
        // A generated secret routinely carries ';', '=', and quotes; string concatenation would
        // split it into bogus keywords, the builder must quote it.
        const string password = "a;b=c'd\"e f";

        string? merged = PostgresConnectionString.FromConfiguration(Config(
            ("DB_CONNECTION_STRING", BaseWithoutPassword),
            ("DB_PASSWORD", password)));

        Assert.Equal(password, new NpgsqlConnectionStringBuilder(merged).Password);
    }
}
