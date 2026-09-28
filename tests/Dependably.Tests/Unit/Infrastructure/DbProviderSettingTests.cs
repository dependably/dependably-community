using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class DbProviderSettingTests
{
    private static IConfiguration Config(string? value) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DB_PROVIDER"] = value })
            .Build();

    [Theory]
    [InlineData(null, DbProvider.Sqlite)]
    [InlineData("", DbProvider.Sqlite)]
    [InlineData("   ", DbProvider.Sqlite)]
    [InlineData("sqlite", DbProvider.Sqlite)]
    [InlineData("SQLite", DbProvider.Sqlite)]
    [InlineData("postgres", DbProvider.Postgres)]
    [InlineData(" Postgres ", DbProvider.Postgres)]
    public void KnownValues_Parse(string? value, DbProvider expected) =>
        Assert.Equal(expected, DbProviderSetting.FromConfiguration(Config(value)));

    [Theory]
    [InlineData("postgresql")]
    [InlineData("pg")]
    [InlineData("mysql")]
    [InlineData("sqlite3")]
    public void UnknownValue_FailsNamingTheAcceptedValues(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => DbProviderSetting.FromConfiguration(Config(value)));

        Assert.Contains("'sqlite' or 'postgres'", ex.Message, StringComparison.Ordinal);
        Assert.Contains($"got '{value}'", ex.Message, StringComparison.Ordinal);
    }

    // The regression the setting exists for: a mistyped provider used to boot on SQLite.
    [Fact]
    public void Startup_UnknownProvider_FailsBootInsteadOfFallingBackToSqlite()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration["DB_PROVIDER"] = "postgresql";
        builder.Configuration["DB_CONNECTION_STRING"] = "Host=db;Database=dependably";

        var ex = Assert.Throws<InvalidOperationException>(() => builder.AddDependablyMetadataStore());
        Assert.Contains("got 'postgresql'", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, DbProvider.Sqlite)]
    [InlineData("sqlite", DbProvider.Sqlite)]
    [InlineData("postgres", DbProvider.Postgres)]
    [InlineData(" POSTGRES ", DbProvider.Postgres)]
    public void Startup_KnownProvider_Boots(string? value, DbProvider expected)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration["DB_PROVIDER"] = value;
        builder.Configuration["DB_CONNECTION_STRING"] = "Host=db;Database=dependably";
        builder.Configuration["DB_PATH"] = Path.Combine(Path.GetTempPath(), $"dbprovider-{Guid.NewGuid():N}.db");
        builder.Configuration["DEPLOYMENT_MODE"] = "single";

        builder.AddDependablyMetadataStore();

        using var services = builder.Services.BuildServiceProvider();
        Assert.Equal(expected, services.GetRequiredService<IMetadataStore>().Provider);
    }
}
