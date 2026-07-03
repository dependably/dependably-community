using Dependably.Infrastructure.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the HA-over-SQLite fail-closed guard: <c>DEPENDABLY_DEPLOYMENT_MODE=ha</c> validated
/// Redis but not the metadata store, so the documented-forbidden combination (HA + SQLite —
/// write-lock corruption, WAL divergence, silent data loss per CONTRIBUTING.md) used to boot
/// with no error or warning. <see cref="AuthStartupExtensions.AddDependablyRedisAndDataProtection"/>
/// now throws before registering any Redis/DB services when ha mode is combined with a
/// non-Postgres provider, mirroring the pre-existing Redis-connection-string check.
///
/// These tests call the internal extension method directly against a minimal
/// <see cref="WebApplicationBuilder"/> — the guard runs and throws before any Redis connection
/// attempt or DB registration, so no live Redis/Postgres is needed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HaDeploymentValidationTests
{
    private static WebApplicationBuilder NewBuilder(IDictionary<string, string?> config)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(config);
        return builder;
    }

    [Fact]
    public void HaMode_SqliteDefault_RedisConfigured_ThrowsBeforeRegisteringAnything()
    {
        // DB_PROVIDER unset ⇒ defaults to sqlite. Redis IS configured, so the pre-existing
        // Redis check passes — this must fail on the new DB_PROVIDER check specifically, not
        // fall through silently into the SQLite+HA corruption-class configuration.
        var builder = NewBuilder(new Dictionary<string, string?>
        {
            ["DEPENDABLY_DEPLOYMENT_MODE"] = "ha",
            ["REDIS_CONNECTION_STRING"] = "localhost:6379",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => builder.AddDependablyRedisAndDataProtection());

        Assert.Contains("DB_PROVIDER=postgres", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void HaMode_SqliteExplicit_RedisConfigured_Throws()
    {
        var builder = NewBuilder(new Dictionary<string, string?>
        {
            ["DEPENDABLY_DEPLOYMENT_MODE"] = "ha",
            ["REDIS_CONNECTION_STRING"] = "localhost:6379",
            ["DB_PROVIDER"] = "sqlite",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => builder.AddDependablyRedisAndDataProtection());

        Assert.Contains("DB_PROVIDER=postgres", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void HaMode_Postgres_RedisConfigured_DoesNotThrowOnProviderCheck()
    {
        // The correct HA combination (postgres + Redis) must clear the provider guard. This
        // proceeds into live Redis connection setup, so we only assert the provider check
        // itself does not fire — a ConnectionMultiplexer.Connect failure downstream (no live
        // Redis in this unit test) is a different, expected exception type/message.
        var builder = NewBuilder(new Dictionary<string, string?>
        {
            ["DEPENDABLY_DEPLOYMENT_MODE"] = "ha",
            ["REDIS_CONNECTION_STRING"] = "localhost:6379",
            ["DB_PROVIDER"] = "postgres",
        });

        var ex = Record.Exception(() => builder.AddDependablyRedisAndDataProtection());

        // Registration itself (Configure<RedisOptions> + AddSingleton factories) never throws —
        // IConnectionMultiplexer.Connect is deferred until the service is resolved. So the
        // provider-check guard clearing means no exception at all at this call site.
        Assert.Null(ex);
    }

    [Fact]
    public void StandaloneMode_SqliteDefault_DoesNotThrow()
    {
        // Standalone (non-ha) mode is unaffected by the new guard regardless of provider —
        // the default single-instance deployment must keep booting on SQLite exactly as before.
        var builder = NewBuilder(new Dictionary<string, string?>());

        var ex = Record.Exception(() => builder.AddDependablyRedisAndDataProtection());

        Assert.Null(ex);
    }

    [Fact]
    public void HaMode_NoRedis_ThrowsRedisCheckFirst_NotProviderCheck()
    {
        // Both checks would fail here (no Redis, sqlite default); the pre-existing Redis check
        // must still fire first so its message isn't shadowed by the new provider guard.
        var builder = NewBuilder(new Dictionary<string, string?>
        {
            ["DEPENDABLY_DEPLOYMENT_MODE"] = "ha",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => builder.AddDependablyRedisAndDataProtection());

        Assert.Contains("REDIS_CONNECTION_STRING", ex.Message, StringComparison.Ordinal);
    }
}
