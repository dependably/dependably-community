using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Migration;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The schema apply refuses a database older than the documented upgrade floor before it changes
/// anything, because the one-time migrations only carry the shapes a floor database can be in. A
/// database is at the floor when its ledger holds the floor sentinel (a migration every database
/// that booted the floor release has recorded) or the marker a previous boot of this check wrote;
/// a database with no application tables is a fresh install. <c>UPGRADE_FLOOR_OVERRIDE=true</c>
/// boots a below-floor database anyway, with an error-level log.
/// </summary>
[Trait("Category", "Schema")]
public sealed class UpgradeFloorTests : IAsyncLifetime
{
    private const string Sentinel = "expand_usage_daily_meter_check_cache_storage";
    private const string Marker = "upgrade_floor_0_13_3";

    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Override(string value) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["UPGRADE_FLOOR_OVERRIDE"] = value })
            .Build();

    private async Task ForgetFloorAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name IN (@Sentinel, @Marker)", new { Sentinel, Marker });
    }

    private async Task<long> LedgerCountAsync(string name)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name });
    }

    [Fact]
    public async Task DatabaseBelowTheFloor_IsRefused_BeforeAnyMigrationRuns()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await ForgetFloorAsync();

        var ex = await Assert.ThrowsAsync<UpgradeFloorException>(() => new SchemaInitializer(_db).InitializeAsync());

        Assert.Contains("0.13.3", ex.Message, StringComparison.Ordinal);
        Assert.Contains("UPGRADE_FLOOR_OVERRIDE", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, await LedgerCountAsync(Sentinel));
        Assert.Equal(0, await LedgerCountAsync(Marker));
    }

    [Fact]
    public async Task DatabaseWithTheSentinel_Passes_AndRecordsTheMarker()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @Marker", new { Marker });
        }

        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Equal(1, await LedgerCountAsync(Marker));
    }

    [Fact]
    public async Task DatabaseWithOnlyTheMarker_Passes()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @Sentinel", new { Sentinel });
        }

        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Equal(1, await LedgerCountAsync(Sentinel));
    }

    [Fact]
    public async Task FreshDatabase_Passes_AndRecordsTheMarkerFirst()
    {
        bool markerAtClaim = false;
        await new SchemaInitializer(_db).InitializeAsync(async ct =>
        {
            await using var probe = await _db.OpenAsync(ct);
            markerAtClaim = await probe.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM _applied_migrations WHERE name = @Marker", new { Marker }) == 1;
        });

        // Recorded before the migration sequence, so a first boot interrupted part-way is still
        // recognized as at the floor on the next one.
        Assert.True(markerAtClaim);
        Assert.Equal(1, await LedgerCountAsync(Sentinel));
    }

    [Theory]
    [InlineData("true")]
    [InlineData("TRUE")]
    public async Task Override_BootsABelowFloorDatabase_AndLogsAnError(string value)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await ForgetFloorAsync();
        var log = new ErrorCapturingLogger();

        await new SchemaInitializer(_db, log, config: Override(value)).InitializeAsync();

        Assert.Contains(log.Errors, m => m.Contains("UPGRADE_FLOOR_OVERRIDE", StringComparison.Ordinal)
            && m.Contains("0.13.3", StringComparison.Ordinal));
        Assert.Equal(1, await LedgerCountAsync(Sentinel));
    }

    [Theory]
    [InlineData("false")]
    [InlineData("yes")]
    [InlineData("")]
    public async Task OverrideThatIsNotTrue_DoesNotBypassTheFloor(string value)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await ForgetFloorAsync();

        await Assert.ThrowsAsync<UpgradeFloorException>(
            () => new SchemaInitializer(_db, config: Override(value)).InitializeAsync());
    }

    [Fact]
    public async Task MigrateToPostgresTargetInitializer_HonoursTheOverride()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await ForgetFloorAsync();
        using var loggers = Microsoft.Extensions.Logging.LoggerFactory.Create(_ => { });

        await Assert.ThrowsAsync<UpgradeFloorException>(() => DatabaseMigrationCommand
            .CreateTargetInitializer(_db, Override("false"), loggers, TimeProvider.System).InitializeAsync());
        await DatabaseMigrationCommand
            .CreateTargetInitializer(_db, Override("true"), loggers, TimeProvider.System).InitializeAsync();

        Assert.Equal(1, await LedgerCountAsync(Marker));
    }

    private sealed class ErrorCapturingLogger : ILogger<SchemaInitializer>
    {
        private readonly List<string> _errors = [];

        public IReadOnlyList<string> Errors => _errors;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Error)
            {
                _errors.Add(formatter(state, exception));
            }
        }
    }
}
