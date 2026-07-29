using Dapper;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the ordering fix for the global Dapper <c>DateTimeOffsetHandler</c> registration
/// (<c>SchemaInitializer.RegisterDateTimeOffsetHandler</c>, <c>[ModuleInitializer]</c>).
///
/// Dapper caches its compiled "add parameters" emitter per <c>(SQL text, parameter CLR type)</c>
/// the first time that exact pair is executed; the decision of whether a bound
/// <see cref="DateTimeOffset"/> goes through <c>DateTimeOffsetHandler.SetValue</c> or the
/// ADO.NET provider's own default serialization is baked in at that first compilation, not
/// re-checked afterwards. A registration tied to a static constructor on <c>SchemaInitializer</c>
/// specifically only fires the first time <em>that type</em> is touched — nothing guarantees that
/// happens before some unrelated query already bound a <see cref="DateTimeOffset"/> and cached
/// the wrong emitter for the rest of the process. A <c>[ModuleInitializer]</c> fires the moment
/// this assembly's module is loaded, before the first member access anywhere in it — including
/// from a caller that never references <see cref="Dependably.Infrastructure.SchemaInitializer"/>
/// at all — so it always wins the race.
///
/// This test never constructs a <c>SchemaInitializer</c> or calls its <c>InitializeAsync</c>: it
/// creates its probe table with raw DDL and binds the <see cref="DateTimeOffset"/> parameter
/// through a call site (and anonymous type) unique to this file, so Dapper is compiling this
/// exact (SQL, type) pair for the first time in the process right here — exactly the scenario a
/// static-constructor-based registration would have lost the race on, and exactly the scenario
/// the module initializer is required to still win.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DateTimeOffsetHandlerModuleInitializerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task DateTimeOffsetParameter_BindsCanonically_WithoutSchemaInitializerEverRunning()
    {
        await using var conn = await _db.OpenAsync();

        // Raw DDL — deliberately not SchemaInitializer.InitializeAsync(), so nothing in this
        // test ever touches the SchemaInitializer type.
        await conn.ExecuteAsync(
            "CREATE TABLE module_initializer_probe (module_initializer_probe_value TEXT)");

        var instant = new DateTimeOffset(2026, 7, 26, 12, 0, 0, TimeSpan.Zero);
        await conn.ExecuteAsync(
            "INSERT INTO module_initializer_probe (module_initializer_probe_value) " +
            "VALUES (@ModuleInitializerProbeValue)",
            new { ModuleInitializerProbeValue = instant });

        string stored = await conn.QuerySingleAsync<string>(
            "SELECT module_initializer_probe_value FROM module_initializer_probe");

        // Canonical UTC "Z" form — not "2026-07-26 12:00:00+00:00", which is what the ADO.NET
        // provider's own default DateTimeOffset serialization produces when the handler never
        // ran for this (SQL, type) pair.
        Assert.Equal("2026-07-26T12:00:00Z", stored);
    }

    [Fact]
    public async Task NonZeroOffsetParameter_NormalizesToUtc_WithoutSchemaInitializerEverRunning()
    {
        await using var conn = await _db.OpenAsync();

        await conn.ExecuteAsync(
            "CREATE TABLE module_initializer_probe_offset (module_initializer_probe_offset_value TEXT)");

        // +02:00 representing 2026-07-26T10:00:00Z.
        var instant = new DateTimeOffset(2026, 7, 26, 12, 0, 0, TimeSpan.FromHours(2));
        await conn.ExecuteAsync(
            "INSERT INTO module_initializer_probe_offset (module_initializer_probe_offset_value) " +
            "VALUES (@ModuleInitializerProbeOffsetValue)",
            new { ModuleInitializerProbeOffsetValue = instant });

        string stored = await conn.QuerySingleAsync<string>(
            "SELECT module_initializer_probe_offset_value FROM module_initializer_probe_offset");

        Assert.Equal("2026-07-26T10:00:00Z", stored);
    }
}
