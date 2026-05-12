using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Per-test-class fixture that gives each consuming test a fresh in-memory SQLite database
/// with the full production schema applied. Schema init runs once on
/// <see cref="InitializeAsync"/>; the underlying named-shared-cache DB is destroyed in
/// <see cref="DisposeAsync"/>.
///
/// Use via xUnit's <c>IClassFixture&lt;InMemoryDbFixture&gt;</c> for repo tests, or
/// indirectly via <see cref="ControllerScenario"/> for controller tests.
/// </summary>
public sealed class InMemoryDbFixture : IAsyncLifetime
{
    public TestMetadataStore Store { get; } = new();

    public async Task InitializeAsync()
    {
        // The production SchemaInitializer applies CREATE IF NOT EXISTS + additive migrations,
        // so the same code path runs in tests as in prod. SQLite quirks (no IF NOT EXISTS on
        // ADD COLUMN, etc.) are already handled by SchemaInitializer.
        var init = new SchemaInitializer(Store);
        await init.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await Store.DisposeAsync();
    }
}
