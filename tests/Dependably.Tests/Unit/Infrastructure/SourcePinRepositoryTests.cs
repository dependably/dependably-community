using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for <see cref="SourcePinRepository"/>: first-serve-wins pinning of a package name
/// to its serving upstream host, mismatch detection for a different upstream, per-org isolation,
/// and the PROXY_SOURCE_PINNING off switch.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SourcePinRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'beta')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private SourcePinRepository Build(bool enabled = true)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            { ["PROXY_SOURCE_PINNING"] = enabled ? "true" : "false" })
            .Build();
        return new SourcePinRepository(_db, config);
    }

    [Fact]
    public void Enabled_DefaultsOff_AndRespectsOnSwitch()
    {
        Assert.False(new SourcePinRepository(_db, new ConfigurationBuilder().Build()).Enabled);
        Assert.True(Build(enabled: true).Enabled);
    }

    [Fact]
    public async Task PinIfAbsentAsync_FirstServe_BindsNameToHost()
    {
        var repo = Build();

        string winner = await repo.PinIfAbsentAsync("o1", "npm", "left-pad", "https://private.example");
        Assert.Equal("https://private.example", winner);
        Assert.Equal("https://private.example", await repo.GetPinnedHostAsync("o1", "npm", "left-pad"));
    }

    [Fact]
    public async Task PinIfAbsentAsync_DifferentHostAfterPin_ReturnsOriginalHost()
    {
        var repo = Build();
        await repo.PinIfAbsentAsync("o1", "npm", "left-pad", "https://private.example");

        // A second upstream trying to bind the same name loses — the original pin is returned so
        // the caller detects the mismatch and refuses the serve.
        string winner = await repo.PinIfAbsentAsync("o1", "npm", "left-pad", "https://registry.npmjs.org");
        Assert.Equal("https://private.example", winner);
    }

    [Fact]
    public async Task Pins_AreIsolatedPerOrgAndEcosystem()
    {
        var repo = Build();
        await repo.PinIfAbsentAsync("o1", "npm", "shared-name", "https://private.example");

        // Different org: unpinned.
        Assert.Null(await repo.GetPinnedHostAsync("o2", "npm", "shared-name"));
        // Different ecosystem, same org/name: unpinned.
        Assert.Null(await repo.GetPinnedHostAsync("o1", "pypi", "shared-name"));

        // A different org can pin the same name to its own upstream independently.
        string winner = await repo.PinIfAbsentAsync("o2", "npm", "shared-name", "https://registry.npmjs.org");
        Assert.Equal("https://registry.npmjs.org", winner);
    }

    [Fact]
    public async Task GetPinnedHostAsync_UnknownName_ReturnsNull()
    {
        var repo = Build();
        Assert.Null(await repo.GetPinnedHostAsync("o1", "npm", "never-seen"));
    }
}
