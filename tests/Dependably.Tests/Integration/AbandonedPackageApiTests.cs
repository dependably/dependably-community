using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies the "abandoned package" signal (issue #351) is carried on the management API
/// packages-list and package-detail payloads as camelCase <c>abandonedState</c>: "abandoned"
/// (upstream's latest release is >= 365 days old), "active" (published more recently), or
/// "unknown" (no upstream publish timestamp is known yet — never rendered as "abandoned").
///
/// Mixed partial-failure: a single packages-list call spans all three states for different
/// packages in the same org, mirroring how a real org's package list contains a mix.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AbandonedPackageApiTests : IAsyncLifetime
{
    // FrozenClock so the >= 365-day threshold is asserted against a known instant, not wall time.
    // Offsets are deliberately far from the 365-day boundary (400/300 days) — a boundary-exact
    // seed drifts across leap years depending on which year TestTime.KnownNow falls in.
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task PackagesList_AbandonedState_ComputesIndependentlyAcrossMixedBatch()
    {
        string abandonedName = $"abandonedpkg{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string activeName = $"activepkg{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string unknownName = $"unknownpkg{Guid.NewGuid():N}"[..20].ToLowerInvariant();

        await _factory.PushNpmPackage(abandonedName, "1.0.0");
        await _factory.PushNpmPackage(activeName, "1.0.0");
        await _factory.PushNpmPackage(unknownName, "1.0.0");

        string orgId = await GetDefaultOrgIdAsync();
        var packages = _factory.Services.GetRequiredService<PackageRepository>();
        var abandonedPkg = await packages.GetByPurlNameAsync(orgId, "npm", abandonedName);
        var activePkg = await packages.GetByPurlNameAsync(orgId, "npm", activeName);
        await packages.UpdateUpstreamLatestAsync(abandonedPkg!.Id, "1.0.0", Clock.GetUtcNow().AddDays(-400));
        await packages.UpdateUpstreamLatestAsync(activePkg!.Id, "1.0.0", Clock.GetUtcNow().AddDays(-300));
        // unknownName keeps no upstream baseline at all.

        string jwt = await _factory.CreateAdminJwt();
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await admin.GetAsync("/api/v1/packages?ecosystem=npm&limit=200");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var items = doc.RootElement.GetProperty("items").EnumerateArray().ToList();

        string AbandonedStateOf(string purlName) => items
            .First(i => string.Equals(i.GetProperty("purlName").GetString(), purlName, StringComparison.OrdinalIgnoreCase))
            .GetProperty("abandonedState").GetString()!;

        Assert.Equal("abandoned", AbandonedStateOf(abandonedName));
        Assert.Equal("active", AbandonedStateOf(activeName));
        Assert.Equal("unknown", AbandonedStateOf(unknownName));
    }

    [Fact]
    public async Task PackageDetail_AbandonedState_MatchesListDerivation()
    {
        string name = $"detailabandoned{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        await _factory.PushNpmPackage(name, "1.0.0");

        string orgId = await GetDefaultOrgIdAsync();
        var packages = _factory.Services.GetRequiredService<PackageRepository>();
        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", name);
        await packages.UpdateUpstreamLatestAsync(pkg!.Id, "1.0.0", Clock.GetUtcNow().AddDays(-400));

        string jwt = await _factory.CreateAdminJwt();
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await admin.GetAsync($"/api/v1/packages/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        Assert.Equal("abandoned", doc.RootElement.GetProperty("package").GetProperty("abandonedState").GetString());
    }

    private async Task<string> GetDefaultOrgIdAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }
}
