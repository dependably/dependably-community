using System.Net;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Foundation smoke tests — prove the Phase 1 scaffolding wires up correctly.
/// Phase 2-5 lean on these patterns; if anything here breaks, no downstream phase ships.
/// </summary>
[Trait("Category", "Unit")]
public sealed class FoundationSmokeTests
{
    // ── Pattern A — repo over real SQLite via InMemoryDbFixture ──────────────

    [Fact]
    public async Task InMemoryDbFixture_AppliesSchemaAndOrgSeederWorks()
    {
        await using var fixture = new InMemoryDbFixture();
        await fixture.InitializeAsync();

        var orgId = await OrgSeeder.InsertAsync(fixture.Store, "acme");

        await using var conn = await fixture.Store.OpenAsync();
        var (slug, settingsRows) = await conn.QuerySingleAsync<(string Slug, long SettingsRows)>(
            """
            SELECT o.slug AS Slug,
                   (SELECT COUNT(*) FROM org_settings WHERE org_id = o.id) AS SettingsRows
            FROM orgs o WHERE o.id = @id
            """,
            new { id = orgId });
        Assert.Equal("acme", slug);
        Assert.Equal(1, settingsRows);
    }

    // ── Pattern B — controller via ControllerScenario ────────────────────────

    [Fact]
    public async Task ControllerScenario_BuildsAuthorizedLicenseControllerAndReturnsPolicy()
    {
        await using var scenario = await ControllerScenario.CreateAsync();
        await scenario.WithOrgAsync("acme");
        await scenario.WithUserAsync(role: "owner");
        var built = await scenario.BuildAsync();

        var result = await built.LicenseController.GetPolicy(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);
    }

    [Fact]
    public async Task ControllerScenario_AfterBuild_IsImmutable()
    {
        await using var scenario = await ControllerScenario.CreateAsync();
        await scenario.WithOrgAsync("acme");
        await scenario.WithUserAsync();
        await scenario.BuildAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await scenario.WithOrgAsync("late-add"));
    }

    [Fact]
    public async Task ControllerScenario_UserWithoutOrg_Throws()
    {
        // Explicit relationships rule: WithUser does NOT silently create the org.
        await using var scenario = await ControllerScenario.CreateAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await scenario.WithUserAsync(org: "doesnt-exist"));
    }

    [Fact]
    public async Task ControllerScenario_NegativeHelper_WithNoUser_ProducesAnonymousContext()
    {
        await using var scenario = await ControllerScenario.CreateAsync();
        await scenario.WithOrgAsync("acme");
        scenario.WithNoUser();
        var built = await scenario.BuildAsync();

        // GetPolicy requires authentication — anonymous → 401/403 via the guard.
        var result = await built.LicenseController.GetPolicy(CancellationToken.None);
        var statusCode = result switch
        {
            UnauthorizedResult => HttpStatusCode.Unauthorized,
            ObjectResult o when o.StatusCode == 401 => HttpStatusCode.Unauthorized,
            ObjectResult o when o.StatusCode == 403 => HttpStatusCode.Forbidden,
            ForbidResult => HttpStatusCode.Forbidden,
            ChallengeResult => HttpStatusCode.Unauthorized,
            StatusCodeResult s => (HttpStatusCode)s.StatusCode,
            _ => throw new Xunit.Sdk.XunitException($"Unexpected result type {result.GetType().Name}")
        };
        Assert.True(statusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
    }

    // ── Pattern C — NSubstitute over a blob-store seam ───────────────────────

    [Fact]
    public async Task AzureBlobStore_UploadAsync_CallsContainerUploadWithCorrectKey()
    {
        var container = Substitute.For<IAzureBlobContainer>();
        var sut = new AzureBlobStore(container);

        await using var data = new MemoryStream([1, 2, 3]);
        await sut.PutAsync("proxy/sha256/abc", data);

        await container.Received(1).UploadAsync(
            "proxy/sha256/abc",
            Arg.Any<Stream>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AzureBlobStore_GetTotalSizeAsync_SumsAllPages()
    {
        var container = Substitute.For<IAzureBlobContainer>();
        // Two pages of sizes — adapter iterates both and sums.
        container.EnumerateSizesAsync(Arg.Any<CancellationToken>())
            .Returns(AsyncEnum(100L, 250L, 50L));

        var total = await new AzureBlobStore(container).GetTotalSizeAsync();

        Assert.Equal(400, total);
    }

    private static async IAsyncEnumerable<long> AsyncEnum(params long[] values)
    {
        foreach (var v in values) { await Task.Yield(); yield return v; }
    }
}
