using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

[Trait("Category", "Unit")]
public sealed class InstanceControllerUnitTests
{
    [Fact]
    public async Task GetSettings_Owner_Returns200_AndOmitsJwtSecret()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Seed both a public + a secret instance setting.
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', 'DO-NOT-LEAK')");
            await conn.ExecuteAsync(
                "INSERT INTO instance_settings (key, value) VALUES ('max_upload_bytes', '1048576') ON CONFLICT(key) DO UPDATE SET value = '1048576'");
        }

        var result = await b.InstanceController.GetSettings(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);

        // ListInstanceSettingsAsync returns Dictionary<string, string>.
        var dict = Assert.IsAssignableFrom<IReadOnlyDictionary<string, string>>(ok.Value);
        Assert.False(dict.ContainsKey("jwt_secret"));
        Assert.Equal("1048576", dict["max_upload_bytes"]);
    }

    [Fact]
    public async Task GetSettings_Anonymous_Denied()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.InstanceController.GetSettings(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task GetSettings_Member_Forbidden()
    {
        // tenant:admin is owner-only — a member is rejected.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.InstanceController.GetSettings(CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task UpdateSettings_Owner_PersistsAndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.InstanceController.UpdateSettings(
            new Dictionary<string, string> { ["max_upload_bytes"] = "2097152" },
            CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        string? value = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes'");
        Assert.Equal("2097152", value);

        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'instance_settings_updated'");
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task UpdateSettings_RejectsUnknownKey_BeforeAnyWrite()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.InstanceController.UpdateSettings(
            new Dictionary<string, string>
            {
                ["max_upload_bytes"] = "1048576",
                ["unknown_key"] = "nope",
            },
            CancellationToken.None);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.NotNull(bad.Value);

        // No row written — failure is atomic at the validation layer.
        await using var conn = await b.Db.OpenAsync();
        long legitWritten = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM instance_settings WHERE key = 'max_upload_bytes'");
        Assert.Equal(0, legitWritten);
    }

    [Theory]
    [InlineData("max_upload_bytes_pypi", "1024")]
    [InlineData("max_upload_bytes_npm", "2048")]
    [InlineData("max_upload_bytes_nuget", "4096")]
    [InlineData("max_upload_bytes_maven", "8192")]
    [InlineData("max_upload_bytes_rpm", "16384")]
    [InlineData("max_upload_bytes_oci", "32768")]
    [InlineData("gc_schedule", "0 4 * * *")]
    [InlineData("siem_max_lookback_days", "60")]
    [InlineData("default_storage_quota_bytes", "1073741824")]
    [InlineData("max_active_tokens_per_tenant", "250")]
    public async Task UpdateSettings_AcceptsEachAllowedKey(string key, string value)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.InstanceController.UpdateSettings(
            new Dictionary<string, string> { [key] = value }, CancellationToken.None);
        Assert.IsType<NoContentResult>(result);
    }
}

/// <summary>
/// Unit-level predicate tests for the deployment-mode gate on InstanceController.
/// The 404 is returned before any auth or DB call, so no seeded tenant or user is needed —
/// only a real in-memory DB (to satisfy the concrete repository constructors) and the
/// appropriate DEPLOYMENT_MODE config entry.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InstanceControllerModePredicateTests : IAsyncLifetime
{
    private readonly InMemoryDbFixture _db = new();

    public Task InitializeAsync() => _db.InitializeAsync();
    public Task DisposeAsync() => _db.DisposeAsync();

    private static IConfiguration Cfg(string mode) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPLOYMENT_MODE"] = mode })
            .Build();

    private InstanceController Build(string mode)
    {
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsEnabled.Returns(false);
        airGap.DisabledJobs.Returns((IReadOnlySet<string>)new HashSet<string>());
        airGap.IsJobDisabled(Arg.Any<string>()).Returns(false);

        var ctrl = new InstanceController(
            new OrgRepository(_db.Store),
            new AuditRepository(_db.Store),
            new OrgAccessGuard(_db.Store),
            airGap,
            new BackgroundJobRunRepository(_db.Store),
            Cfg(mode))
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() },
        };
        return ctrl;
    }

    [Theory]
    [InlineData("multi")]
    [InlineData("header")]
    public async Task MultiTenantModes_GetSettings_Returns404(string mode)
    {
        var result = await Build(mode).GetSettings(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Theory]
    [InlineData("multi")]
    [InlineData("header")]
    public async Task MultiTenantModes_UpdateSettings_Returns404(string mode)
    {
        var result = await Build(mode).UpdateSettings(
            new Dictionary<string, string> { ["max_upload_bytes"] = "1024" },
            CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Theory]
    [InlineData("multi")]
    [InlineData("header")]
    public async Task MultiTenantModes_GetBackgroundJobs_Returns404(string mode)
    {
        var result = await Build(mode).GetBackgroundJobs(CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Theory]
    [InlineData("single")]
    [InlineData("bound")]
    public async Task SingleTenantModes_GetSettings_DoesNotReturn404(string mode)
    {
        // In single/bound mode the _isMultiMode gate does not fire.  The controller
        // proceeds to OrgAccessGuard.AuthorizeCapAsync, which needs a TenantContext in
        // HttpContext.Items to reach the auth check.  Without one the guard also returns
        // NotFound (unknown org), so we seed a minimal TenantContext for the default org.
        // With no authenticated user the guard then returns Unauthorized, proving the
        // mode gate was not what fired.
        var ctrl = Build(mode);
        ctrl.ControllerContext.HttpContext.Items[TenantContext.HttpItemsKey] =
            TenantContext.ForTenant("default", "default");
        var result = await ctrl.GetSettings(CancellationToken.None);
        Assert.IsNotType<NotFoundResult>(result);
    }
}
