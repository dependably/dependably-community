using Dapper;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Xunit;

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
        var value = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes'");
        Assert.Equal("2097152", value);

        var auditCount = await conn.ExecuteScalarAsync<long>(
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
        var legitWritten = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM instance_settings WHERE key = 'max_upload_bytes'");
        Assert.Equal(0, legitWritten);
    }

    [Theory]
    [InlineData("max_upload_bytes_pypi", "1024")]
    [InlineData("max_upload_bytes_npm",  "2048")]
    [InlineData("max_upload_bytes_nuget", "4096")]
    [InlineData("gc_schedule", "0 4 * * *")]
    [InlineData("siem_max_lookback_days", "60")]
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
