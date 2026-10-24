using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The <c>oci_scan_enforcement</c> field on <c>/api/v1/proxy-settings</c>: default off, round trip,
/// leave-unchanged-on-absent, vocabulary validation, and the refusal to move off 'off' while the
/// instance runs no image scanning or the org's scanner has never called the scan API (every
/// image would then be unscanned).
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanEnforcementSettingsTests : IAsyncLifetime
{
    private readonly DependablyFactory _enabled = new()
    {
        FrozenClock = TestTime.Frozen(),
        ExtraSettings = new Dictionary<string, string?> { ["OCI_SCAN_ENABLED"] = "true" },
    };

    private readonly DependablyFactory _disabled = new() { FrozenClock = TestTime.Frozen() };

    public async Task InitializeAsync()
    {
        await _enabled.InitializeAsync();
        await _disabled.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _enabled.DisposeAsync();
        await _disabled.DisposeAsync();
    }

    private static async Task<HttpClient> AdminAsync(DependablyFactory factory)
    {
        var c = factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await factory.CreateAdminJwt());
        return c;
    }

    private static async Task<JsonElement> GetAsync(HttpClient c)
    {
        using var resp = await c.GetAsync("/api/v1/proxy-settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    [Fact]
    public async Task Default_IsOff_AndTheInstanceFlagIsReported()
    {
        using var c = await AdminAsync(_enabled);
        var body = await GetAsync(c);
        Assert.Equal("off", body.GetProperty("oci_scan_enforcement").GetString());
        Assert.True(body.GetProperty("oci_scan_enabled").GetBoolean());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("oci_scanner_last_seen_at").ValueKind);

        using var d = await AdminAsync(_disabled);
        Assert.False((await GetAsync(d)).GetProperty("oci_scan_enabled").GetBoolean());
    }

    [Fact]
    public async Task Get_ReportsWhenTheScannerLastCalled()
    {
        var at = _enabled.FrozenClock!.GetUtcNow().AddDays(-3);
        await OciScanSeeder.ScannerSeenAsync(Db(_enabled), await OrgIdAsync(_enabled), at);

        using var c = await AdminAsync(_enabled);
        Assert.Equal(at.ToUtcIsoMillis(), (await GetAsync(c)).GetProperty("oci_scanner_last_seen_at").GetString());
    }

    [Fact]
    public async Task Get_ReportsNoScanner_WhileScanningIsDisabled_EvenWithAScannerRow()
    {
        // A scanner row left from before the instance flag was cleared is not a usable scanner.
        await OciScanSeeder.ScannerSeenAsync(Db(_disabled), await OrgIdAsync(_disabled), _disabled.FrozenClock!.GetUtcNow());

        using var c = await AdminAsync(_disabled);
        Assert.Equal(JsonValueKind.Null, (await GetAsync(c)).GetProperty("oci_scanner_last_seen_at").ValueKind);
        using var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = "block" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, put.StatusCode);
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task Put_RefusesAMoveOffOff_WhenTheOrgsScannerHasNeverCalled(string value)
    {
        using var c = await AdminAsync(_enabled);
        using var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = value });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, put.StatusCode);
        Assert.Contains("oci_scan_enforcement", await put.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal("off", (await GetAsync(c)).GetProperty("oci_scan_enforcement").GetString());
    }

    [Fact]
    public async Task Put_AcceptsBlock_OnceTheScannerHasCalled_EvenIfItIsNoLongerLive()
    {
        // A scanner that called once and stopped leaves the org failing closed under block; the
        // check only keeps an org that never had a scanner from refusing every pull.
        var stale = _enabled.FrozenClock!.GetUtcNow().AddDays(-30);
        await OciScanSeeder.ScannerSeenAsync(Db(_enabled), await OrgIdAsync(_enabled), stale);

        using var c = await AdminAsync(_enabled);
        using var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = "block" });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    [InlineData("off")]
    public async Task Put_RoundTrips_WhenScanningIsEnabled(string value)
    {
        await ScannerSeenAsync(_enabled);
        using var c = await AdminAsync(_enabled);
        using var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = value });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
        Assert.Equal(value, (await GetAsync(c)).GetProperty("oci_scan_enforcement").GetString());
    }

    [Fact]
    public async Task Put_LeavesTheStoredValue_WhenTheFieldIsAbsent()
    {
        await ScannerSeenAsync(_enabled);
        using var c = await AdminAsync(_enabled);
        using (var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = "block" }))
        {
            Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
        }

        // A partial PUT addressing an unrelated field must not reset an enforcing gate.
        using (var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { blockKev = "warn" }))
        {
            Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
        }

        Assert.Equal("block", (await GetAsync(c)).GetProperty("oci_scan_enforcement").GetString());
    }

    [Fact]
    public async Task Put_RejectsAnUnknownValue()
    {
        using var c = await AdminAsync(_enabled);
        using var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = "block_all" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, put.StatusCode);
        Assert.Contains("oci_scan_enforcement", await put.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal("off", (await GetAsync(c)).GetProperty("oci_scan_enforcement").GetString());
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task Put_RefusesAMoveOffOff_WhenTheInstanceRunsNoScanner(string value)
    {
        using var c = await AdminAsync(_disabled);
        using var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = value });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, put.StatusCode);
        Assert.Contains("oci_scan_enforcement", await put.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal("off", (await GetAsync(c)).GetProperty("oci_scan_enforcement").GetString());
    }

    [Fact]
    public async Task Put_StillAcceptsOff_WhenTheInstanceRunsNoScanner()
    {
        using var c = await AdminAsync(_disabled);
        using var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = "off" });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
    }

    [Theory]
    [InlineData("block")]
    [InlineData("warn")]
    public async Task Put_AcceptsReSendingTheStoredValue_WhenTheInstanceRunsNoScanner(string stored)
    {
        using var c = await AdminAsync(_disabled);
        await StoreAsync(_disabled, stored);

        // An unrelated-tab save re-sends the stored posture unchanged; it is not a move.
        using var same = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = stored, blockKev = "warn" });
        Assert.Equal(HttpStatusCode.NoContent, same.StatusCode);
        Assert.Equal(stored, (await GetAsync(c)).GetProperty("oci_scan_enforcement").GetString());

        // A different non-off value is still a move off 'off' semantics-wise and stays refused.
        string other = stored == "block" ? "warn" : "block";
        using var move = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = other });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, move.StatusCode);

        // Moving to off is always allowed.
        using var off = await c.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = "off" });
        Assert.Equal(HttpStatusCode.NoContent, off.StatusCode);
    }

    // Reaching into the host's services as the test harness, so reads run as the owner under
    // row-level security rather than as an undeclared background tenant.
    private static IMetadataStore Db(DependablyFactory factory)
    {
        TestHarnessDbScope.Enter();
        return factory.Services.GetRequiredService<IMetadataStore>();
    }

    private static async Task<string> OrgIdAsync(DependablyFactory factory)
    {
        await using var conn = await Db(factory).OpenAsync();
        return await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs LIMIT 1") ?? throw new InvalidOperationException("no org");
    }

    private static async Task ScannerSeenAsync(DependablyFactory factory) =>
        await OciScanSeeder.ScannerSeenAsync(Db(factory), await OrgIdAsync(factory), factory.FrozenClock!.GetUtcNow());

    private static async Task StoreAsync(DependablyFactory factory, string value)
    {
        string orgId = await OrgIdAsync(factory);
        await using var conn = await Db(factory).OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, oci_scan_enforcement) VALUES (@orgId, @value)
            ON CONFLICT(org_id) DO UPDATE SET oci_scan_enforcement = @value
            """,
            new { orgId, value });
        factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }
}
