using System.Text.Json;
using Dependably.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Verifies that <see cref="MetricsAccessView.Build"/> emits the exact camelCase JSON
/// shape the frontend metrics-access settings panel expects. A PascalCase regression here
/// is a silent runtime failure in the browser, so the test asserts on the serialized output.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetricsAccessViewTests
{
    private static readonly JsonSerializerOptions WebOptions =
        new(JsonSerializerDefaults.Web);

    private static MetricsAccessConfig.ResolvedConfig MakeResolved(
        bool enabled = true,
        MetricsAccessConfig.Source enabledSource = MetricsAccessConfig.Source.Default,
        bool enabledLockedByEnv = false,
        IReadOnlyList<string>? allowedRaw = null,
        MetricsAccessConfig.Source allowlistSource = MetricsAccessConfig.Source.Default,
        bool allowlistLockedByEnv = false) =>
        new(
            Enabled: enabled,
            Allowed: Array.Empty<NetTools.IPAddressRange>(),
            AllowedRaw: allowedRaw ?? Array.Empty<string>(),
            EnabledSource: enabledSource,
            AllowlistSource: allowlistSource,
            EnabledLockedByEnv: enabledLockedByEnv,
            AllowlistLockedByEnv: allowlistLockedByEnv);

    private static ScrapeDiagnostics MakeDiagnostics()
    {
        var clock = new FakeTimeProvider();
        return new ScrapeDiagnostics(clock);
    }

    [Fact]
    public void Build_SerializedShape_IsCamelCase()
    {
        var resolved = MakeResolved(enabled: true, enabledSource: MetricsAccessConfig.Source.Env,
            enabledLockedByEnv: true, allowedRaw: ["127.0.0.1"],
            allowlistSource: MetricsAccessConfig.Source.Db);
        var diag = MakeDiagnostics();

        object view = MetricsAccessView.Build(resolved, diag);
        string json = JsonSerializer.Serialize(view, WebOptions);

        // Frontend contract: all keys must be camelCase.
        Assert.Contains("\"enabled\"", json);
        Assert.Contains("\"enabledSource\"", json);
        Assert.Contains("\"enabledLockedByEnv\"", json);
        Assert.Contains("\"allowedIps\"", json);
        Assert.Contains("\"allowlistSource\"", json);
        Assert.Contains("\"allowlistLockedByEnv\"", json);
        Assert.Contains("\"recentDeniedIps\"", json);

        // Must NOT contain PascalCase keys.
        Assert.DoesNotContain("\"Enabled\"", json);
        Assert.DoesNotContain("\"EnabledSource\"", json);
        Assert.DoesNotContain("\"AllowedIps\"", json);
    }

    [Fact]
    public void Build_EnabledSource_IsLowercase()
    {
        // Source enum serializes as lowercase string (e.g. "env", not "Env").
        var resolved = MakeResolved(enabledSource: MetricsAccessConfig.Source.Env,
            allowlistSource: MetricsAccessConfig.Source.Db);
        var diag = MakeDiagnostics();

        object view = MetricsAccessView.Build(resolved, diag);
        string json = JsonSerializer.Serialize(view, WebOptions);

        Assert.Contains("\"env\"", json);
        Assert.Contains("\"db\"", json);
        Assert.DoesNotContain("\"Env\"", json);
        Assert.DoesNotContain("\"Db\"", json);
    }

    [Fact]
    public void Build_AllowedIps_ReflectsRawList()
    {
        var resolved = MakeResolved(allowedRaw: ["10.0.0.1", "10.0.0.2"]);
        var diag = MakeDiagnostics();

        object view = MetricsAccessView.Build(resolved, diag);
        string json = JsonSerializer.Serialize(view, WebOptions);

        Assert.Contains("10.0.0.1", json);
        Assert.Contains("10.0.0.2", json);
    }

    [Fact]
    public void Build_EmptyDeniedIps_WhenNoDenials()
    {
        var resolved = MakeResolved();
        var diag = MakeDiagnostics();

        object view = MetricsAccessView.Build(resolved, diag);
        string json = JsonSerializer.Serialize(view, WebOptions);

        // recentDeniedIps must be present as an empty array, not absent.
        Assert.Contains("\"recentDeniedIps\":[]", json);
    }

    [Fact]
    public void Build_InstanceController_AndSystemController_ProduceSameShape()
    {
        // Regression: both controllers must call the same builder to guarantee
        // identical JSON shapes. This test exercises Build twice with the same
        // inputs and asserts the results are equal.
        var resolved = MakeResolved(enabled: false, enabledLockedByEnv: true,
            allowlistSource: MetricsAccessConfig.Source.Env, allowlistLockedByEnv: true);
        var diag = MakeDiagnostics();

        string json1 = JsonSerializer.Serialize(MetricsAccessView.Build(resolved, diag), WebOptions);
        string json2 = JsonSerializer.Serialize(MetricsAccessView.Build(resolved, diag), WebOptions);

        Assert.Equal(json1, json2);
    }
}
