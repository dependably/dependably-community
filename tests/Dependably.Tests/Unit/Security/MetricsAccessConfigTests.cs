using Dependably.Security;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Covers the env → DB → default precedence chain in
/// <see cref="MetricsAccessConfig"/>, plus JSON parsing, cache TTL, and
/// explicit invalidation. The instance-setting reader is mocked as a
/// dictionary so the tests don't need a real DB.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetricsAccessConfigTests
{
    private static MetricsAccessConfig Build(
        Dictionary<string, string?>? envVars = null,
        Dictionary<string, string?>? dbValues = null)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(envVars ?? new())
            .Build();

        var db = dbValues ?? new Dictionary<string, string?>();
        Task<string?> Reader(string key, CancellationToken _) =>
            Task.FromResult(db.TryGetValue(key, out string? v) ? v : null);

        return new MetricsAccessConfig(Reader, config);
    }

    [Fact]
    public async Task EnvAllowlist_WinsOverDb()
    {
        var sut = Build(
            envVars: new() { ["METRICS_ALLOWED_IPS"] = "10.0.0.0/8" },
            dbValues: new() { ["metrics_allowed_ips"] = "[\"172.16.0.0/12\"]" });
        var r = await sut.ResolveAsync();

        Assert.Equal(MetricsAccessConfig.Source.Env, r.AllowlistSource);
        Assert.True(r.AllowlistLockedByEnv);
        Assert.Single(r.AllowedRaw);
        Assert.Equal("10.0.0.0/8", r.AllowedRaw[0]);
    }

    [Fact]
    public async Task DbAllowlist_UsedWhenEnvUnset()
    {
        var sut = Build(
            dbValues: new() { ["metrics_allowed_ips"] = "[\"172.16.0.0/12\"]" });
        var r = await sut.ResolveAsync();

        Assert.Equal(MetricsAccessConfig.Source.Db, r.AllowlistSource);
        Assert.False(r.AllowlistLockedByEnv);
        Assert.Equal("172.16.0.0/12", r.AllowedRaw[0]);
    }

    [Fact]
    public async Task DefaultAllowlist_WhenNeitherEnvNorDbSet()
    {
        var sut = Build();
        var r = await sut.ResolveAsync();

        Assert.Equal(MetricsAccessConfig.Source.Default, r.AllowlistSource);
        Assert.False(r.AllowlistLockedByEnv);
        Assert.Contains("127.0.0.1", r.AllowedRaw);
        Assert.Contains("::1", r.AllowedRaw);
    }

    [Fact]
    public async Task EnvEnabled_WinsOverDb()
    {
        var sut = Build(
            envVars: new() { ["METRICS_ENABLED"] = "0" },
            dbValues: new() { ["metrics_enabled"] = "1" });
        var r = await sut.ResolveAsync();

        Assert.False(r.Enabled);
        Assert.Equal(MetricsAccessConfig.Source.Env, r.EnabledSource);
        Assert.True(r.EnabledLockedByEnv);
    }

    [Fact]
    public async Task DefaultEnabled_IsTrue()
    {
        var sut = Build();
        var r = await sut.ResolveAsync();

        Assert.True(r.Enabled);
        Assert.Equal(MetricsAccessConfig.Source.Default, r.EnabledSource);
    }

    [Fact]
    public async Task DbEnabledZero_DisablesMetrics()
    {
        var sut = Build(dbValues: new() { ["metrics_enabled"] = "0" });
        var r = await sut.ResolveAsync();

        Assert.False(r.Enabled);
        Assert.Equal(MetricsAccessConfig.Source.Db, r.EnabledSource);
    }

    [Fact]
    public async Task MalformedDbJson_FallsBackToDefault()
    {
        var sut = Build(
            dbValues: new() { ["metrics_allowed_ips"] = "not valid json" });
        var r = await sut.ResolveAsync();

        Assert.Equal(MetricsAccessConfig.Source.Default, r.AllowlistSource);
        Assert.Contains("127.0.0.1", r.AllowedRaw);
    }

    [Fact]
    public async Task CsvEnvAllowlist_Parses()
    {
        var sut = Build(
            envVars: new() { ["METRICS_ALLOWED_IPS"] = "10.0.0.0/8, 192.168.0.0/16, ::1" });
        var r = await sut.ResolveAsync();

        Assert.Equal(3, r.AllowedRaw.Count);
        Assert.Equal(3, r.Allowed.Count);
    }

    [Theory]
    // Truthy variants — the switch arms list canonical forms; each must resolve to enabled=true.
    [InlineData("1", true)]
    [InlineData("true", true)]
    [InlineData("True", true)]
    [InlineData("TRUE", true)]
    // Falsy variants
    [InlineData("0", false)]
    [InlineData("false", false)]
    [InlineData("False", false)]
    [InlineData("FALSE", false)]
    public async Task EnvEnabled_RecognizedVariants(string raw, bool expected)
    {
        var sut = Build(envVars: new() { ["METRICS_ENABLED"] = raw });
        var r = await sut.ResolveAsync();
        Assert.Equal(expected, r.Enabled);
    }

    [Fact]
    public async Task EnvEnabled_UnrecognizedValue_UsesFallbackTrue()
    {
        // The ParseBool switch falls through on unrecognized text and returns the
        // caller-supplied fallback (true in the env branch).
        var sut = Build(envVars: new() { ["METRICS_ENABLED"] = "yes-please" });
        var r = await sut.ResolveAsync();
        Assert.True(r.Enabled);
    }

    [Fact]
    public async Task DbEnabled_UnrecognizedValue_UsesFallbackTrue()
    {
        // Same fallback path on the DB branch — non-canonical text resolves to true.
        var sut = Build(dbValues: new() { ["metrics_enabled"] = "nah" });
        var r = await sut.ResolveAsync();
        Assert.True(r.Enabled);
        Assert.Equal(MetricsAccessConfig.Source.Db, r.EnabledSource);
    }

    [Fact]
    public async Task EnvAllowlist_MalformedCidrEntries_SilentlyDropped()
    {
        // ParseCsv splits all three entries into AllowedRaw, but IPAddressRange.TryParse
        // rejects the middle one — only the two valid ranges land in Allowed.
        var sut = Build(envVars: new()
        {
            ["METRICS_ALLOWED_IPS"] = "10.0.0.0/8, not-a-cidr, 192.168.0.0/16",
        });
        var r = await sut.ResolveAsync();

        Assert.Equal(3, r.AllowedRaw.Count);
        Assert.Equal(2, r.Allowed.Count);
    }

    [Fact]
    public async Task DbAllowlist_NullJsonValue_FallsBackToDefault()
    {
        // The JsonSerializer.Deserialize<string[]> returns null for "null" — TryParseJsonArray
        // returns false and the resolver falls through to the default allowlist.
        var sut = Build(dbValues: new() { ["metrics_allowed_ips"] = "null" });
        var r = await sut.ResolveAsync();

        Assert.Equal(MetricsAccessConfig.Source.Default, r.AllowlistSource);
        Assert.Contains("127.0.0.1", r.AllowedRaw);
    }

    [Fact]
    public async Task DbAllowlist_EmptyJsonArray_UsedWithNoEntries()
    {
        // An explicit [] is valid JSON — it overrides the default allowlist with an empty set
        // (effectively denying all IPs). Source should be Db, not Default.
        var sut = Build(dbValues: new() { ["metrics_allowed_ips"] = "[]" });
        var r = await sut.ResolveAsync();

        Assert.Equal(MetricsAccessConfig.Source.Db, r.AllowlistSource);
        Assert.Empty(r.AllowedRaw);
        Assert.Empty(r.Allowed);
    }

    [Fact]
    public async Task Invalidate_ForcesRefresh()
    {
        var db = new Dictionary<string, string?> { ["metrics_enabled"] = "1" };
        Task<string?> Reader(string key, CancellationToken _) =>
            Task.FromResult(db.TryGetValue(key, out string? v) ? v : null);

        var sut = new MetricsAccessConfig(
            Reader,
            new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build());

        var first = await sut.ResolveAsync();
        Assert.True(first.Enabled);

        // Mutate the underlying DB value AFTER initial resolve.
        db["metrics_enabled"] = "0";

        // Without invalidate, the 5s cache still holds the old value.
        var cached = await sut.ResolveAsync();
        Assert.True(cached.Enabled);

        sut.Invalidate();
        var refreshed = await sut.ResolveAsync();
        Assert.False(refreshed.Enabled);
    }
}
