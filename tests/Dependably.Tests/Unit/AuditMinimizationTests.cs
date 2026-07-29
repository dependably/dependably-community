using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// The audit write path's two data-minimization knobs. Both are opt-in: an audit trail exists to
/// attribute, and degrading that for every deployment would swap one compliance posture for
/// another without the operator choosing. These tests pin the default (full precision) as firmly
/// as the opted-in behaviour — a knob that silently became the default would be the regression.
///
/// Scope matters here: this is the audit WRITE path only. Rate-limit partition keys aggregate for
/// an unrelated reason at an unrelated prefix, and must not move with these settings.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditMinimizationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── The masking helper ───────────────────────────────────────────────────

    [Theory]
    [InlineData("192.0.2.147", "192.0.2.0/24")]
    [InlineData("10.1.2.3", "10.1.2.0/24")]
    [InlineData("2001:db8:1:2:3:4:5:6", "2001:db8:1::/48")]
    [InlineData("::ffff:192.0.2.147", "192.0.2.0/24")]
    public void Minimization_MasksTheHostPortion(string input, string expected)
        => Assert.Equal(expected, IpAddressExtensions.NormalizeForAuditMinimization(IPAddress.Parse(input)));

    /// <summary>
    /// The minimized form and the rate-limit partition form are different answers to different
    /// questions, and must not be quietly unified: rate limiting keeps IPv4 at full precision (the
    /// per-host budget is the point) and collapses IPv6 only to /64.
    /// </summary>
    [Fact]
    public void Minimization_IsNotTheRateLimitPartitionForm()
    {
        var v4 = IPAddress.Parse("192.0.2.147");
        Assert.Equal("192.0.2.147", IpAddressExtensions.NormalizeForRateLimit(v4));
        Assert.Equal("192.0.2.0/24", IpAddressExtensions.NormalizeForAuditMinimization(v4));

        var v6 = IPAddress.Parse("2001:db8:1:2:3:4:5:6");
        Assert.Equal("2001:db8:1:2::/64", IpAddressExtensions.NormalizeForRateLimit(v6));
        Assert.Equal("2001:db8:1::/48", IpAddressExtensions.NormalizeForAuditMinimization(v6));
    }

    // ── The write path ───────────────────────────────────────────────────────

    [Fact]
    public async Task ByDefault_TheFullAddressAndUserAgentAreRecorded()
    {
        var (SourceIp, UserAgent, _) = await EmitAndReadAsync(new Dictionary<string, string?>());

        Assert.Equal("192.0.2.147", SourceIp);
        Assert.Equal("probe/1.0", UserAgent);
    }

    [Fact]
    public async Task WithTruncationOn_OnlyTheNetworkIsRecorded_AndTheUserAgentIsUntouched()
    {
        var (SourceIp, UserAgent, _) = await EmitAndReadAsync(new Dictionary<string, string?> { ["AUDIT_TRUNCATE_IP"] = "true" });

        Assert.Equal("192.0.2.0/24", SourceIp);
        // The two knobs are independent — turning one on must not move the other.
        Assert.Equal("probe/1.0", UserAgent);
    }

    [Fact]
    public async Task WithUserAgentDisabled_NoneIsRecorded_AndTheAddressIsUntouched()
    {
        var (SourceIp, UserAgent, _) = await EmitAndReadAsync(new Dictionary<string, string?> { ["AUDIT_DISABLE_USER_AGENT"] = "true" });

        Assert.Null(UserAgent);
        Assert.Equal("192.0.2.147", SourceIp);
    }

    [Fact]
    public async Task BothOn_RecordsNeitherTheHostNorTheClient()
    {
        var (SourceIp, UserAgent, ActorId) = await EmitAndReadAsync(new Dictionary<string, string?>
        {
            ["AUDIT_TRUNCATE_IP"] = "true",
            ["AUDIT_DISABLE_USER_AGENT"] = "true",
        });

        Assert.Equal("192.0.2.0/24", SourceIp);
        Assert.Null(UserAgent);
        // The event itself still lands — minimization removes detail, never the record.
        Assert.Equal("u1", ActorId);
    }

    // ── Harness ──────────────────────────────────────────────────────────────

    private async Task<(string? SourceIp, string? UserAgent, string? ActorId)> EmitAndReadAsync(
        Dictionary<string, string?> settings)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        var http = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        http.HttpContext!.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.147");
        http.HttpContext.Request.Headers.UserAgent = "probe/1.0";

        var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var emitter = new AuditEmitter(
            new AuditEventRepository(_db), http, NullLogger<AuditEmitter>.Instance,
            config, services, new OrgRepository(_db), TestTime.Frozen());

        await emitter.EmitAsync(
            eventType: "package.publish", orgId: "o1", actorType: "user", actorId: "u1",
            outcome: "accepted", payloadJson: """{"ecosystem":"npm"}""", ct: default);

        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<(string?, string?, string?)>(
            "SELECT source_ip, user_agent, actor_id FROM audit_event WHERE org_id = 'o1'");
    }
}
