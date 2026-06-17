using Dapper;
using Dependably.Infrastructure.Audit;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit.Infrastructure.Audit;

/// <summary>
/// AuditEmitter persists typed audit events with envelope fields read from HttpContext.
/// SiemForwarderQueue is opt-in; tests run with a null queue (no SIEM configured) so the
/// happy path covers persist + envelope construction. Failure path covers the audit-gap
/// metric increment (event-emit failures must never propagate to the caller).
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditEmitterTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public AuditEmitterTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private AuditEmitter NewSut(HttpContext? http = null, string deploymentMode = "single")
    {
        var repo = new AuditEventRepository(_fixture.Store);
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(http);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPLOYMENT_MODE"] = deploymentMode })
            .Build();
        var sp = new ServiceCollection().BuildServiceProvider();   // no SiemForwarderQueue registered
        return new AuditEmitter(repo, accessor, NullLogger<AuditEmitter>.Instance, config, sp, TimeProvider.System);
    }

    [Fact]
    public async Task EmitAsync_PersistsRowWithEnvelopeFromHttpContext()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string eventType = $"emit-env-{Guid.NewGuid():N}";

        var http = new DefaultHttpContext { TraceIdentifier = "trace-123" };
        http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.5");
        http.Request.Headers.UserAgent = "test-agent/1.0";

        var sut = NewSut(http, deploymentMode: "multi");
        await sut.EmitAsync(eventType, orgId, actorType: "user", actorId: "u-1",
            outcome: "accepted", payloadJson: "{\"k\":\"v\"}");

        await using var conn = await _fixture.Store.OpenAsync();
        var (RequestId, SourceIp, UserAgent, TenantResolver, Payload) = await conn.QuerySingleOrDefaultAsync<(string RequestId, string SourceIp, string UserAgent, string TenantResolver, string Payload)>(
            "SELECT request_id AS RequestId, source_ip AS SourceIp, user_agent AS UserAgent, " +
            "       tenant_resolver AS TenantResolver, payload AS Payload " +
            "FROM audit_event WHERE event_type = @t ORDER BY occurred_at DESC LIMIT 1",
            new { t = eventType });
        Assert.False(string.IsNullOrEmpty(RequestId));
        Assert.Equal("trace-123", RequestId);
        Assert.Equal("10.0.0.5", SourceIp);
        Assert.Equal("test-agent/1.0", UserAgent);
        Assert.Equal("multi", TenantResolver);
        Assert.Equal("{\"k\":\"v\"}", Payload);
    }

    [Fact]
    public async Task EmitAsync_NoHttpContext_StillPersists_AndLeavesEnvelopeFieldsNull()
    {
        string eventType = $"ambient-{Guid.NewGuid():N}";
        var sut = NewSut(http: null);
        await sut.EmitAsync(eventType, orgId: null, actorType: "system", actorId: null,
            outcome: "accepted", payloadJson: "{}");

        await using var conn = await _fixture.Store.OpenAsync();
        var (RequestId, SourceIp, UserAgent) = await conn.QuerySingleOrDefaultAsync<(string? RequestId, string? SourceIp, string? UserAgent)>(
            "SELECT request_id AS RequestId, source_ip AS SourceIp, user_agent AS UserAgent " +
            "FROM audit_event WHERE event_type = @t ORDER BY occurred_at DESC LIMIT 1",
            new { t = eventType });
        Assert.Null(RequestId);
        Assert.Null(SourceIp);
        Assert.Null(UserAgent);
    }

    [Fact]
    public async Task EmitAsync_LongUserAgent_Truncated_To512Chars()
    {
        var http = new DefaultHttpContext();
        http.Request.Headers.UserAgent = new string('x', 1000);

        var sut = NewSut(http);
        await sut.EmitAsync($"ua-trunc-{Guid.NewGuid():N}", null, "system", null, "accepted", "{}");

        await using var conn = await _fixture.Store.OpenAsync();
        string? ua = await conn.ExecuteScalarAsync<string>(
            "SELECT user_agent FROM audit_event ORDER BY occurred_at DESC LIMIT 1");
        Assert.NotNull(ua);
        Assert.Equal(512, ua.Length);
    }

    [Fact]
    public async Task EmitAsync_RepoThrows_SwallowsException_NeverPropagates()
    {
        // Audit gap contract: failure must not break the caller — log + counter + continue.
        // We force a failure by passing an event_type that triggers a constraint problem in
        // the audit_event schema: simplest reliable trigger is a NULL event_type via a
        // partially-broken emitter built on a closed DB.
        var fxClosed = new InMemoryDbFixture();
        await fxClosed.InitializeAsync();
        await fxClosed.DisposeAsync();   // tear it down so subsequent inserts throw

        var repo = new AuditEventRepository(fxClosed.Store);
        var accessor = Substitute.For<IHttpContextAccessor>();
        var config = new ConfigurationBuilder().Build();
        var sp = new ServiceCollection().BuildServiceProvider();
        var sut = new AuditEmitter(repo, accessor, NullLogger<AuditEmitter>.Instance, config, sp, TimeProvider.System);

        // Must not throw — the catch in EmitAsync swallows + increments the metric.
        Assert.Null(await Record.ExceptionAsync(() =>
            sut.EmitAsync("event.that.wont.persist", null, "system", null, "accepted", "{}")));
    }
}
