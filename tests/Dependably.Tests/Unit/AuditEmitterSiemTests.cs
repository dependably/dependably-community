using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Siem;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// AuditEmitter must enqueue every persisted event to the optional
/// <see cref="SiemForwarderQueue"/>. Without this wiring the entire outbound SIEM
/// path is dead weight — this test exists so future refactors that drop the
/// enqueue (eg. by accident during DI cleanup) fail loudly.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditEmitterSiemTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private sealed class CapturingForwarder : ISiemForwarder
    {
        public string Name => "capture";
        public List<SiemEvent> Sent { get; } = [];
        public Task SendAsync(SiemEvent ev, CancellationToken ct)
        {
            lock (Sent) Sent.Add(ev);
            return Task.CompletedTask;
        }
    }

    private static IConfiguration EmptyConfig() =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();

    [Fact]
    public async Task EmitAsync_WithSiemQueueRegistered_ForwardsEventDownstream()
    {
        var forwarder = new CapturingForwarder();
        var services = new ServiceCollection()
            .AddSingleton<ISiemForwarder>(forwarder)
            .AddSingleton<SiemForwarderQueue>()
            .AddSingleton(EmptyConfig())
            .AddLogging()
            .BuildServiceProvider();

        var queue = services.GetRequiredService<SiemForwarderQueue>();
        await queue.StartAsync(default);

        try
        {
            var emitter = new AuditEmitter(
                new AuditEventRepository(_db),
                new HttpContextAccessor(),
                NullLogger<AuditEmitter>.Instance,
                EmptyConfig(),
                services);

            await emitter.EmitAsync(
                eventType: "package.publish",
                orgId: "o1",
                actorType: "user",
                actorId: "u1",
                outcome: "accepted",
                payloadJson: """{"ecosystem":"npm","name":"lodash"}""",
                ct: default);

            // BackgroundService delivery is async via the channel reader; poll briefly.
            var deadline = DateTime.UtcNow.AddSeconds(2);
            while (DateTime.UtcNow < deadline && forwarder.Sent.Count == 0)
                await Task.Delay(25);

            var ev = Assert.Single(forwarder.Sent);
            Assert.Equal("package.publish", ev.Action);
            Assert.Equal("tenant", ev.Scope);
            Assert.Equal("o1", ev.OrgId);
            Assert.Equal("u1", ev.ActorId);
            Assert.Contains("lodash", ev.Detail);
        }
        finally
        {
            await queue.StopAsync(default);
        }
    }

    [Fact]
    public async Task EmitAsync_WithoutSiemQueue_DoesNotThrow()
    {
        // No SiemForwarderQueue registered — the most common production shape.
        var sp = new ServiceCollection().BuildServiceProvider();
        var emitter = new AuditEmitter(
            new AuditEventRepository(_db),
            new HttpContextAccessor(),
            NullLogger<AuditEmitter>.Instance,
            EmptyConfig(),
            sp);

        await emitter.EmitAsync(
            eventType: "package.publish",
            orgId: "o1",
            actorType: "user",
            actorId: "u1",
            outcome: "accepted",
            payloadJson: "{}",
            ct: default);

        // Test passes if no exception was thrown — the forwarder path must be a clean no-op
        // when the queue is absent. The repository write still happens.
        await using var conn = await _db.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_event WHERE event_type = 'package.publish'");
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task EmitAsync_NullOrgId_MarksScopeAsSystem()
    {
        var forwarder = new CapturingForwarder();
        var services = new ServiceCollection()
            .AddSingleton<ISiemForwarder>(forwarder)
            .AddSingleton<SiemForwarderQueue>()
            .AddSingleton(EmptyConfig())
            .AddLogging()
            .BuildServiceProvider();

        var queue = services.GetRequiredService<SiemForwarderQueue>();
        await queue.StartAsync(default);

        try
        {
            var emitter = new AuditEmitter(
                new AuditEventRepository(_db),
                new HttpContextAccessor(),
                NullLogger<AuditEmitter>.Instance,
                EmptyConfig(),
                services);

            await emitter.EmitAsync(
                eventType: "system.config_change",
                orgId: null,
                actorType: "system",
                actorId: null,
                outcome: "accepted",
                payloadJson: "{}",
                ct: default);

            var deadline = DateTime.UtcNow.AddSeconds(2);
            while (DateTime.UtcNow < deadline && forwarder.Sent.Count == 0)
                await Task.Delay(25);

            var ev = Assert.Single(forwarder.Sent);
            Assert.Equal("system", ev.Scope);
            Assert.Null(ev.OrgId);
        }
        finally
        {
            await queue.StopAsync(default);
        }
    }
}
