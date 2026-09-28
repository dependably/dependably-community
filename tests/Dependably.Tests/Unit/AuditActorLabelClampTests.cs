using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit;

/// <summary>
/// <c>AuditRepository</c> stores an actor label for service actors only. Every writer drops a
/// label paired with any other kind, including a NULL kind, and logs a warning, so a producer
/// that returns a label for a human degrades to a missing label rather than an email at rest in
/// a column no scrub reaches.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditActorLabelClampTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly CapturingLogger _logger = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private AuditRepository Repo(ActivityWriter? writer = null) =>
        new(_db, writer, TestTime.Frozen(), _logger);

    private async Task<string?> AuditLabelAsync(string action)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT actor_label FROM audit_log WHERE action = @action", new { action });
    }

    [Theory]
    [InlineData(ActorKinds.User)]
    [InlineData(null)]
    public async Task LogAsyncDropsALabelForANonServiceActor(string? kind)
    {
        await Repo().LogAsync("t.user", orgId: "o1", actorId: "u1", actorKind: kind, actorLabel: "alice@acme.test");

        Assert.Null(await AuditLabelAsync("t.user"));
        Assert.Contains(_logger.Warnings, w => w.Contains("t.user", StringComparison.Ordinal));
        Assert.DoesNotContain(_logger.Warnings, w => w.Contains("alice@acme.test", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LogAsyncKeepsAServiceActorsLabelWithoutWarning()
    {
        await Repo().LogAsync("t.service", orgId: "o1", actorId: "st1", actorKind: ActorKinds.Service, actorLabel: "ci-publish");

        Assert.Equal("ci-publish", await AuditLabelAsync("t.service"));
        Assert.Empty(_logger.Warnings);
    }

    [Fact]
    public async Task ANullLabelIsNeverWarnedAbout()
    {
        await Repo().LogAsync("t.none", orgId: "o1", actorId: "u1", actorKind: ActorKinds.User);

        Assert.Null(await AuditLabelAsync("t.none"));
        Assert.Empty(_logger.Warnings);
    }

    [Fact]
    public async Task LogSystemAsyncDropsALabelForAnAdminActor()
    {
        await Repo().LogSystemAsync(action: "s.admin", actorId: "admin-1", actorLabel: "root@example.test");
        await Repo().LogSystemAsync(action: "s.token", actorId: "stok-1", actorKind: ActorKinds.Service, actorLabel: "provisioner");

        Assert.Null(await AuditLabelAsync("s.admin"));
        Assert.Equal("provisioner", await AuditLabelAsync("s.token"));
        Assert.Single(_logger.Warnings);
    }

    [Fact]
    public async Task LogSystemAsyncOnACallerConnectionDropsALabelForANonServiceActor()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await Repo().LogSystemAsync(conn, tx: null, action: "s.conn", actorId: "admin-1",
                actorKind: ActorKinds.User, actorLabel: "root@example.test");
        }

        Assert.Null(await AuditLabelAsync("s.conn"));
        Assert.Single(_logger.Warnings);
    }

    [Fact]
    public async Task LogActivityAsyncDropsALabelOnTheSynchronousRow()
    {
        await Repo().LogActivityAsync("o1", "npm", "pkg:npm/a@1.0.0", "a.user",
            actorId: "u1", actorKind: ActorKinds.User, actorLabel: "alice@acme.test");
        await Repo().LogActivityAsync("o1", "npm", "pkg:npm/a@1.0.0", "a.service",
            actorId: "st1", actorKind: ActorKinds.Service, actorLabel: "ci-publish");

        await using var conn = await _db.OpenAsync();
        var labels = (await conn.QueryAsync<(string EventType, string? ActorLabel)>(
            "SELECT event_type, actor_label FROM activity ORDER BY event_type")).ToList();
        Assert.Equal([("a.service", "ci-publish"), ("a.user", (string?)null)], labels);
        Assert.Single(_logger.Warnings);
    }

    [Fact]
    public async Task LogActivityAsyncDropsALabelOnTheQueuedRow()
    {
        var writer = new ActivityWriter(capacity: 4);

        await Repo(writer).LogActivityAsync("o1", "npm", "pkg:npm/a@1.0.0", "a.user",
            actorId: "u1", actorKind: ActorKinds.User, actorLabel: "alice@acme.test");

        Assert.True(writer.Reader.TryRead(out var record));
        Assert.Equal(ActorKinds.User, record!.ActorKind);
        Assert.Null(record.ActorLabel);
        Assert.Single(_logger.Warnings);
    }

    private sealed class CapturingLogger : ILogger<AuditRepository>
    {
        private readonly List<string> _warnings = [];

        public IReadOnlyList<string> Warnings
        {
            get
            {
                lock (_warnings)
                {
                    return [.. _warnings];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                lock (_warnings)
                {
                    _warnings.Add(formatter(state, exception));
                }
            }
        }
    }
}
