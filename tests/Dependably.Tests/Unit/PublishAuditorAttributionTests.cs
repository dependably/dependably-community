using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Publish;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Attribution coverage for the <em>writer</em> side of the audit actor contract.
/// <see cref="ActorKindAttributionTests"/> proves the list queries resolve a service-token
/// actor to <c>service:&lt;name&gt;</c>, but it supplies <c>actor_id</c> by hand — so it stayed
/// green while every production publish path wrote <c>actor_kind='service'</c> alongside a NULL
/// <c>actor_id</c> (a service token carries no user id) and the join it depends on never
/// matched. These tests drive <see cref="PublishAuditor"/> itself and read back through
/// <see cref="AuditRepository"/>, so the assertion covers the pair the UI actually renders.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PublishAuditorAttributionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, 'o1', @email, 'x', 'admin')",
            new { id = "u1", email = "alice@acme.test" });
        await conn.ExecuteAsync(
            """
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
            VALUES (@id, 'o1', @name, @hash, '["write:packages"]', '2026-01-01T00:00:00Z')
            """,
            new { id = "st1", name = "ci-publish", hash = "deadbeef" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// The request shape a protocol publish builds. A service-token push carries
    /// <c>ActorUserId = null</c> (TokenRepository selects NULL AS user_id for the service
    /// branch), <c>ActorKind = "service"</c>, and the token's own id in <c>ActorTokenId</c>.
    /// </summary>
    private static PublishRequest ServiceTokenPush() => new()
    {
        OrgId = "o1",
        Ecosystem = "npm",
        Name = "left-pad",
        PurlName = "left-pad",
        Version = "1.0.0",
        Filename = "left-pad-1.0.0.tgz",
        Purl = "pkg:npm/left-pad@1.0.0",
        Origin = "uploaded",
        SizeCap = long.MaxValue,
        ActorUserId = null,
        ActorKind = ActorKinds.Service,
        ActorTokenId = "st1",
        AuditAction = "push",
        SourceIp = "203.0.113.7",
    };

    private static PublishRequest UserTokenPush() => ServiceTokenPush() with
    {
        ActorUserId = "u1",
        ActorKind = ActorKinds.User,
        ActorTokenId = "ut1",
    };

    private PublishAuditor NewAuditor(RecordingAuditEmitter emitter)
        => new(new AuditRepository(_db), emitter);

    [Fact]
    public async Task Service_token_push_is_attributed_to_the_token_in_activity()
    {
        var emitter = new RecordingAuditEmitter();
        await NewAuditor(emitter).RecordAsync(ServiceTokenPush(), "abc123", existing: null,
            sizeBytes: 42, CancellationToken.None);

        var (items, _, _) = await new AuditRepository(_db).ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Equal("st1", row.ActorId);
        Assert.Equal("service:ci-publish", row.ActorEmail);
    }

    [Fact]
    public async Task Service_token_push_is_attributed_to_the_token_in_audit_log()
    {
        var emitter = new RecordingAuditEmitter();
        await NewAuditor(emitter).RecordAsync(ServiceTokenPush(), "abc123", existing: null,
            sizeBytes: 42, CancellationToken.None);

        var (items, _, _) = await new AuditRepository(_db).ListAuditAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Equal("push", row.Action);
        Assert.Equal("st1", row.ActorId);
        Assert.Equal("service:ci-publish", row.ActorEmail);
        // The Configuration tab renders these two columns; a push row that carries neither is
        // the "push with no detail" the feed used to show.
        Assert.Equal("npm", row.Ecosystem);
        Assert.Equal("pkg:npm/left-pad@1.0.0", row.Purl);
    }

    [Fact]
    public async Task Service_token_push_emits_api_token_actor_type_not_system()
    {
        var emitter = new RecordingAuditEmitter();
        await NewAuditor(emitter).RecordAsync(ServiceTokenPush(), "abc123", existing: null,
            sizeBytes: 42, CancellationToken.None);

        var ev = Assert.Single(emitter.Events);
        Assert.Equal("api_token", ev.ActorType);
        Assert.Equal("st1", ev.ActorId);
    }

    [Fact]
    public async Task User_token_push_still_resolves_to_the_owning_user()
    {
        var emitter = new RecordingAuditEmitter();
        await NewAuditor(emitter).RecordAsync(UserTokenPush(), "abc123", existing: null,
            sizeBytes: 42, CancellationToken.None);

        var (items, _, _) = await new AuditRepository(_db).ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        // The user id, never the token id — a user token's stable identity is its owner.
        Assert.Equal("u1", row.ActorId);
        Assert.Equal("alice@acme.test", row.ActorEmail);

        var ev = Assert.Single(emitter.Events);
        Assert.Equal("user", ev.ActorType);
        Assert.Equal("u1", ev.ActorId);
    }

    [Fact]
    public async Task Actorless_publish_stays_system_with_no_actor()
    {
        // A background/import caller with neither a user nor a token must not acquire a
        // fabricated actor — a NULL actor_id is the honest record of an actor-less write.
        var emitter = new RecordingAuditEmitter();
        var request = ServiceTokenPush() with { ActorKind = null, ActorTokenId = null };
        await NewAuditor(emitter).RecordAsync(request, "abc123", existing: null,
            sizeBytes: 42, CancellationToken.None);

        var (items, _, _) = await new AuditRepository(_db).ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Null(row.ActorId);
        Assert.Null(row.ActorEmail);
        Assert.Equal("system", Assert.Single(emitter.Events).ActorType);
    }

    [Fact]
    public async Task Service_token_replace_is_attributed_to_the_token()
    {
        // A replace writes its own activity row from a separate call site; it must carry the
        // same actor as the push that triggered it.
        var emitter = new RecordingAuditEmitter();
        var existing = new PackageVersion { ChecksumSha256 = "old000" };
        await NewAuditor(emitter).RecordAsync(ServiceTokenPush(), "abc123", existing,
            sizeBytes: 42, CancellationToken.None);

        var (items, _, _) = await new AuditRepository(_db).ListActivityAsync(
            "o1", limit: 10, offset: 0, eventType: "package.replace");
        var row = Assert.Single(items);
        Assert.Equal("st1", row.ActorId);
        Assert.Equal("service:ci-publish", row.ActorEmail);
    }

    [Fact]
    public async Task Service_token_license_publish_warn_is_attributed_to_the_token()
    {
        var emitter = new RecordingAuditEmitter();
        await NewAuditor(emitter).RecordLicensePublishWarnAsync(ServiceTokenPush(), CancellationToken.None);

        var (items, _, _) = await new AuditRepository(_db).ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Equal("license_publish_warn", row.EventType);
        Assert.Equal("st1", row.ActorId);
        Assert.Equal("service:ci-publish", row.ActorEmail);
    }

    private sealed record EmittedEvent(string EventType, string ActorType, string? ActorId);

    private sealed class RecordingAuditEmitter : IAuditEmitter
    {
        public List<EmittedEvent> Events { get; } = [];

        public Task EmitAsync(string eventType, string? orgId, string actorType, string? actorId,
            string outcome, string payloadJson, CancellationToken ct = default)
        {
            Events.Add(new EmittedEvent(eventType, actorType, actorId));
            return Task.CompletedTask;
        }
    }
}
