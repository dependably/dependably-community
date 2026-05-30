using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression coverage for the bug where service-token-authenticated activity rows rendered
/// as "anonymous" in the audit UI because <c>TokenRepository.ResolveAsync</c> sets
/// <c>UserId = null</c> for service tokens. The fix added an <c>actor_kind</c> discriminator
/// so the list query can resolve service tokens to <c>service:&lt;name&gt;</c> via a join to
/// <c>service_tokens</c>, while users keep resolving via <c>users</c>. Legacy rows with NULL
/// <c>actor_kind</c> must still resolve through the users join (back-compat).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ActorKindAttributionTests : IAsyncLifetime
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
            VALUES (@id, 'o1', @name, @hash, '["read:metadata"]', '2026-01-01T00:00:00Z')
            """,
            new { id = "st1", name = "ci-pull", hash = "deadbeef" });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task ListActivity_resolves_service_token_actor_to_service_prefix()
    {
        var repo = new AuditRepository(_db);

        await repo.LogActivityAsync("o1", "npm", "pkg:npm/left-pad@1.0.0", "first_fetch",
            actorId: "st1", actorKind: ActorKinds.Service);

        var (items, _) = await repo.ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Equal("st1", row.ActorId);
        Assert.Equal("service:ci-pull", row.ActorEmail);
    }

    [Fact]
    public async Task ListActivity_resolves_user_token_actor_to_email()
    {
        var repo = new AuditRepository(_db);

        await repo.LogActivityAsync("o1", "npm", "pkg:npm/left-pad@1.0.0", "first_fetch",
            actorId: "u1", actorKind: ActorKinds.User);

        var (items, _) = await repo.ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Equal("u1", row.ActorId);
        Assert.Equal("alice@acme.test", row.ActorEmail);
    }

    [Fact]
    public async Task ListActivity_truly_anonymous_row_yields_null_actor_email()
    {
        // AnonymousPull=true path: no token, no actor, no kind. The UI renders this as
        // "anonymous" — and importantly it is *distinguishable* from a service-token row
        // because ActorId is null here, not a service_tokens.id.
        var repo = new AuditRepository(_db);

        await repo.LogActivityAsync("o1", "npm", "pkg:npm/left-pad@1.0.0", "first_fetch",
            actorId: null, actorKind: null);

        var (items, _) = await repo.ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Null(row.ActorId);
        Assert.Null(row.ActorEmail);
    }

    [Fact]
    public async Task ListActivity_legacy_null_kind_with_user_id_falls_back_to_users_join()
    {
        // Rows written before this migration have actor_kind=NULL even though actor_id is a
        // users.id. The list query treats NULL as "try the users join", preserving the prior
        // rendering behaviour for historical rows.
        var repo = new AuditRepository(_db);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, purl, event_type, actor_id, actor_kind, created_at)
            VALUES ('legacy1', 'o1', 'pypi', 'pkg:pypi/legacy@1', 'download', 'u1', NULL, '2025-01-01T00:00:00Z')
            """);

        var (items, _) = await repo.ListActivityAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Equal("u1", row.ActorId);
        Assert.Equal("alice@acme.test", row.ActorEmail);
    }

    [Fact]
    public async Task ListAudit_resolves_service_token_actor_to_service_prefix()
    {
        // audit_log path mirrors activity — service tokens that push, replace, or trigger
        // checksum failures should likewise read back as service:<name>.
        var repo = new AuditRepository(_db);

        await repo.LogAsync("package.push", orgId: "o1", actorId: "st1",
            actorKind: ActorKinds.Service, ecosystem: "npm", purl: "pkg:npm/left-pad@1.0.0");

        var (items, _) = await repo.ListAuditAsync("o1", limit: 10, offset: 0);
        var row = Assert.Single(items);
        Assert.Equal("st1", row.ActorId);
        Assert.Equal("service:ci-pull", row.ActorEmail);
    }

    [Fact]
    public async Task TokenRecord_ActorKind_maps_source_correctly()
    {
        // The plumbing relies on TokenRecord.ActorKind faithfully reflecting Source. A regression
        // here (e.g. someone adds a new TokenSource and forgets the switch arm) would silently
        // break attribution at every controller call site.
        Assert.Equal(ActorKinds.User,
            new TokenRecord { Source = TokenSource.User }.ActorKind);
        Assert.Equal(ActorKinds.Service,
            new TokenRecord { Source = TokenSource.Service }.ActorKind);
    }
}
