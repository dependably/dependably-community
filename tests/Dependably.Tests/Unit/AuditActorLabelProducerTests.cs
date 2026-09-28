using System.Security.Claims;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The producer half of the actor-label rule. <c>AuditActorIdComplianceTests</c> proves every
/// label written towards <c>actor_label</c> is read through a derived accessor; it cannot prove
/// the accessor is right. These pin the accessors that exist: each yields a label for a service
/// actor and NULL for a human one, whose display name is an email.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditActorLabelProducerTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ('u1', 'o1', 'alice@acme.test', 'x', 'admin')");
        await conn.ExecuteAsync(
            """
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
            VALUES ('st1', 'o1', 'ci-publish', 'deadbeef', '["read:metadata"]', '2026-01-01T00:00:00Z')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public void UserTokenHasNoAuditActorLabelEvenWhenANameIsResolved()
    {
        var token = new TokenRecord { Id = "t1", UserId = "u1", Source = TokenSource.User, Name = "alice@acme.test" };

        Assert.Null(token.AuditActorLabel);
        Assert.Equal(ActorKinds.User, token.ActorKind);
    }

    [Fact]
    public void ServiceTokenAuditActorLabelIsTheTokenName()
    {
        var token = new TokenRecord { Id = "st1", Source = TokenSource.Service, Name = "ci-publish" };

        Assert.Equal("ci-publish", token.AuditActorLabel);
    }

    [Fact]
    public void SystemActorForAHumanAdminHasNoLabel()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "admin-1"),
                new Claim(ClaimTypes.Email, "root@example.test"),
                new Claim("stok_name", "must-not-be-read"),
            ],
            authenticationType: "Bearer"));

        var actor = SystemActor.From(principal);

        Assert.Equal("admin-1", actor.Id);
        Assert.Null(actor.Kind);
        Assert.Null(actor.Label);
    }

    [Fact]
    public void SystemActorForASystemTokenCarriesTheTokenName()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "stok-1"),
                new Claim("stok_name", "provisioner"),
                new Claim("stok_owner", "admin-1"),
            ],
            authenticationType: SystemTokenDefaults.Scheme));

        var actor = SystemActor.From(principal);

        Assert.Equal(ActorKinds.Service, actor.Kind);
        Assert.Equal("provisioner", actor.Label);
    }

    [Fact]
    public async Task ResolveActorForAUserYieldsNoLabel()
    {
        var repo = new SbomIngestRepository(_db);

        var actor = await repo.ResolveActorAsync("o1", "u1");

        Assert.Equal(ActorKinds.User, actor.Kind);
        Assert.Null(actor.Label);
    }

    [Fact]
    public async Task ResolveActorForAServiceTokenYieldsItsName()
    {
        var repo = new SbomIngestRepository(_db);

        var actor = await repo.ResolveActorAsync("o1", "st1");

        Assert.Equal(ActorKinds.Service, actor.Kind);
        Assert.Equal("ci-publish", actor.Label);
    }

    [Fact]
    public async Task ResolveActorForAnUnknownSubjectYieldsNoLabel()
    {
        var repo = new SbomIngestRepository(_db);

        var actor = await repo.ResolveActorAsync("o1", "nobody");

        Assert.Equal(ActorKinds.User, actor.Kind);
        Assert.Null(actor.Label);
    }
}
