using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for the name-level publish-authorization gate: first-publisher ownership,
/// refusal of a second principal, grant override, cross-ecosystem independence, the enforcement
/// flag, and the BOLA-twin property that authorization keys on the principal (kind + id) — never
/// a value a caller could substitute.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NameBindingGateTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly NamePrincipal Alice = new(ActorKinds.User, "user-alice");
    private static readonly NamePrincipal Bob = new(ActorKinds.User, "user-bob");
    private static readonly NamePrincipal ServiceCi = new(ActorKinds.Service, "svc-ci");

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private NameBindingGate Gate(bool enforce)
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PUBLISH_NAME_BINDING"] = enforce ? "on" : "off",
            })
            .Build();
        return new NameBindingGate(cfg, new NameBindingRepository(_db), NullLogger<NameBindingGate>.Instance);
    }

    // ── enforcement off ──────────────────────────────────────────────────────

    [Fact]
    public async Task EnforcementOff_AnyPrincipal_Allowed_ButOwnershipRecorded()
    {
        var gate = Gate(enforce: false);

        // Alice publishes first and is (of course) allowed; ownership is recorded regardless.
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", Alice));
        await gate.RecordOwnershipAsync("o1", "npm", "lib", Alice);

        // Bob would be refused when enforcement is on, but with the flag off he is allowed —
        // yet the binding still names Alice as owner (data is ready for a later flag flip).
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", Bob));

        var binding = await new NameBindingRepository(_db).GetBindingAsync("o1", "npm", "lib");
        Assert.NotNull(binding);
        Assert.True(binding!.IsOwnedBy(Alice));
    }

    // ── enforcement on: the core authorization contract ──────────────────────

    [Fact]
    public async Task EnforcementOn_UnboundName_FirstPublisherAllowed()
    {
        var gate = Gate(enforce: true);
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "fresh", Alice));
    }

    [Fact]
    public async Task EnforcementOn_Owner_CanPublishAgain()
    {
        var gate = Gate(enforce: true);
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", Alice));
        await gate.RecordOwnershipAsync("o1", "npm", "lib", Alice);

        // The owner keeps publishing new versions to a name it owns.
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", Alice));
    }

    [Fact]
    public async Task EnforcementOn_DifferentPrincipal_Denied()
    {
        var gate = Gate(enforce: true);
        await gate.RecordOwnershipAsync("o1", "npm", "lib", Alice);

        // Bob holds publish:npm but does not own 'lib' and has no grant — refused.
        Assert.False(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", Bob));
    }

    [Fact]
    public async Task EnforcementOn_Grant_LetsSecondPrincipalPublish()
    {
        var gate = Gate(enforce: true);
        var repo = new NameBindingRepository(_db);
        await gate.RecordOwnershipAsync("o1", "npm", "lib", Alice);
        Assert.False(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", Bob));

        // Grant Bob co-publish on 'lib' — now he is authorized, Alice's ownership unchanged.
        await repo.AddGrantAsync("o1", "npm", "lib", Bob, createdBy: null);
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", Bob));

        var binding = await repo.GetBindingAsync("o1", "npm", "lib");
        Assert.True(binding!.IsOwnedBy(Alice));
    }

    // ── BOLA twin: the decision keys on the authenticated principal ──────────

    [Fact]
    public async Task EnforcementOn_PrincipalKindMustMatch_NotJustId()
    {
        var gate = Gate(enforce: true);
        // Owner is the SERVICE token svc-ci.
        await gate.RecordOwnershipAsync("o1", "npm", "lib", ServiceCi);

        // A user principal whose id string collides with the service-token id is NOT the owner:
        // ownership is the (kind,id) tuple, so a substituted identifier cannot impersonate it.
        var impostor = new NamePrincipal(ActorKinds.User, ServiceCi.Id);
        Assert.False(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", impostor));

        // The real service principal is authorized.
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", ServiceCi));
    }

    [Fact]
    public async Task EnforcementOn_NullPrincipal_NotEnforced()
    {
        var gate = Gate(enforce: true);
        await gate.RecordOwnershipAsync("o1", "npm", "lib", Alice);

        // A background/anonymous caller (no principal to attribute) is never refused — but also
        // records no ownership, so it cannot seize a name.
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "npm", "lib", principal: null));
        await gate.RecordOwnershipAsync("o1", "npm", "other", principal: null);
        Assert.Null(await new NameBindingRepository(_db).GetBindingAsync("o1", "npm", "other"));
    }

    // ── cross-ecosystem independence ─────────────────────────────────────────

    [Fact]
    public async Task SameName_DifferentEcosystem_IsIndependent()
    {
        var gate = Gate(enforce: true);
        await gate.RecordOwnershipAsync("o1", "npm", "shared", Alice);

        // Bob cannot take npm/shared, but pypi/shared is a distinct binding and unbound —
        // so Bob owns it freely.
        Assert.False(await gate.IsPublishAuthorizedAsync("o1", "npm", "shared", Bob));
        Assert.True(await gate.IsPublishAuthorizedAsync("o1", "pypi", "shared", Bob));
    }

    // ── record-ownership is trust-on-first-use (no takeover on later publish) ─

    [Fact]
    public async Task RecordOwnership_IsFirstWriterWins()
    {
        var repo = new NameBindingRepository(_db);
        var gate = Gate(enforce: false);

        await gate.RecordOwnershipAsync("o1", "npm", "lib", Alice);
        // A later record by Bob is a no-op — ownership does not transfer on republish.
        await gate.RecordOwnershipAsync("o1", "npm", "lib", Bob);

        var binding = await repo.GetBindingAsync("o1", "npm", "lib");
        Assert.True(binding!.IsOwnedBy(Alice));
    }

    // ── the binding is a tenant-isolated row ─────────────────────────────────

    [Fact]
    public async Task Binding_IsOrgScoped()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'other')");
        }

        var gate = Gate(enforce: true);
        await gate.RecordOwnershipAsync("o1", "npm", "lib", Alice);

        // A different org's binding table is empty for the same name, so its first publisher owns
        // it — org o1's binding never leaks across the tenant boundary.
        Assert.True(await gate.IsPublishAuthorizedAsync("o2", "npm", "lib", Bob));
        var repo = new NameBindingRepository(_db);
        Assert.Null(await repo.GetBindingAsync("o2", "npm", "lib"));
    }
}
