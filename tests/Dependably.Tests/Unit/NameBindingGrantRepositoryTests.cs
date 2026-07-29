using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The read/scoping half of <see cref="NameBindingRepository"/> that the grant-management API is
/// built on. Every test seeds TWO orgs and asserts against the real database, because the property
/// under test is exactly the one a single-org fixture cannot see: that each query is confined to
/// the org it was asked about.
///
/// <para>
/// <see cref="NameBindingRepository.GranteeExistsInOrgAsync"/> gets particular attention. The
/// grantee id reaches it from a request body, and a grant row naming a foreign principal would be
/// a cross-tenant authorization write wearing a correctly-scoped <c>org_id</c> — the kind of hole
/// that passes every schema-level check and only a roster lookup closes.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class NameBindingGrantRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private NameBindingRepository _repo = null!;

    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new NameBindingRepository(_db);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@a, 'acme'), (@b, 'beta')", new { a = OrgA, b = OrgB });
        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role)
            VALUES ('user-a', @a, 'a@example.com', 'x', 'member'),
                   ('user-b', @b, 'b@example.com', 'x', 'member')
            """,
            new { a = OrgA, b = OrgB });
        await conn.ExecuteAsync(
            """
            INSERT INTO service_tokens (id, org_id, name, token_hash)
            VALUES ('svc-a', @a, 'ci-a', 'hash-a'),
                   ('svc-b', @b, 'ci-b', 'hash-b')
            """,
            new { a = OrgA, b = OrgB });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static NamePrincipal User(string id) => new(ActorKinds.User, id);
    private static NamePrincipal Service(string id) => new(ActorKinds.Service, id);

    // ── Grantee resolution ─────────────────────────────────────────────────────

    [Fact]
    public async Task GranteeExistsInOrg_True_ForAUserAndAServiceTokenInThatOrg()
    {
        Assert.True(await _repo.GranteeExistsInOrgAsync(OrgA, User("user-a")));
        Assert.True(await _repo.GranteeExistsInOrgAsync(OrgA, Service("svc-a")));
    }

    /// <summary>
    /// Adversarial twin: a principal that exists, but in another tenant, must resolve to false.
    /// Returning true here is what would let an admin authorize a foreign user or CI token to
    /// publish into their org — the grant row's own org_id would look perfectly well-scoped.
    /// </summary>
    [Fact]
    public async Task GranteeExistsInOrg_False_ForAPrincipalThatBelongsToAnotherOrg()
    {
        Assert.False(await _repo.GranteeExistsInOrgAsync(OrgA, User("user-b")));
        Assert.False(await _repo.GranteeExistsInOrgAsync(OrgA, Service("svc-b")));
    }

    [Fact]
    public async Task GranteeExistsInOrg_False_ForAnUnknownIdOrAnUnknownKind()
    {
        Assert.False(await _repo.GranteeExistsInOrgAsync(OrgA, User("no-such-user")));
        Assert.False(await _repo.GranteeExistsInOrgAsync(OrgA, new NamePrincipal("robot", "user-a")));
    }

    /// <summary>
    /// The kinds are distinct namespaces: a users.id must not resolve because a service_tokens row
    /// happens to share the value, or the two id spaces would be interchangeable.
    /// </summary>
    [Fact]
    public async Task GranteeExistsInOrg_DoesNotCrossTheUserAndServiceIdSpaces()
    {
        Assert.False(await _repo.GranteeExistsInOrgAsync(OrgA, User("svc-a")));
        Assert.False(await _repo.GranteeExistsInOrgAsync(OrgA, Service("user-a")));
    }

    // ── Binding listing ────────────────────────────────────────────────────────

    [Fact]
    public async Task ListBindings_ReturnsOnlyTheRequestedOrgsNames()
    {
        await _repo.BindIfAbsentAsync(OrgA, "npm", "@acme/widget", User("user-a"));
        await _repo.BindIfAbsentAsync(OrgA, "pypi", "acme-tool", Service("svc-a"));
        await _repo.BindIfAbsentAsync(OrgB, "npm", "@beta/secret", User("user-b"));

        var forA = await _repo.ListBindingsAsync(OrgA);

        Assert.Equal(2, forA.Count);
        Assert.All(forA, b => Assert.Equal(OrgA, b.OrgId));
        Assert.DoesNotContain(forA, b => b.PurlName == "@beta/secret");
    }

    [Fact]
    public async Task ListBindings_NarrowsToOneEcosystem_WhenAsked()
    {
        await _repo.BindIfAbsentAsync(OrgA, "npm", "@acme/widget", User("user-a"));
        await _repo.BindIfAbsentAsync(OrgA, "pypi", "acme-tool", User("user-a"));

        var npmOnly = await _repo.ListBindingsAsync(OrgA, "npm");

        Assert.Single(npmOnly);
        Assert.Equal("@acme/widget", npmOnly[0].PurlName);
    }

    // ── Grant read and revoke scoping ──────────────────────────────────────────

    [Fact]
    public async Task GetGrant_ReturnsTheRow_ForItsOwnOrg()
    {
        await _repo.AddGrantAsync(OrgA, "npm", "@acme/widget", Service("svc-a"), createdBy: "user-a");
        var grants = await _repo.ListGrantsAsync(OrgA, "npm", "@acme/widget");
        string grantId = Assert.Single(grants).Id;

        var read = await _repo.GetGrantAsync(OrgA, grantId);

        Assert.NotNull(read);
        Assert.Equal("svc-a", read!.GranteeId);
        Assert.Equal("user-a", read.CreatedBy);
    }

    /// <summary>
    /// Adversarial twin: reading another org's grant by its id must be indistinguishable from
    /// reading one that does not exist — otherwise the revoke endpoint's 404-vs-204 answer becomes
    /// a probe for whether a given grant id exists in some other tenant.
    /// </summary>
    [Fact]
    public async Task GetGrant_ReturnsNull_ForAnotherOrgsGrantId()
    {
        await _repo.AddGrantAsync(OrgB, "npm", "@beta/secret", Service("svc-b"), createdBy: "user-b");
        var grants = await _repo.ListGrantsAsync(OrgB, "npm", "@beta/secret");
        string foreignGrantId = Assert.Single(grants).Id;

        Assert.Null(await _repo.GetGrantAsync(OrgA, foreignGrantId));
        Assert.Null(await _repo.GetGrantAsync(OrgA, "no-such-grant"));
    }

    /// <summary>
    /// The delete carries the same predicate, so a cross-org revoke removes nothing — and,
    /// critically, leaves the victim's grant intact.
    /// </summary>
    [Fact]
    public async Task RemoveGrant_DoesNothing_ForAnotherOrgsGrantId()
    {
        await _repo.AddGrantAsync(OrgB, "npm", "@beta/secret", Service("svc-b"), createdBy: "user-b");
        string foreignGrantId = (await _repo.ListGrantsAsync(OrgB, "npm", "@beta/secret"))[0].Id;

        int removed = await _repo.RemoveGrantAsync(OrgA, foreignGrantId);

        Assert.Equal(0, removed);
        Assert.Single(await _repo.ListGrantsAsync(OrgB, "npm", "@beta/secret"));
    }

    [Fact]
    public async Task AddGrant_IsIdempotent_AndListsOnlyTheRequestedName()
    {
        await _repo.AddGrantAsync(OrgA, "npm", "@acme/widget", Service("svc-a"), createdBy: "user-a");
        await _repo.AddGrantAsync(OrgA, "npm", "@acme/widget", Service("svc-a"), createdBy: "user-a");
        await _repo.AddGrantAsync(OrgA, "npm", "@acme/other", User("user-a"), createdBy: "user-a");

        Assert.Single(await _repo.ListGrantsAsync(OrgA, "npm", "@acme/widget"));
        Assert.Single(await _repo.ListGrantsAsync(OrgA, "npm", "@acme/other"));
    }
}
