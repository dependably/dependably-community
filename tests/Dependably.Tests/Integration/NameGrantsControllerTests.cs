using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Full-surface coverage of <see cref="Dependably.Api.NameGrantsController"/>: listing bound names,
/// listing/creating/revoking co-publish grants, the capability gates on each, the validation
/// branches that keep an inert or cross-tenant grant from being written, and the audit rows.
///
/// <para>
/// Each test builds its own <see cref="DependablyFactory"/>. The surface is org-scoped and
/// <c>DEPLOYMENT_MODE=single</c> resolves every request to the one org, so a shared fixture would
/// let one test's bindings and grants leak into another's "list" assertions.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class NameGrantsControllerTests
{
    private const string Ecosystem = "npm";
    private const string BoundName = "@acme/widget";

    private static async Task<HttpClient> AdminClientAsync(DependablyFactory factory)
    {
        string jwt = await factory.CreateAdminJwt();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    /// <summary>A session holding read:tenant only — enough to list, never enough to grant.</summary>
    private static async Task<HttpClient> ReadOnlyClientAsync(DependablyFactory factory)
    {
        string userId = await factory.CreateUser($"ng-ro-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await factory.CreateUserJwtWithCaps(userId, ["read:tenant"]);
        return factory.CreateClientWithBearer(jwt);
    }

    private static async Task<string> DefaultOrgIdAsync(DependablyFactory factory)
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    /// <summary>Binds <see cref="BoundName"/> to a seeded service token and returns that token's id.</summary>
    private static async Task<string> SeedBoundNameAsync(DependablyFactory factory, string tokenName = "ci-primary")
    {
        string orgId = await DefaultOrgIdAsync(factory);
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string serviceTokenId = Guid.NewGuid().ToString("N");

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO service_tokens (id, org_id, name, token_hash)
                VALUES (@id, @orgId, @name, @hash)
                """,
                new { id = serviceTokenId, orgId, name = tokenName, hash = Guid.NewGuid().ToString("N") });
        }

        var bindings = factory.Services.GetRequiredService<NameBindingRepository>();
        await bindings.BindIfAbsentAsync(
            orgId, Ecosystem, BoundName, new NamePrincipal(ActorKinds.Service, serviceTokenId));

        return serviceTokenId;
    }

    private static async Task<string> SeedServiceTokenAsync(DependablyFactory factory, string name)
    {
        string orgId = await DefaultOrgIdAsync(factory);
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string id = Guid.NewGuid().ToString("N");

        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO service_tokens (id, org_id, name, token_hash) VALUES (@id, @orgId, @name, @hash)",
            new { id, orgId, name, hash = Guid.NewGuid().ToString("N") });
        return id;
    }

    private static object GrantBody(string granteeId, string granteeKind = "service", string? name = null) =>
        new { ecosystem = Ecosystem, name = name ?? BoundName, granteeKind, granteeId };

    // ── Bound-name listing ─────────────────────────────────────────────────────

    [Fact]
    public async Task ListBindings_ReturnsTheOrgsBoundNames()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);

        using var client = await AdminClientAsync(factory);
        var resp = await client.GetAsync("/api/v1/name-bindings");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var names = body.EnumerateArray().Select(b => b.GetProperty("name").GetString()).ToList();
        Assert.Contains(BoundName, names);
    }

    [Fact]
    public async Task ListBindings_UnknownEcosystem_Returns422()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();

        using var client = await AdminClientAsync(factory);
        var resp = await client.GetAsync("/api/v1/name-bindings?ecosystem=cobol");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Grant creation ─────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateGrant_BoundNameAndLocalPrincipal_Returns201_AndPersistsTheGrant()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        var resp = await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody(coPublisher));

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var bindings = factory.Services.GetRequiredService<NameBindingRepository>();
        string orgId = await DefaultOrgIdAsync(factory);
        Assert.True(await bindings.HasGrantAsync(
            orgId, Ecosystem, BoundName, new NamePrincipal(ActorKinds.Service, coPublisher)));
    }

    /// <summary>
    /// Re-granting the same pair is a no-op that still succeeds, so a config-management run that
    /// reapplies its desired state does not need to special-case "already granted".
    /// </summary>
    [Fact]
    public async Task CreateGrant_Twice_IsIdempotent_AndLeavesOneRow()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        var first = await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody(coPublisher));
        var second = await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody(coPublisher));

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);

        var bindings = factory.Services.GetRequiredService<NameBindingRepository>();
        string orgId = await DefaultOrgIdAsync(factory);
        Assert.Single(await bindings.ListGrantsAsync(orgId, Ecosystem, BoundName));
    }

    /// <summary>
    /// A grant against an unbound name would be permanently inert — the gate never consults grants
    /// for a name with no owner. Answering 201 there is how an operator ends up believing
    /// co-publish is configured when it is not.
    /// </summary>
    [Fact]
    public async Task CreateGrant_NameNotBound_Returns404_AndWritesNothing()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        var resp = await client.PostAsJsonAsync(
            "/api/v1/name-grants", GrantBody(coPublisher, name: "@acme/never-published"));

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);

        var bindings = factory.Services.GetRequiredService<NameBindingRepository>();
        string orgId = await DefaultOrgIdAsync(factory);
        Assert.Empty(await bindings.ListGrantsAsync(orgId, Ecosystem, "@acme/never-published"));
    }

    /// <summary>
    /// Adversarial twin: an id that resolves to no principal in this org is refused. Together with
    /// <c>NameBindingGrantRepositoryTests</c> — which proves the same lookup rejects a principal
    /// that exists in ANOTHER org — this is what stops the endpoint minting a well-scoped-looking
    /// row that authorizes a foreign publisher.
    /// </summary>
    [Fact]
    public async Task CreateGrant_GranteeNotInThisOrg_Returns422_AndWritesNothing()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);

        using var client = await AdminClientAsync(factory);
        var resp = await client.PostAsJsonAsync(
            "/api/v1/name-grants", GrantBody(Guid.NewGuid().ToString("N")));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        var bindings = factory.Services.GetRequiredService<NameBindingRepository>();
        string orgId = await DefaultOrgIdAsync(factory);
        Assert.Empty(await bindings.ListGrantsAsync(orgId, Ecosystem, BoundName));
    }

    [Fact]
    public async Task CreateGrant_InvalidGranteeKind_Returns422()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        var resp = await client.PostAsJsonAsync(
            "/api/v1/name-grants", GrantBody(coPublisher, granteeKind: "robot"));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task CreateGrant_MissingName_Returns422()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        var resp = await client.PostAsJsonAsync(
            "/api/v1/name-grants",
            new { ecosystem = Ecosystem, name = "  ", granteeKind = "service", granteeId = coPublisher });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Listing and revoking ───────────────────────────────────────────────────

    [Fact]
    public async Task ListGrants_ReturnsTheGrantsForThatName()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody(coPublisher));

        var resp = await client.GetAsync(
            $"/api/v1/name-grants?ecosystem={Ecosystem}&name={Uri.EscapeDataString(BoundName)}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var grant = Assert.Single(body.EnumerateArray().ToList());
        Assert.Equal(coPublisher, grant.GetProperty("granteeId").GetString());
        Assert.Equal(BoundName, grant.GetProperty("name").GetString());
    }

    [Fact]
    public async Task RevokeGrant_Returns204_AndRemovesTheGrant()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        var created = await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody(coPublisher));
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();
        string grantId = createdBody.GetProperty("id").GetString()!;

        var resp = await client.DeleteAsync($"/api/v1/name-grants/{grantId}");

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        var bindings = factory.Services.GetRequiredService<NameBindingRepository>();
        string orgId = await DefaultOrgIdAsync(factory);
        Assert.False(await bindings.HasGrantAsync(
            orgId, Ecosystem, BoundName, new NamePrincipal(ActorKinds.Service, coPublisher)));
    }

    [Fact]
    public async Task RevokeGrant_UnknownId_Returns404()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();

        using var client = await AdminClientAsync(factory);
        var resp = await client.DeleteAsync($"/api/v1/name-grants/{Guid.NewGuid():N}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Audit ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Both writes are audited with the name and principal, not just the opaque grant id — an
    /// authorization change nobody can reconstruct after the fact is not accountable.
    /// </summary>
    [Fact]
    public async Task GrantAndRevoke_AreBothAudited_WithTheNameAndPrincipal()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await AdminClientAsync(factory);
        var created = await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody(coPublisher));
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();
        await client.DeleteAsync($"/api/v1/name-grants/{createdBody.GetProperty("id").GetString()}");

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var rows = (await conn.QueryAsync<(string Action, string? Detail)>(
            """
            SELECT action AS Action, detail AS Detail FROM audit_log
            WHERE action IN ('name_grant_added', 'name_grant_revoked')
            ORDER BY created_at, action
            """)).ToList();

        Assert.Equal(2, rows.Count);
        Assert.All(rows, r =>
        {
            Assert.NotNull(r.Detail);
            Assert.Contains(BoundName, r.Detail!, StringComparison.Ordinal);
            Assert.Contains(coPublisher, r.Detail!, StringComparison.Ordinal);
        });
    }

    // ── Capability gates ───────────────────────────────────────────────────────

    [Fact]
    public async Task ListSurfaces_AreReachableWithReadTenantOnly()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);

        using var client = await ReadOnlyClientAsync(factory);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/name-bindings")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(
            $"/api/v1/name-grants?ecosystem={Ecosystem}&name={Uri.EscapeDataString(BoundName)}")).StatusCode);
    }

    /// <summary>
    /// Adversarial twin to the read gate: read:tenant must not be enough to change who may publish
    /// a name. Granting co-publish is a privilege change, and it requires tenant:configure.
    /// </summary>
    [Fact]
    public async Task WriteSurfaces_AreRefusedWithReadTenantOnly()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        await SeedBoundNameAsync(factory);
        string coPublisher = await SeedServiceTokenAsync(factory, "ci-secondary");

        using var client = await ReadOnlyClientAsync(factory);

        var create = await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody(coPublisher));
        var revoke = await client.DeleteAsync($"/api/v1/name-grants/{Guid.NewGuid():N}");

        Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, revoke.StatusCode);

        var bindings = factory.Services.GetRequiredService<NameBindingRepository>();
        string orgId = await DefaultOrgIdAsync(factory);
        Assert.Empty(await bindings.ListGrantsAsync(orgId, Ecosystem, BoundName));
    }

    [Fact]
    public async Task EverySurface_RequiresAuthentication()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();

        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/name-bindings")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.PostAsJsonAsync("/api/v1/name-grants", GrantBody("anything"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.DeleteAsync($"/api/v1/name-grants/{Guid.NewGuid():N}")).StatusCode);
    }
}
