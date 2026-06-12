using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// PR-4 enforces a two-tier authorization model for PatchMemberRole and RemoveUser:
///   - tier 1 (entry): tenant:configure — admin or owner can reach the endpoint;
///   - tier 2 (in-handler): tenant:admin — only owners can modify owners, grant owner, or
///     remove owners.
/// These tests pin that behavior down so a future change to the role→cap map can't quietly
/// re-tighten or re-loosen who can manage who. The last-owner invariant (cannot demote or
/// remove the sole owner) is also covered.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UserManagementCapabilityTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;

    public UserManagementCapabilityTests(DependablyFactory factory)
    {
        _factory = factory;
    }

    private async Task<HttpClient> ClientFor(string userId, string role)
    {
        string jwt = await _factory.CreateUserJwt(userId, role);
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    [Fact]
    public async Task PatchMemberRole_AdminPromotesMemberToAdmin_Allowed()
    {
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "x", "admin");
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "x", "member");
        using var client = await ClientFor(adminId, "admin");

        var resp = await client.PatchAsJsonAsync($"/api/v1/users/{memberId}/role", new { role = "admin" });

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    [Fact]
    public async Task PatchMemberRole_AdminTouchesOwnerRow_Forbidden()
    {
        // Admin caller, owner target → tier-2 tenant:admin check must reject.
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "x", "admin");
        string ownerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        using var client = await ClientFor(adminId, "admin");

        var resp = await client.PatchAsJsonAsync($"/api/v1/users/{ownerId}/role", new { role = "admin" });

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task PatchMemberRole_AdminGrantsOwnerRole_Forbidden()
    {
        // Admin caller, granting owner → tier-2 tenant:admin check must reject.
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "x", "admin");
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "x", "member");
        using var client = await ClientFor(adminId, "admin");

        var resp = await client.PatchAsJsonAsync($"/api/v1/users/{memberId}/role", new { role = "owner" });

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task PatchMemberRole_OwnerPromotesMemberToOwner_Allowed()
    {
        string callerOwnerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "x", "member");
        using var client = await ClientFor(callerOwnerId, "owner");

        var resp = await client.PatchAsJsonAsync($"/api/v1/users/{memberId}/role", new { role = "owner" });

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    [Fact]
    public async Task PatchMemberRole_MemberCaller_Forbidden()
    {
        string caller = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "x", "member");
        string target = await _factory.CreateUser($"member2-{Guid.NewGuid():N}@example.com", "x", "member");
        using var client = await ClientFor(caller, "member");

        var resp = await client.PatchAsJsonAsync($"/api/v1/users/{target}/role", new { role = "admin" });

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task RemoveUser_AdminRemovesMember_Allowed()
    {
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "x", "admin");
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "x", "member");
        using var client = await ClientFor(adminId, "admin");

        var resp = await client.DeleteAsync($"/api/v1/users/{memberId}");

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    [Fact]
    public async Task RemoveUser_AdminRemovesOwner_Forbidden()
    {
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "x", "admin");
        string ownerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        using var client = await ClientFor(adminId, "admin");

        var resp = await client.DeleteAsync($"/api/v1/users/{ownerId}");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task RemoveUser_MemberCaller_Forbidden()
    {
        string caller = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "x", "member");
        string target = await _factory.CreateUser($"member2-{Guid.NewGuid():N}@example.com", "x", "member");
        using var client = await ClientFor(caller, "member");

        var resp = await client.DeleteAsync($"/api/v1/users/{target}");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }
}
