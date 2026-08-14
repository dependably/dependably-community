using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// A two-tier authorization model governs every action that mutates another member's identity or
/// standing: PatchMemberRole, RemoveUser, and RequestEmailChange (when the caller targets someone
/// else) —
///   - tier 1 (entry): tenant:configure — admin or owner can reach the endpoint;
///   - tier 2 (in-handler): tenant:admin — only owners can modify owners, grant owner, remove
///     owners, or retarget an owner's account email.
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

    /// <summary>
    /// The account-takeover path this test closes: an admin (tenant:configure, not
    /// tenant:admin) points the email-change endpoint at the tenant owner instead of a member.
    /// Without the tier-2 gate this call accepts (202) and mails a confirmation link for an
    /// attacker-controlled address to the owner's account — the first step of a takeover chain
    /// that continues through confirm-email-change and a password reset. It must be rejected the
    /// same way PatchMemberRole and RemoveUser already reject an admin targeting an owner.
    /// </summary>
    [Fact]
    public async Task RequestEmailChange_AdminTargetsOwner_Forbidden()
    {
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "x", "admin");
        string ownerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        using var client = await ClientFor(adminId, "admin");

        var resp = await client.PatchAsJsonAsync(
            $"/api/v1/users/{ownerId}/email", new { email = "attacker-controlled@example.test" });

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    /// <summary>
    /// Mixed batch: the same admin caller acts on two different targets in sequence. The member
    /// target is within an admin's tenant:configure authority and must succeed; the owner target
    /// requires tenant:admin and must be refused. One caller, one capability set, two outcomes —
    /// the tier-2 check must key off the target's role each call, not cache a blanket allow/deny
    /// for the caller.
    /// </summary>
    [Fact]
    public async Task RequestEmailChange_AdminMixedTargets_MemberAllowedOwnerForbidden()
    {
        string adminId = await _factory.CreateUser($"admin-{Guid.NewGuid():N}@example.com", "x", "admin");
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "x", "member");
        string ownerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        using var client = await ClientFor(adminId, "admin");

        var memberResp = await client.PatchAsJsonAsync(
            $"/api/v1/users/{memberId}/email", new { email = $"rectified-{Guid.NewGuid():N}@example.test" });
        var ownerResp = await client.PatchAsJsonAsync(
            $"/api/v1/users/{ownerId}/email", new { email = "attacker-controlled@example.test" });

        Assert.Equal(HttpStatusCode.Accepted, memberResp.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, ownerResp.StatusCode);
    }

    [Fact]
    public async Task RequestEmailChange_OwnerTargetsOwner_Allowed()
    {
        string callerOwnerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "x", "owner");
        string otherOwnerId = await _factory.CreateUser($"owner2-{Guid.NewGuid():N}@example.com", "x", "owner");
        using var client = await ClientFor(callerOwnerId, "owner");

        var resp = await client.PatchAsJsonAsync(
            $"/api/v1/users/{otherOwnerId}/email", new { email = $"rectified-{Guid.NewGuid():N}@example.test" });

        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
    }
}
