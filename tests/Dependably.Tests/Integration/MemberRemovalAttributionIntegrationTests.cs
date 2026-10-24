using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Removing a member who authored licence policy rows or a package-name grant used to hit the
/// restrict FK on <c>created_by</c> (a 500). The rows are written through the real repositories and
/// the removal goes through the real endpoint, so the schema's FK is live on whichever database
/// <c>TEST_INTEGRATION_DB</c> selects.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MemberRemovalAttributionIntegrationTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;

    public MemberRemovalAttributionIntegrationTests(DependablyFactory factory) => _factory = factory;

    [Fact]
    public async Task RemoveUser_WhoAuthoredLicencePolicyAndNameGrant_Succeeds_AndKeepsTheRowsWithoutAttribution()
    {
        TestHarnessDbScope.Enter();
        string suffix = Guid.NewGuid().ToString("N")[..8];
        string adminId = await _factory.CreateUser($"adm-{suffix}@example.com", "x", "admin");
        string memberId = await _factory.CreateUser($"mem-{suffix}@example.com", "x", "member");
        string bystanderId = await _factory.CreateUser($"by-{suffix}@example.com", "x", "member");

        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
        var licences = _factory.Services.GetRequiredService<LicenseRepository>();
        var grants = _factory.Services.GetRequiredService<NameBindingRepository>();

        string allowSpdx = "MIT";
        string blockSpdx = "GPL-3.0-only";
        string grantName = $"grant-{suffix}";
        string bystanderGrantName = $"bystander-{suffix}";
        await licences.RemoveAllowlistAsync(orgId, allowSpdx);
        await licences.RemoveBlocklistAsync(orgId, blockSpdx);
        await licences.AddAllowlistAsync(orgId, allowSpdx, LicenseDispositions.Allowed, "seed", memberId);
        await licences.AddBlocklistAsync(orgId, blockSpdx, "seed", memberId);
        await grants.AddGrantAsync(orgId, "npm", grantName, new NamePrincipal(ActorKinds.User, adminId), memberId);
        await grants.AddGrantAsync(orgId, "npm", bystanderGrantName, new NamePrincipal(ActorKinds.User, adminId), bystanderId);

        string jwt = await _factory.CreateUserJwt(adminId, "admin");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.DeleteAsync($"/api/v1/users/{memberId}");
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM users WHERE id = @memberId", new { memberId }));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM license_allowlist WHERE org_id = @orgId AND license_spdx = @allowSpdx AND created_by IS NULL",
            new { orgId, allowSpdx }));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM license_blocklist WHERE org_id = @orgId AND license_spdx = @blockSpdx AND created_by IS NULL",
            new { orgId, blockSpdx }));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM package_name_grant WHERE org_id = @orgId AND purl_name = @grantName AND created_by IS NULL",
            new { orgId, grantName }));

        // Twin: a different author's row keeps its attribution.
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM package_name_grant WHERE org_id = @orgId AND purl_name = @bystanderGrantName AND created_by = @bystanderId",
            new { orgId, bystanderGrantName, bystanderId }));
    }
}
