using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Authenticated non-OCI upstream registries via the management API: auth-field validation,
/// fail-closed secret-at-rest (no master key ⇒ 422), the bearer scheme, and RPM's
/// anonymous-only rule.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamRegistryControllerAuthTests
{
    private static AddUpstreamRegistryRequest Npm(string? authType, string? username, string? secret) =>
        new(Ecosystem: "npm", Url: "https://cache.example/npm", AuthType: authType, Username: username, Secret: secret);

    [Fact]
    public async Task Bearer_Secret_NoMasterKey_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Npm("bearer", null, "tok"), CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Bearer_Secret_WithMasterKey_Persists201_EncryptedAtRest()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Npm("bearer", null, "tok-xyz"), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);
        await using var conn = await b.Db.OpenAsync();
        var (authType, secret) = await conn.QuerySingleAsync<(string AuthType, string Secret)>(
            "SELECT auth_type AS AuthType, secret AS Secret FROM upstream_registry WHERE org_id = @org AND ecosystem = 'npm'",
            new { org = b.PrimaryOrgId });
        Assert.Equal("bearer", authType);
        Assert.StartsWith("enc:v1:", secret);
        Assert.DoesNotContain("tok-xyz", secret);
    }

    [Fact]
    public async Task Bearer_WithoutSecret_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Npm("bearer", null, null), CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Basic_RequiresUsernameAndSecret()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // basic without username is rejected.
        var result = await b.UpstreamRegistryController.Add(Npm("basic", null, "pw"), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Rpm_AuthFields_AreRejected()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new AddUpstreamRegistryRequest(
            Ecosystem: "rpm", Url: "https://cache.example/rpm", AuthType: "bearer", Secret: "tok");
        var result = await b.UpstreamRegistryController.Add(req, CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Anonymous_NoCreds_Persists201()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Npm(null, null, null), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);
    }
}
