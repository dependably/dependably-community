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

    [Fact]
    public async Task Bearer_Secret_PlaintextHttpUrl_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // http:// + bearer credential would transit the secret in cleartext — rejected.
        var req = new AddUpstreamRegistryRequest(
            Ecosystem: "npm", Url: "http://cache.example/npm", AuthType: "bearer", Secret: "tok-xyz");
        var result = await b.UpstreamRegistryController.Add(req, CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);

        // Nothing was persisted.
        await using var conn = await b.Db.OpenAsync();
        int rows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @org AND ecosystem = 'npm'",
            new { org = b.PrimaryOrgId });
        Assert.Equal(0, rows);
    }

    [Fact]
    public async Task Basic_Secret_PlaintextHttpUrl_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new AddUpstreamRegistryRequest(
            Ecosystem: "npm", Url: "http://cache.example/npm", AuthType: "basic", Username: "u", Secret: "pw");
        var result = await b.UpstreamRegistryController.Add(req, CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Anonymous_PlaintextHttpUrl_RejectedByDefault()
    {
        // #437 item 1: plaintext http:// upstreams are refused unless the instance opts in.
        // An http upstream carries both the artifact and its declared checksum in cleartext,
        // so an on-path attacker substitutes both consistently and content-addressing verifies
        // bytes it should never have trusted.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new AddUpstreamRegistryRequest(
            Ecosystem: "npm", Url: "http://mirror.internal/npm", AuthType: null, Username: null, Secret: null);
        var result = await b.UpstreamRegistryController.Add(req, CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);

        await using var conn = await b.Db.OpenAsync();
        int rows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @org AND ecosystem = 'npm'",
            new { org = b.PrimaryOrgId });
        Assert.Equal(0, rows);
    }

    [Fact]
    public async Task Anonymous_PlaintextHttpUrl_AllowedWithOptIn()
    {
        // Adversarial twin to the default-reject: with Proxy:AllowInsecureUpstreams the same
        // anonymous http upstream (internal mirror) persists.
        await using var s = await ControllerScenario.CreateAsync();
        s.WithInsecureUpstreams();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new AddUpstreamRegistryRequest(
            Ecosystem: "npm", Url: "http://mirror.internal/npm", AuthType: null, Username: null, Secret: null);
        var result = await b.UpstreamRegistryController.Add(req, CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task HttpsUrl_AlwaysAllowed()
    {
        // Adversarial twin: an https:// upstream saves regardless of the insecure-upstreams flag.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Npm(null, null, null), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task EmbeddedCredentialsInUrl_RejectedAtSaveTime()
    {
        // #437 item 2: a user:pass@ userinfo component must be rejected at save time — storing it
        // plaintext in upstream_registry.url leaks the credential to read:packages callers.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new AddUpstreamRegistryRequest(
            Ecosystem: "npm", Url: "https://svc:s3cr3t@nexus.corp.example/repository/npm/",
            AuthType: null, Username: null, Secret: null);
        var result = await b.UpstreamRegistryController.Add(req, CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);

        await using var conn = await b.Db.OpenAsync();
        int rows = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @org AND ecosystem = 'npm'",
            new { org = b.PrimaryOrgId });
        Assert.Equal(0, rows);
    }
}
