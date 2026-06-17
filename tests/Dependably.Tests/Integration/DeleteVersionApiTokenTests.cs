using System.Net;
using System.Net.Http.Headers;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression: DELETE /api/v1/packages/{ecosystem}/{name}/{version} must be reachable
/// by API tokens (PATs) carrying the per-ecosystem yank capability. The endpoint
/// previously required a JWT session because the class-level [Authorize] on OrgController
/// ran only the Bearer/JWT scheme; a method-level override now unions in the ApiToken scheme
/// so automation scripts can yank packages without a full UI session.
/// </summary>
[Trait("Category", "Integration")]
public sealed class DeleteVersionApiTokenTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public DeleteVersionApiTokenTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private static MultipartFormDataContent OneNpmFile(byte[] bytes, string filename)
    {
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return new MultipartFormDataContent { { part, "files", filename } };
    }

    private async Task<string> SeedNpmPackage(string name, string version)
    {
        using var admin = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        using var content = OneNpmFile(bytes, $"{name}-{version}.tgz");
        var resp = await admin.PostAsync("/api/v1/admin/upload", content);
        resp.EnsureSuccessStatusCode();
        return version;
    }

    [Fact]
    public async Task DeleteVersion_ApiTokenWithYankCap_Returns204AndVersionIsGone()
    {
        // Seed a version with the admin JWT so there is something to delete.
        string pkg = $"acme-yank-pat-{Guid.NewGuid():N}";
        await SeedNpmPackage(pkg, "1.0.0");

        // A PAT carrying yank:npm must drive DELETE and receive 204.
        string pat = await _factory.CreateAdminUserToken(
            """["yank:npm","read:metadata","read:artifact","read:packages"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);

        var del = await client.DeleteAsync($"/api/v1/packages/npm/{pkg}/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // Confirm the version is actually gone: a second DELETE returns 404, not 204.
        using var admin = await AdminClient();
        var del2 = await admin.DeleteAsync($"/api/v1/packages/npm/{pkg}/1.0.0");
        Assert.Equal(HttpStatusCode.NotFound, del2.StatusCode);
    }

    [Fact]
    public async Task DeleteVersion_ApiTokenLackingYankCap_Returns403()
    {
        // Seed a version so the route would succeed for an authorised caller.
        string pkg = $"acme-yank-nopat-{Guid.NewGuid():N}";
        await SeedNpmPackage(pkg, "1.0.0");

        // A read-only PAT authenticates under the ApiToken scheme but has no yank cap —
        // the capability gate must reject it with 403, NOT bounce it with 401.
        string pat = await _factory.CreateAdminUserToken(
            """["read:metadata","read:artifact","read:packages"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);

        var del = await client.DeleteAsync($"/api/v1/packages/npm/{pkg}/1.0.0");
        Assert.Equal(HttpStatusCode.Forbidden, del.StatusCode);
    }

    [Fact]
    public async Task DeleteVersion_ApiTokenWithYankNpm_WrongEcosystem_Returns404()
    {
        // A PAT with yank:npm cannot delete a pypi package — the ecosystem switch maps
        // "pypi" to Capabilities.YankPypi, which the token does not carry. The endpoint
        // returns 404 for an unrecognised ecosystem before even reaching auth, but for a
        // known ecosystem with a missing cap it returns 403. This test confirms that a
        // PAT with yank:npm sees 403 (not 401) when it tries to yank a nuget version,
        // proving the ApiToken scheme was invoked (authentication succeeded, authz failed).
        string pkg = $"acme-yank-wrong-eco-{Guid.NewGuid():N}";

        // Seed a nuget package so the route can reach the capability check.
        using var admin = await AdminClient();
        var (bytes, _) = NuGetFixtures.BuildNupkg(pkg, "1.0.0");
        using var content = new MultipartFormDataContent();
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(part, "files", $"{pkg}.1.0.0.nupkg");
        var upload = await admin.PostAsync("/api/v1/admin/upload", content);
        upload.EnsureSuccessStatusCode();

        // Token carries yank:npm only — cannot yank nuget.
        string pat = await _factory.CreateAdminUserToken(
            """["yank:npm","read:metadata","read:artifact","read:packages"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);

        var del = await client.DeleteAsync($"/api/v1/packages/nuget/{pkg}/1.0.0");
        // 403 = authentication succeeded (ApiToken scheme ran), authz failed (wrong yank cap).
        Assert.Equal(HttpStatusCode.Forbidden, del.StatusCode);
    }
}
