using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// #55: TokenAuthenticationHandler must produce a ClaimsPrincipal carrying the right
/// role + capability claims so that <c>[Authorize(AuthenticationSchemes = "ApiToken")]</c>
/// + <c>[RequireCapability]</c> on protocol publish endpoints actually gates correctly.
///
/// We don't unit-test the handler directly because its DB lookup of users.role makes
/// integration coverage cheaper than mocking. The proof is "publish endpoints reject
/// when capability is missing, accept when present" against real seeded tokens.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TokenAuthenticationHandlerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public TokenAuthenticationHandlerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> SeedServiceTokenAsync(string? capabilitiesJson)
    {
        var raw = Dependably.Security.TokenGenerator.Generate();
        var hash = TokenRepository.HashToken(raw);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1");
        await conn.ExecuteAsync("""
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities)
            VALUES (@id, @orgId, @name, @hash, @capabilities)
            """, new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                name = $"auth-test-{Guid.NewGuid():N}",
                hash,
                capabilities = capabilitiesJson,
            });
        return raw;
    }

    [Fact]
    public async Task PublishEndpoint_NoAuth_Returns401()
    {
        // [Authorize] on the action method gates the route — a request with no
        // Authorization header / X-NuGet-ApiKey gets 401 before the controller runs.
        using var client = _factory.CreateClient();

        var body = NpmFixtures.BuildPublishBody("acme-auth-noauth", "1.0.0");
        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/acme-auth-noauth", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task PublishEndpoint_NullCapabilitiesToken_Forbidden()
    {
        // A token row with NULL capabilities denies all. Mint paths always populate the
        // column at insert time, so this shape is only reachable by bypassing the repo
        // (direct INSERT). The auth path returns an empty cap claim set, so
        // [RequireCapability(PublishNpm)] rejects.
        var token = await SeedServiceTokenAsync(capabilitiesJson: null);
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var body = NpmFixtures.BuildPublishBody("acme-auth-nullcaps", "1.0.0");
        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/acme-auth-nullcaps", content);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task PublishEndpoint_PushScopeMintedThroughRepo_Authorizes()
    {
        // The supported path: mint through the repository (which translates the 'push'
        // scope to an explicit cap array at issue time). The same scope value goes in,
        // but the caps column lands populated and the handler emits the expected claims.
        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var body = NpmFixtures.BuildPublishBody("acme-auth-pushrepo", "1.0.0");
        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/acme-auth-pushrepo", content);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task PublishEndpoint_PullOnlyToken_403sViaRequireCapability()
    {
        // scope='pull' grants read:metadata + read:artifact only — no publish.
        // [RequireCapability(PublishNpm)] must reject before the controller runs. Mint
        // through the repo so the row has the issue-time-derived caps populated.
        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var body = NpmFixtures.BuildPublishBody("acme-auth-pullonly", "1.0.0");
        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/acme-auth-pullonly", content);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task PublishEndpoint_NarrowedTokenForOtherEcosystem_403s()
    {
        // capabilities=["publish:nuget"] — token can publish nuget, must NOT publish npm.
        var token = await SeedServiceTokenAsync(capabilitiesJson: """["publish:nuget"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var body = NpmFixtures.BuildPublishBody("acme-auth-narrow", "1.0.0");
        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/acme-auth-narrow", content);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task PublishEndpoint_NuGetApiKey_Authorizes()
    {
        // X-NuGet-ApiKey header must work — the handler tries it after Authorization.
        // Mint through the repo so caps are populated.
        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        var (nupkg, _) = NuGetFixtures.BuildNupkg("Acme.Auth.Test", "1.0.0");
        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(nupkg);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", "Acme.Auth.Test.1.0.0.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }
}
