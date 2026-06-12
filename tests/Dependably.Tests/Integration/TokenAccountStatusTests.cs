using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Prove that API tokens are credentials *of a user*: a user token only authenticates
/// while its owner exists in the token's tenant with <c>account_status = 'active'</c>.
/// Locking or disabling the account cuts off its tokens on every protocol surface
/// (token resolution happens in <see cref="TokenRepository.ResolveAsync"/>, shared by
/// the Bearer/Basic/X-NuGet-ApiKey paths); re-activating restores them; removing the
/// user deletes them via FK cascade. Service tokens have no owner and are unaffected.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TokenAccountStatusTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public TokenAccountStatusTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Seeds a fresh member user in the default org and issues a user token for them.
    /// Returns (userId, rawToken).
    /// </summary>
    private async Task<(string UserId, string RawToken)> SeedUserWithTokenAsync(string capabilities)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
        }

        string userId = await UserSeeder.InsertAsync(
            store, orgId, $"status-{Guid.NewGuid():N}@example.test");

        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var (raw, _) = await tokens.CreateUserTokenAsync(orgId, userId, capabilities, expiresAt: null);
        return (userId, raw);
    }

    private async Task SetAccountStatusAsync(string userId, string status)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE users SET account_status = @status WHERE id = @userId",
            new { status, userId });
    }

    [Fact]
    public async Task DisabledUser_TokenRejected_ReactivationRestoresIt()
    {
        var (userId, token) = await SeedUserWithTokenAsync("""["read:artifact","read:metadata"]""");
        using var client = _factory.CreateClientWithBearer(token);

        var active = await client.GetAsync("/npm/-/whoami");
        Assert.Equal(HttpStatusCode.OK, active.StatusCode);

        await SetAccountStatusAsync(userId, "disabled");
        var disabled = await client.GetAsync("/npm/-/whoami");
        Assert.Equal(HttpStatusCode.Unauthorized, disabled.StatusCode);

        await SetAccountStatusAsync(userId, "active");
        var reactivated = await client.GetAsync("/npm/-/whoami");
        Assert.Equal(HttpStatusCode.OK, reactivated.StatusCode);
    }

    [Fact]
    public async Task LockedUser_TokenRejectedOnPublishSurfaces()
    {
        var (userId, token) = await SeedUserWithTokenAsync(
            """["publish:*","read:artifact","read:metadata"]""");
        await SetAccountStatusAsync(userId, "locked");

        // npm publish (Bearer) — the ApiToken authentication scheme must reject the token.
        using var npmClient = _factory.CreateClientWithBearer(token);
        string npmBody = NpmFixtures.BuildPublishBody("acme-locked-npm", "1.0.0");
        using var npmContent = new StringContent(npmBody, System.Text.Encoding.UTF8, "application/json");
        var npmResp = await npmClient.PutAsync("/npm/acme-locked-npm", npmContent);
        Assert.Equal(HttpStatusCode.Unauthorized, npmResp.StatusCode);

        // PyPI publish (Basic, token-as-password) — same resolver, same rejection.
        using var pypiClient = _factory.CreateClient();
        string basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"__token__:{token}"));
        pypiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basic);
        var (sdistBytes, _) = PyPiFixtures.BuildSdist("acme-locked-pypi", "1.0.0");
        using var pypiContent = new MultipartFormDataContent
        {
            { new StringContent("acme-locked-pypi"), "name" },
            { new StringContent("1.0.0"), "version" },
            { new StringContent("sdist"), "filetype" },
            { new ByteArrayContent(sdistBytes), "content", "acme_locked_pypi-1.0.0.tar.gz" },
        };
        var pypiResp = await pypiClient.PostAsync("/pypi/legacy/", pypiContent);
        Assert.Equal(HttpStatusCode.Unauthorized, pypiResp.StatusCode);

        // NuGet push (X-NuGet-ApiKey) — same resolver, same rejection.
        using var nugetClient = _factory.CreateClient();
        nugetClient.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg("Acme.Locked.NuGet", "1.0.0");
        using var nugetContent = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(nupkgBytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        nugetContent.Add(fileContent, "package", "Acme.Locked.NuGet.1.0.0.nupkg");
        var nugetResp = await nugetClient.PutAsync("/nuget/publish", nugetContent);
        Assert.Equal(HttpStatusCode.Unauthorized, nugetResp.StatusCode);
    }

    [Fact]
    public async Task RemovedUser_TokenDeletedByCascade()
    {
        var (userId, token) = await SeedUserWithTokenAsync("""["read:artifact","read:metadata"]""");
        using var client = _factory.CreateClientWithBearer(token);

        var active = await client.GetAsync("/npm/-/whoami");
        Assert.Equal(HttpStatusCode.OK, active.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM users WHERE id = @userId", new { userId });
            long remaining = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM user_tokens WHERE user_id = @userId", new { userId });
            Assert.Equal(0, remaining);
        }

        var removed = await client.GetAsync("/npm/-/whoami");
        Assert.Equal(HttpStatusCode.Unauthorized, removed.StatusCode);
    }

    [Fact]
    public async Task ServiceToken_UnaffectedByUserStatusSemantics()
    {
        // Service tokens have no owning user — the account_status join must not
        // accidentally filter them out.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/-/whoami");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
