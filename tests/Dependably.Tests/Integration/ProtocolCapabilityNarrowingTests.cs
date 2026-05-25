using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// #54: prove that protocol publish endpoints (NpmController, PyPiController,
/// NuGetController) enforce per-ecosystem capability narrowing via
/// <c>HasCapability(Capabilities.PublishNpm/Pypi/Nuget)</c>. A token with
/// <c>capabilities=["publish:npm"]</c> must publish npm but be rejected by PyPI and
/// NuGet — without these tests a regression to a broader cap set would silently
/// re-broaden private tokens.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProtocolCapabilityNarrowingTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public ProtocolCapabilityNarrowingTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Inserts a service token directly with the given <paramref name="capabilities"/>
    /// JSON. Bypasses the issuance API so the test can construct exactly the token
    /// shape it needs without depending on issuance logic that's covered separately.
    /// </summary>
    private async Task<string> SeedServiceTokenAsync(string capabilities)
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
                name = $"narrow-{Guid.NewGuid():N}",
                hash,
                capabilities,
            });
        return raw;
    }

    [Fact]
    public async Task NpmOnlyToken_PublishesNpm_RejectedByPyPi()
    {
        var token = await SeedServiceTokenAsync("""["publish:npm","read:metadata","read:artifact"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // npm publish: capability matches → expect success.
        var npmBody = NpmFixtures.BuildPublishBody("acme-narrow-npm", "1.0.0");
        using var npmContent = new StringContent(npmBody, System.Text.Encoding.UTF8, "application/json");
        var npmResp = await client.PutAsync("/npm/acme-narrow-npm", npmContent);
        Assert.Equal(HttpStatusCode.OK, npmResp.StatusCode);

        // PyPI publish: capability missing → 403.
        // PyPI takes Basic auth, not Bearer. Build a Basic header from the token.
        using var pypiClient = _factory.CreateClient();
        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"__token__:{token}"));
        pypiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basic);

        var (sdistBytes, _) = PyPiFixtures.BuildSdist("acme-narrow-pypi", "1.0.0");
        using var pypiContent = new MultipartFormDataContent
        {
            { new StringContent("acme-narrow-pypi"), "name" },
            { new StringContent("1.0.0"), "version" },
            { new StringContent("sdist"), "filetype" },
            { new ByteArrayContent(sdistBytes), "content", "acme_narrow_pypi-1.0.0.tar.gz" },
        };
        var pypiResp = await pypiClient.PostAsync("/pypi/legacy/", pypiContent);
        Assert.Equal(HttpStatusCode.Forbidden, pypiResp.StatusCode);
    }

    [Fact]
    public async Task NugetOnlyToken_PublishesNuget_RejectedByNpm()
    {
        var token = await SeedServiceTokenAsync("""["publish:nuget","read:metadata","read:artifact"]""");

        // NuGet publish: capability matches → expect success.
        using var nugetClient = _factory.CreateClient();
        nugetClient.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg("Acme.Narrow.NuGet", "1.0.0");
        using var nugetContent = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(nupkgBytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        nugetContent.Add(fileContent, "package", "Acme.Narrow.NuGet.1.0.0.nupkg");

        var nugetResp = await nugetClient.PutAsync("/nuget/publish", nugetContent);
        Assert.Equal(HttpStatusCode.Created, nugetResp.StatusCode);

        // npm publish with the same token: capability missing → 403.
        using var npmClient = _factory.CreateClient();
        npmClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var npmBody = NpmFixtures.BuildPublishBody("acme-narrow-by-nuget", "1.0.0");
        using var npmContent = new StringContent(npmBody, System.Text.Encoding.UTF8, "application/json");
        var npmResp = await npmClient.PutAsync("/npm/acme-narrow-by-nuget", npmContent);
        Assert.Equal(HttpStatusCode.Forbidden, npmResp.StatusCode);
    }

    [Fact]
    public async Task NullCapabilitiesToken_DeniesEveryEcosystem()
    {
        // A token row with NULL capabilities is unreachable through the repository
        // (issuance always stamps the column). If such a row is produced anyway (direct
        // INSERT below — corrupted row, migration miss), it must deny every protocol
        // publish rather than silently allowing anything.
        var raw = Dependably.Security.TokenGenerator.Generate();
        var hash = TokenRepository.HashToken(raw);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            var orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1");
            await conn.ExecuteAsync("""
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities)
                VALUES (@id, @orgId, @name, @hash, NULL)
                """, new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    name = $"nullcaps-{Guid.NewGuid():N}",
                    hash,
                });
        }

        // npm publish — denied.
        using var npmClient = _factory.CreateClient();
        npmClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        var npmBody = NpmFixtures.BuildPublishBody("acme-nullcaps-npm", "1.0.0");
        using var npmContent = new StringContent(npmBody, System.Text.Encoding.UTF8, "application/json");
        var npmResp = await npmClient.PutAsync("/npm/acme-nullcaps-npm", npmContent);
        Assert.Equal(HttpStatusCode.Forbidden, npmResp.StatusCode);

        // NuGet publish — denied.
        using var nugetClient = _factory.CreateClient();
        nugetClient.DefaultRequestHeaders.Add("X-NuGet-ApiKey", raw);
        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg("Acme.NullCaps.NuGet", "1.0.0");
        using var nugetContent = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(nupkgBytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        nugetContent.Add(fileContent, "package", "Acme.NullCaps.NuGet.1.0.0.nupkg");
        var nugetResp = await nugetClient.PutAsync("/nuget/publish", nugetContent);
        Assert.Equal(HttpStatusCode.Forbidden, nugetResp.StatusCode);
    }
}
