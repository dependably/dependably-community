using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Cross-tenant BOLA isolation across all three protocols. Each test publishes (or seeds)
/// against the default org, then exercises the same path with a token issued for a
/// different real org and asserts the request is refused. The token.OrgId != orgId check
/// lives in each protocol controller — this fixture pins the invariant so a regression in
/// any controller surfaces immediately rather than as a downstream cross-tenant leak.
///
/// PyPI publish and NuGet push lacked dedicated cross-org coverage before this file;
/// NpmController had one publish-side test (kept there for proximity) and NuGetController
/// had an unlist test. The read-side npm test added here closes the GET path too.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CrossTenantIsolationTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public CrossTenantIsolationTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Create a second real org plus a push-capable CI/CD token bound to it. The token
    /// is returned raw so the caller can attach it to a request that targets the default
    /// org's path — the controller's token.OrgId != orgId guard should reject.
    /// </summary>
    private async Task<string> CreateOtherOrgPushTokenAsync()
    {
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var other = await orgRepo.CreateOrgAsync($"other-{Guid.NewGuid():N}"[..16]);
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            other.Id,
            $"xtenant-{Guid.NewGuid():N}"[..16],
            """["publish:*","read:artifact","read:metadata","yank:*"]""",
            expiresAt: null);
        return raw;
    }

    // ── PyPI publish: token from a different org must be rejected ────────────────

    [Fact]
    public async Task PyPi_Publish_TokenFromOtherOrg_Returns401()
    {
        string name = $"cross_pypi_{Guid.NewGuid():N}"[..16];
        var (bytes, sha256) = PyPiFixtures.BuildWheel(name, "1.0.0");
        string filename = $"{name.Replace('-', '_')}-1.0.0-py3-none-any.whl";

        string crossToken = await CreateOtherOrgPushTokenAsync();
        using var client = _factory.CreateClient();
        using var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
            { new StringContent(name), "name" },
            { new StringContent("1.0.0"), "version" },
            { new StringContent(sha256), "sha256_digest" },
        };
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);

        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{crossToken}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        // No package row must have been created in the default org.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE purl_name = @name", new { name });
        Assert.Equal(0, count);
    }

    // ── NuGet push: token from a different org must be rejected ──────────────────

    [Fact]
    public async Task NuGet_Push_TokenFromOtherOrg_Returns401()
    {
        string id = $"CrossNug{Guid.NewGuid():N}"[..16];
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, "1.0.0");
        string filename = $"{id}.1.0.0.nupkg";

        string crossToken = await CreateOtherOrgPushTokenAsync();
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", crossToken);

        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", filename);

        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE purl_name = @id", new { id = id.ToLowerInvariant() });
        Assert.Equal(0, count);
    }

    // ── NPM read: tarball of a hosted package, token from a different org ────────

    [Fact]
    public async Task Npm_GetHostedPackage_TokenFromOtherOrg_DoesNotReturn200()
    {
        // Hosted (non-proxy) packages require authentication AND the token's org_id must
        // match the request's org. A cross-org token must NOT yield a 200 — the controller
        // either 401s (unauth/realm mismatch) or 404s; the only outcome we forbid is
        // successful disclosure of another tenant's hosted metadata.
        string name = $"cross-npm-read-{Guid.NewGuid():N}"[..20];
        await _factory.PushNpmPackage(name, "1.0.0");

        string crossToken = await CreateOtherOrgPushTokenAsync();
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", crossToken);

        var resp = await client.GetAsync($"/npm/{name}");

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(
            resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound,
            $"Cross-org GET should be 401 or 404; got {(int)resp.StatusCode}.");
    }
}
