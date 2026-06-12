using System.Net;
using System.Security.Cryptography;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// `npm ci` installs from package-lock.json's <c>resolved</c> URLs. When the lockfile resolves
/// to the public registry but the configured <c>registry</c> is this one, npm swaps only the
/// host and keeps the canonical <c>/{pkg}/-/{file}</c> tarball layout — it never fetches the
/// packument, so it never sees the <c>/npm/tarballs/…</c> URL we rewrite into metadata. These
/// tests pin that the conventional path resolves to the same tarball handler (unscoped proxy
/// first-fetch + scoped hosted), so `npm ci` works against a public lockfile.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmConventionalTarballRouteTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NpmConventionalTarballRouteTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ConventionalPath_UnscopedProxyFirstFetch_ServesTarball()
    {
        string name = $"convnpm{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.1.4";
        var (bytes, _, integrity) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";
        string shasum = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();

        string packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": {
                  "name": "{{name}}", "version": "{{version}}",
                  "dist": { "integrity": "{{integrity}}", "shasum": "{{shasum}}" }
                }
              }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // The conventional path npm ci uses after host-swapping the public lockfile URL —
        // NOT the rewritten /npm/tarballs/ path. Must reach the same handler and serve.
        var resp = await client.GetAsync($"/npm/{name}/-/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(bytes, await resp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task ConventionalPath_ScopedHosted_DownloadsViaScopedRoute()
    {
        await _factory.PushNpmPackage("@ext/conv-scoped", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Scoped conventional path: /npm/@{scope}/{pkg}/-/{file}.
        var resp = await client.GetAsync("/npm/@ext/conv-scoped/-/conv-scoped-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
    }
}
