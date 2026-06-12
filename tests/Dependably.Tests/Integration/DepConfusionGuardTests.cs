using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the dependency-confusion guard: a hosted name with no explicit
/// claim is implicitly local_only (no upstream merge, no proxy fetch — silent 404 semantics),
/// and operator-reserved namespace patterns shut upstream off for matching names while hosted
/// content keeps serving. Also covers the /api/v1/reserved-namespaces CRUD surface.
/// </summary>
[Trait("Category", "Integration")]
public sealed class DepConfusionGuardTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public DepConfusionGuardTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"dcg-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    private void StubUpstreamPackument(string name, string version)
    {
        string upstreamJson = $$"""
        {
          "_id": "{{name}}",
          "name": "{{name}}",
          "dist-tags": {"latest":"{{version}}"},
          "versions": {
            "{{version}}": {
              "name": "{{name}}",
              "version": "{{version}}",
              "dist": {"tarball":"https://registry.npmjs.org/{{name}}/-/{{name}}-{{version}}.tgz","shasum":"deadbeef"}
            }
          }
        }
        """;
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));
    }

    // ── implicit local_only for hosted names ──────────────────────────────────

    [Fact]
    public async Task HostedName_NoClaim_DoesNotMergeUpstream_AndRefusesProxyFetch()
    {
        // The dependency-confusion hole this guard closes: a HIGHER version published
        // publicly under an internal name must not win resolution or be fetchable.
        string name = $"internal{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(name, "1.0.0");
        StubUpstreamPackument(name, "99.9.9");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty("1.0.0", out _), "hosted version must serve");
        Assert.False(versions.TryGetProperty("99.9.9", out _), "upstream version must not be merged");

        // Proxy fetch of the upstream version: silent 404, same as a local_only claim —
        // not a 403, which would confirm the name's existence to anonymous probes.
        var tarball = await client.GetAsync($"/npm/tarballs/{name}/{name}-99.9.9.tgz");
        Assert.Equal(HttpStatusCode.NotFound, tarball.StatusCode);
    }

    // ── reserved namespaces ───────────────────────────────────────────────────

    [Fact]
    public async Task ReservedPattern_NeverConsultsUpstream_HostedStillServes()
    {
        string stem = $"rsvd{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        using var admin = await AdminClient();
        var add = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "npm", pattern = $"{stem}*" });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        // A never-pushed name under the reserved pattern: upstream has it, but the proxy
        // must not even ask — 404 without consulting the (stubbed) upstream.
        string upstreamOnly = $"{stem}-public";
        StubUpstreamPackument(upstreamOnly, "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{upstreamOnly}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);

        // Hosted content under the reserved pattern serves normally.
        string hosted = $"{stem}-app";
        await _factory.PushNpmPackage(hosted, "2.0.0");
        var hostedResp = await client.GetAsync($"/npm/{hosted}");
        Assert.Equal(HttpStatusCode.OK, hostedResp.StatusCode);
        using var doc = JsonDocument.Parse(await hostedResp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("versions").TryGetProperty("2.0.0", out _));
    }

    // ── CRUD surface ──────────────────────────────────────────────────────────

    [Fact]
    public async Task ReservedNamespaces_AddListDelete_RoundTrip()
    {
        using var c = await AdminClient();
        string pattern = $"@crud{Guid.NewGuid():N}/*";

        var add = await c.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "npm", pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        var created = await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync());
        string? id = created.RootElement.GetProperty("id").GetString();
        Assert.False(string.IsNullOrEmpty(id));

        var list = await c.GetAsync("/api/v1/reserved-namespaces");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        Assert.Contains(items.EnumerateArray(), e => e.GetProperty("pattern").GetString() == pattern);

        var remove = await c.DeleteAsync($"/api/v1/reserved-namespaces/{id}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);

        // Idempotent delete (unknown id) — same shape as the allowlist surface.
        var again = await c.DeleteAsync($"/api/v1/reserved-namespaces/{id}");
        Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
    }

    [Theory]
    [InlineData("docker", "lib*")]   // unsupported ecosystem
    [InlineData("npm", "")]          // empty pattern
    [InlineData("npm", "a*b")]       // non-trailing glob
    public async Task ReservedNamespaces_InvalidInput_Returns422(string ecosystem, string pattern)
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/reserved-namespaces", new { ecosystem, pattern });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task ReservedNamespaces_AddByMember_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "npm", pattern = "@nope/*" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }
}
