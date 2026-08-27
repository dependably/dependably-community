using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// The PyPI simple index is rendered by two mutually-exclusive paths — a proxy path that merges
/// upstream files into the local ones, and a local-only path — and the two wrote into the same
/// cache slot at two different TTLs. Which path a request takes is not a property of the request:
/// it is decided per request from claim state and the org's passthrough setting, both of which
/// change under the cache. A flip therefore served the stale wrong-path body until the previous
/// path's TTL expired.
///
/// Neither flip direction routes through the org cache epoch (that fires on a proxy-settings PUT,
/// not on a claim edit), so these tests mutate the setting the way a claim change reaches the
/// serving path: the stored state changes, the cached bytes do not, and only the key discriminator
/// keeps the two bodies apart.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiSimpleIndexProxyLocalCacheKeyTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PyPiSimpleIndexProxyLocalCacheKeyTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> DefaultOrgId()
    {
        _factory.CreateClient().Dispose(); // ensure first-boot ran
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    // Writes the setting directly rather than through PUT /api/v1/proxy-settings, and that is the
    // point: the endpoint bumps the org's cache epoch, which would evict every entry and hide the
    // collision this test exists to catch. A claim-state change reaches the serving path without
    // any such eviction.
    private async Task SetProxyPassthrough(bool enabled)
    {
        string orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    // An upstream index carrying one file this org has never held locally. Its presence or
    // absence in the served document is what says which render path produced it.
    private void StubUpstreamIndexWithOneFile(string name, string upstreamFile) =>
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(
                    "<!DOCTYPE html><html><body>"
                    + $"<a href=\"https://upstream.invalid/packages/{upstreamFile}\">{upstreamFile}</a>"
                    + "</body></html>"));

    private static async Task<string> GetHtml(HttpClient client, string name)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/simple/{name}/");
        req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("text/html"));
        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return await resp.Content.ReadAsStringAsync();
    }

    private static async Task<string> GetJson(HttpClient client, string name)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/simple/{name}/");
        req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(PyPiSimpleIndexHelper.JsonContentType));
        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(name, doc.RootElement.GetProperty("name").GetString());
        return body;
    }

    /// <summary>
    /// Proxy first, then local. The merged body advertises an upstream-only file; once the name
    /// is local-only, the served document must stop advertising it. A shared slot re-serves the
    /// merged body and keeps advertising a file the local plane cannot answer for.
    /// </summary>
    [Fact]
    public async Task LocalOnlyRequest_AfterAProxyMergedRender_DoesNotServeTheMergedBody()
    {
        string name = $"keyflip{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string localFile = $"{underscored}-1.0.0-py3-none-any.whl";
        string upstreamFile = $"{underscored}-9.9.9-py3-none-any.whl";

        StubUpstreamIndexWithOneFile(name, upstreamFile);
        await _factory.PushPyPiPackage(name, "1.0.0");
        // A hosted name is implicitly local_only; merging upstream is an explicit operator opt-in.
        await _factory.SeedMixedClaim("pypi", name);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        await SetProxyPassthrough(true);
        try
        {
            string merged = await GetHtml(client, name);
            Assert.Contains(localFile, merged, StringComparison.Ordinal);
            Assert.Contains(upstreamFile, merged, StringComparison.Ordinal);

            await SetProxyPassthrough(false);

            string local = await GetHtml(client, name);
            Assert.Contains(localFile, local, StringComparison.Ordinal);
            Assert.DoesNotContain(upstreamFile, local, StringComparison.Ordinal);
        }
        finally
        {
            await SetProxyPassthrough(false);
        }
    }

    /// <summary>
    /// The other direction, and the one the issue calls out as merely under-advertising rather
    /// than a parity hole: a name that becomes proxyable after a local-only render must start
    /// listing upstream files instead of re-serving the shorter local body.
    /// </summary>
    [Fact]
    public async Task ProxyRequest_AfterALocalOnlyRender_DoesNotServeTheLocalOnlyBody()
    {
        string name = $"keyflipb{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string localFile = $"{underscored}-1.0.0-py3-none-any.whl";
        string upstreamFile = $"{underscored}-9.9.9-py3-none-any.whl";

        StubUpstreamIndexWithOneFile(name, upstreamFile);
        await _factory.PushPyPiPackage(name, "1.0.0");
        // A hosted name is implicitly local_only; merging upstream is an explicit operator opt-in.
        await _factory.SeedMixedClaim("pypi", name);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        await SetProxyPassthrough(false);
        try
        {
            string local = await GetHtml(client, name);
            Assert.Contains(localFile, local, StringComparison.Ordinal);
            Assert.DoesNotContain(upstreamFile, local, StringComparison.Ordinal);

            await SetProxyPassthrough(true);

            string merged = await GetHtml(client, name);
            Assert.Contains(localFile, merged, StringComparison.Ordinal);
            Assert.Contains(upstreamFile, merged, StringComparison.Ordinal);
        }
        finally
        {
            await SetProxyPassthrough(false);
        }
    }

    /// <summary>
    /// The discriminator has to be independent of the representation axis, not folded into it —
    /// four slots, not two. The PEP 691 JSON form is negotiated at the same URL and is rendered by
    /// the same two paths, so it collides in exactly the same way.
    /// </summary>
    [Fact]
    public async Task JsonRepresentation_KeepsProxyAndLocalBodiesApartToo()
    {
        string name = $"keyflipj{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string localFile = $"{underscored}-1.0.0-py3-none-any.whl";
        string upstreamFile = $"{underscored}-9.9.9-py3-none-any.whl";

        StubUpstreamIndexWithOneFile(name, upstreamFile);
        await _factory.PushPyPiPackage(name, "1.0.0");
        // A hosted name is implicitly local_only; merging upstream is an explicit operator opt-in.
        await _factory.SeedMixedClaim("pypi", name);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        await SetProxyPassthrough(true);
        try
        {
            string merged = await GetJson(client, name);
            Assert.Contains(upstreamFile, merged, StringComparison.Ordinal);

            await SetProxyPassthrough(false);

            string local = await GetJson(client, name);
            Assert.Contains(localFile, local, StringComparison.Ordinal);
            Assert.DoesNotContain(upstreamFile, local, StringComparison.Ordinal);
        }
        finally
        {
            await SetProxyPassthrough(false);
        }
    }
}
