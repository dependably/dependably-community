using System.Net;
using System.Text;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for <c>UploadSizeLimitMiddleware</c> on the real host-relative
/// protocol routes. Tenancy is host/subdomain-resolved, so the middleware reads the
/// TenantContext (set by SubdomainTenantMiddleware) and keys the ecosystem off the path
/// prefix. Each over-limit case asserts the middleware's own problem document ("Upload
/// exceeds the {ecosystem} limit ...") — that message is produced only by the pre-routing
/// Content-Length check, proving the rejection happens before any controller buffers the
/// body. No auth is attached: the middleware runs before authentication, so the cap must
/// hold even for anonymous requests.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UploadSizeLimitMiddlewareTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public UploadSizeLimitMiddlewareTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private const long Cap = 128;
    private const long Restore = 500L * 1024 * 1024;

    private static ByteArrayContent OversizedBody() =>
        new(Encoding.UTF8.GetBytes(new string('x', (int)Cap * 4)));

    private static async Task Assert413FromMiddleware(HttpResponseMessage resp, string ecosystem)
    {
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains($"Upload exceeds the {ecosystem} limit of {Cap} bytes", body);
    }

    [Theory]
    [InlineData("npm", "PUT", "/npm/some-package")]
    [InlineData("npm", "PUT", "/npm/@scope/some-package")]
    [InlineData("pypi", "POST", "/pypi/legacy/")]
    [InlineData("nuget", "PUT", "/nuget/publish")]
    public async Task PerEcosystemOrgLimit_ContentLengthOverCap_Returns413OnHostRelativeRoute(
        string ecosystem, string method, string route)
    {
        await _factory.SetOrgLimit("default", ecosystem, Cap);
        try
        {
            using var client = _factory.CreateClient();
            using var request = new HttpRequestMessage(new HttpMethod(method), route)
            {
                Content = OversizedBody()
            };
            var resp = await client.SendAsync(request);
            await Assert413FromMiddleware(resp, ecosystem);
        }
        finally
        {
            await _factory.SetOrgLimit("default", ecosystem, null);
        }
    }

    [Theory]
    [InlineData("maven", "PUT", "/maven/com/example/app/1.0.0/app-1.0.0.jar")]
    [InlineData("rpm", "PUT", "/rpm/upload")]
    [InlineData("oci", "POST", "/v2/some-image/blobs/uploads/")]
    public async Task OrgGlobalLimit_ContentLengthOverCap_Returns413OnHostRelativeRoute(
        string ecosystem, string method, string route)
    {
        // maven/rpm/oci fall back to the org-wide max_upload_bytes when no per-ecosystem
        // override is set — the resolver picks it up the same way.
        await _factory.SetOrgLimit("default", "all", Cap);
        try
        {
            using var client = _factory.CreateClient();
            using var request = new HttpRequestMessage(new HttpMethod(method), route)
            {
                Content = OversizedBody()
            };
            var resp = await client.SendAsync(request);
            await Assert413FromMiddleware(resp, ecosystem);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "all", null);
        }
    }

    [Fact]
    public async Task InstanceEcosystemLimit_ContentLengthOverCap_Returns413()
    {
        await _factory.SetInstanceLimit("pypi", Cap);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.PostAsync("/pypi/legacy/", OversizedBody());
            await Assert413FromMiddleware(resp, "pypi");
        }
        finally
        {
            await _factory.SetInstanceLimit("pypi", Restore);
        }
    }

    [Fact]
    public async Task UnderCap_UploadStillSucceeds()
    {
        // Positive control: with a generous cap configured, a normal publish passes the
        // middleware and lands 201 — the limit gates, it doesn't break the happy path.
        await _factory.SetOrgLimit("default", "npm", Restore);

        string token = await _factory.CreateToken("push", "default");
        string body = NpmFixtures.BuildPublishBody("size-limit-under-cap", "1.0.0");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/size-limit-under-cap", content);

        Assert.True(resp.IsSuccessStatusCode,
            $"Expected 2xx status for an under-cap npm publish, got {(int)resp.StatusCode} {resp.StatusCode}.");
    }

    [Fact]
    public async Task NonUploadMethod_OverCapContentLength_NotIntercepted()
    {
        // GETs carry no upload body; the middleware must not 413 reads even when a tiny
        // cap is configured for the ecosystem.
        await _factory.SetOrgLimit("default", "npm", Cap);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/npm/size-limit-not-an-upload");
            Assert.NotEqual(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "npm", null);
        }
    }
}
