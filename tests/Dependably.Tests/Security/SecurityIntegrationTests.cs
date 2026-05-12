using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Security;

/// <summary>
/// OWASP-aligned HTTP-level security tests.
/// Covers security headers, CORS, scope enforcement, path traversal, header injection,
/// upload limits, and login rate limiting.
/// </summary>
[Trait("Category", "Security")]
public sealed class SecurityIntegrationTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SecurityIntegrationTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── HTTP security headers ─────────────────────────────────────────────────

    [Fact]
    public async Task SecurityHeaders_AllResponses_HaveXContentTypeOptions()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");

        Assert.Equal("nosniff", resp.Headers.GetValues("X-Content-Type-Options").FirstOrDefault());
    }

    [Fact]
    public async Task SecurityHeaders_AllResponses_HaveXFrameOptions()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");

        Assert.Equal("DENY", resp.Headers.GetValues("X-Frame-Options").FirstOrDefault());
    }

    [Fact]
    public async Task SecurityHeaders_AllResponses_HaveReferrerPolicy()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");

        Assert.Equal("strict-origin-when-cross-origin",
            resp.Headers.GetValues("Referrer-Policy").FirstOrDefault());
    }

    [Fact]
    public async Task SecurityHeaders_ManagementApi_HasContentSecurityPolicy()
    {
        using var client = _factory.CreateClient();
        // Any /api/ route — use login (no auth needed to get the response headers)
        var resp = await client.PostAsync("/api/v1/auth/login",
            new StringContent("{}", Encoding.UTF8, "application/json"));

        Assert.True(resp.Headers.Contains("Content-Security-Policy"),
            "Management API responses must include Content-Security-Policy");
        var csp = resp.Headers.GetValues("Content-Security-Policy").FirstOrDefault();
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("form-action 'self'", csp);
    }

    [Fact]
    public async Task SecurityHeaders_RegistryPaths_HaveCacheControlNoStore()
    {
        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/simple/");

        Assert.Equal("no-store", resp.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task SecurityHeaders_NoHSTS_WithoutXForwardedProto()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");

        Assert.False(resp.Headers.Contains("Strict-Transport-Security"),
            "HSTS must not be set without X-Forwarded-Proto: https");
    }

    [Fact]
    public async Task SecurityHeaders_HSTS_PresentWithXForwardedProtoHttps()
    {
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("X-Forwarded-Proto", "https");
        var resp = await client.SendAsync(req);

        Assert.True(resp.Headers.Contains("Strict-Transport-Security"),
            "HSTS must be set when X-Forwarded-Proto: https");
    }

    // ── Path traversal ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("../../../etc/passwd")]
    [InlineData("..%2F..%2Fetc%2Fpasswd")]
    [InlineData("foo\\..\\bar")]
    public async Task PyPiUpload_PathTraversalName_Returns422AndNoBlobWritten(string maliciousName)
    {
        var blobSizeBefore = await _factory.BlobStore.GetTotalSizeAsync();
        var token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("safe-name", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("2.1"), "metadata_version");
        form.Add(new StringContent(maliciousName), "name");
        form.Add(new StringContent("1.0.0"), "version");
        form.Add(new StringContent(sha256), "sha256_digest");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", "safe-name-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        // No blob must have been written
        Assert.Equal(blobSizeBefore, await _factory.BlobStore.GetTotalSizeAsync());
    }

    [Theory]
    [InlineData("../../../etc/passwd")]
    [InlineData("..%2F..%2Fetc%2Fpasswd")]
    public async Task NuGetPush_PathTraversalId_Returns422AndNoBlobWritten(string maliciousId)
    {
        var blobSizeBefore = await _factory.BlobStore.GetTotalSizeAsync();
        var token = await _factory.CreateToken("push");

        // Build a nuspec with the malicious ID
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>{maliciousId}</id>
                <version>1.0.0</version>
                <authors>test</authors>
                <description>test</description>
              </metadata>
            </package>
            """;
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
        {
            var entry = zip.CreateEntry("pkg.nuspec");
            using var w = new StreamWriter(entry.Open());
            w.Write(nuspec);
        }
        var bytes = ms.ToArray();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", "pkg.1.0.0.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        Assert.Equal(blobSizeBefore, await _factory.BlobStore.GetTotalSizeAsync());
    }

    // ── Header injection ──────────────────────────────────────────────────────

    [Fact]
    public async Task PyPiUpload_HeaderInjectionInName_DoesNotInjectResponseHeader()
    {
        var token = await _factory.CreateToken("push");
        const string injectionName = "pkg\r\nX-Injected: evil";
        var (bytes, sha256) = PyPiFixtures.BuildWheel("safe", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("2.1"), "metadata_version");
        form.Add(new StringContent(injectionName), "name");
        form.Add(new StringContent("1.0.0"), "version");
        form.Add(new StringContent(sha256), "sha256_digest");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", "safe-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", form);

        // Either rejected outright or sanitised — the injected header must never appear
        Assert.False(resp.Headers.Contains("X-Injected"),
            "CRLF injection must not result in an X-Injected response header");
    }

    // ── Push scope enforcement ────────────────────────────────────────────────

    [Fact]
    public async Task PyPiPush_NoToken_Returns401()
    {
        var (bytes, sha256) = PyPiFixtures.BuildWheel("authpkg", "1.0.0");
        using var client = _factory.CreateClient();
        using var form = BuildPyPiForm("authpkg", "1.0.0", bytes, sha256);
        var resp = await client.PostAsync("/pypi/legacy/", form);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task PyPiPush_PullToken_Returns403NotUnauthorized()
    {
        var token = await _factory.CreateToken("pull");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("scopepkg", "1.0.0");
        using var client = _factory.CreateClientWithBasic(token);
        using var form = BuildPyPiForm("scopepkg", "1.0.0", bytes, sha256);
        var resp = await client.PostAsync("/pypi/legacy/", form);
        // Pull token → Forbidden, not Unauthorized (distinguishes wrong scope from no auth)
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task NuGetPush_NoToken_Returns401()
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg("AuthNuGet", "1.0.0");
        using var client = _factory.CreateClient();
        using var content = BuildNuGetContent(bytes, "AuthNuGet.1.0.0.nupkg");
        var resp = await client.PutAsync("/nuget/publish", content);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task NuGetPush_PullToken_Returns403()
    {
        var token = await _factory.CreateToken("pull");
        var (bytes, _) = NuGetFixtures.BuildNupkg("ScopeNuGet", "1.0.0");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = BuildNuGetContent(bytes, "ScopeNuGet.1.0.0.nupkg");
        var resp = await client.PutAsync("/nuget/publish", content);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task NpmPush_NoToken_Returns401()
    {
        var body = NpmFixtures.BuildPublishBody("authpkg-npm", "1.0.0");
        using var client = _factory.CreateClient();
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/authpkg-npm", content);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task NpmPush_PullToken_Returns403()
    {
        var token = await _factory.CreateToken("pull");
        var body = NpmFixtures.BuildPublishBody("scopepkg-npm", "1.0.0");
        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/scopepkg-npm", content);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Upload size limit ─────────────────────────────────────────────────────

    [Fact]
    public async Task PyPiUpload_ExceedsInstanceLimit_Returns413()
    {
        // Set a very small limit (10 bytes) so any real package exceeds it
        await _factory.SetInstanceLimit("pypi", 10);

        var token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("bigsizepkg", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var form = BuildPyPiForm("bigsizepkg", "1.0.0", bytes, sha256);

        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);

        // Reset limit so other tests are not affected
        await _factory.SetInstanceLimit("pypi", long.MaxValue);
    }

    // ── SSRF via upstream URL setting ─────────────────────────────────────────

    [Theory]
    [InlineData("http://127.0.0.1/packages")]
    [InlineData("http://10.0.0.1/packages")]
    [InlineData("http://169.254.169.254/metadata")]
    [InlineData("http://192.168.1.1/packages")]
    public async Task UpdateOrgSettings_BlockedUpstreamUrl_Returns400(string blockedUrl)
    {
        var adminJwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(adminJwt);

        var body = JsonSerializer.Serialize(new { pyPiUpstream = blockedUrl });
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/api/v1/settings", content);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── Login rate limiting ───────────────────────────────────────────────────

    [Fact]
    public async Task Login_After10FailedAttempts_Returns429()
    {
        // Use a separate client so requests are processed sequentially
        using var client = _factory.CreateClient();
        var body = new StringContent(
            """{"email":"noone@example.com","password":"wrong"}""",
            Encoding.UTF8, "application/json");

        HttpResponseMessage? lastResp = null;
        for (var i = 0; i < 11; i++)
        {
            // Reset content for each request (StringContent is single-use)
            var reqContent = new StringContent(
                """{"email":"noone@example.com","password":"wrong"}""",
                Encoding.UTF8, "application/json");
            lastResp = await client.PostAsync("/api/v1/auth/login", reqContent);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, lastResp!.StatusCode);
        Assert.True(lastResp.Headers.Contains("Retry-After"),
            "429 response must include Retry-After header");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static MultipartFormDataContent BuildPyPiForm(
        string name, string version, byte[] bytes, string sha256)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("2.1"), "metadata_version");
        form.Add(new StringContent(name), "name");
        form.Add(new StringContent(version), "version");
        form.Add(new StringContent(sha256), "sha256_digest");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", $"{name}-{version}-py3-none-any.whl");
        return form;
    }

    private static MultipartFormDataContent BuildNuGetContent(byte[] bytes, string filename)
    {
        var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", filename);
        return content;
    }
}
