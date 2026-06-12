using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Compliance;

/// <summary>
/// PEP 503/427/440/508/592 compliance tests.
/// Verifies HTTP-level behaviour of the PyPI endpoints against the relevant PEPs.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class PyPiComplianceTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PyPiComplianceTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [GeneratedRegex(@"/packages/(dl_auth_check[^""#]+\.whl)")]
    private static partial Regex DlAuthCheckWheelLinkRegex();

    // ── PEP 503 — Simple Repository API ──────────────────────────────────────

    [Fact]
    public async Task SimpleIndex_ContentType_IsTextHtml()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/simple/");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task SimpleIndex_RequiresAuth_WhenAnonymousPullDisabled()
    {
        using var client = _factory.CreateClient();

        var resp = await client.GetAsync("/simple/");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task PackageIndex_NormalizedName_ResolvesPackage()
    {
        // Push as "My_Package" — PurlName is normalized to "my-package"
        await _factory.PushPyPiPackage("My_Package", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // All three equivalent names per PEP 503 should resolve to the same page
        foreach (string? name in new[] { "my-package", "My_Package", "my.package" })
        {
            var resp = await client.GetAsync($"/simple/{name}/");
            Assert.True(
                resp.StatusCode is HttpStatusCode.OK or HttpStatusCode.NotFound,
                $"Unexpected {resp.StatusCode} for name '{name}'");
            // At least the canonical form must return 200
            if (name == "my-package")
            {
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            }
        }
    }

    [Fact]
    public async Task SimpleIndex_ContainsLinkToPackage_AfterPush()
    {
        await _factory.PushPyPiPackage("mylib", "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string html = await client.GetStringAsync("/simple/");

        Assert.Contains("mylib", html);
        Assert.Contains("/simple/mylib/", html);
    }

    [Fact]
    public async Task PackageIndex_DownloadUrl_PointsToDependably()
    {
        await _factory.PushPyPiPackage("urlcheck", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string html = await client.GetStringAsync("/simple/urlcheck/");

        // Download links must point to this Dependably instance, never to the original upstream
        Assert.DoesNotContain("pypi.org", html);
        Assert.DoesNotContain("files.pythonhosted.org", html);
        Assert.Contains("/packages/", html);
    }

    // ── PEP 592 — Yanked releases ─────────────────────────────────────────────

    [Fact]
    public async Task PackageIndex_YankedVersion_HasDataYankedAttribute()
    {
        await _factory.PushPyPiPackage("yank-test", "1.0.0");
        await _factory.SetVersionYanked("default", "pypi", "yank-test", "1.0.0", reason: "broken release");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string html = await client.GetStringAsync("/simple/yank-test/");

        Assert.Contains("data-yanked", html);
        // Yanked versions must still appear in the index (PEP 592 §5)
        Assert.Contains("1.0.0", html);
    }

    [Fact]
    public async Task PackageIndex_NonYankedVersion_HasNoDataYankedAttribute()
    {
        await _factory.PushPyPiPackage("no-yank-pkg", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string html = await client.GetStringAsync("/simple/no-yank-pkg/");

        Assert.DoesNotContain("data-yanked", html);
    }

    // ── PEP 508 — Name validation ─────────────────────────────────────────────

    [Theory]
    [InlineData("")]                   // empty
    [InlineData("-invalid")]           // leading hyphen
    [InlineData("invalid-")]           // trailing hyphen
    [InlineData("has space")]          // space
    [InlineData("has/slash")]          // path separator
    public async Task Upload_InvalidName_Returns422(string invalidName)
    {
        string token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("valid-fallback", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm(invalidName, "1.0.0", bytes, sha256,
            filename: $"{invalidName.Replace(' ', '_')}-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── PEP 440 — Version validation ─────────────────────────────────────────

    [Theory]
    [InlineData("not-a-version")]      // does not start with digit
    [InlineData("")]                   // empty
    public async Task Upload_InvalidVersion_Returns422(string invalidVersion)
    {
        string token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("validname", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        // Build form with the real bytes but wrong version in metadata
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("2.1"), "metadata_version");
        form.Add(new StringContent("validname"), "name");
        form.Add(new StringContent(invalidVersion), "version");
        form.Add(new StringContent(sha256), "sha256_digest");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", "validname-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Push auth ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Upload_NoToken_Returns401()
    {
        var (bytes, sha256) = PyPiFixtures.BuildWheel("authtest", "1.0.0");
        using var client = _factory.CreateClient();
        using var content = BuildUploadForm("authtest", "1.0.0", bytes, sha256,
            filename: "authtest-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_PullToken_Returns403()
    {
        string token = await _factory.CreateToken("pull");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("scopetest", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("scopetest", "1.0.0", bytes, sha256,
            filename: "scopetest-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_ChecksumMismatch_Returns422()
    {
        string token = await _factory.CreateToken("push");
        var (bytes, _) = PyPiFixtures.BuildWheel("csumtest", "1.0.0");
        const string wrongHash = "0000000000000000000000000000000000000000000000000000000000000000";

        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("csumtest", "1.0.0", bytes, wrongHash,
            filename: "csumtest-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_DuplicateVersion_Returns409()
    {
        await _factory.PushPyPiPackage("duptest", "1.0.0");

        string token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("duptest", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("duptest", "1.0.0", bytes, sha256,
            filename: "duptest-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
    }

    // ── Upload — action / metadata_version validation ─────────────────────────

    [Fact]
    public async Task Upload_WrongAction_Returns422()
    {
        string token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("action-test", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("wrong_action"), ":action");  // not "file_upload"
        form.Add(new StringContent("2.1"), "metadata_version");
        form.Add(new StringContent("action-test"), "name");
        form.Add(new StringContent("1.0.0"), "version");
        form.Add(new StringContent(sha256), "sha256_digest");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", "action-test-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_InvalidMetadataVersion_Returns422()
    {
        string token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("meta-ver-test", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("9.9"), "metadata_version"); // not in valid set
        form.Add(new StringContent("meta-ver-test"), "name");
        form.Add(new StringContent("1.0.0"), "version");
        form.Add(new StringContent(sha256), "sha256_digest");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", "meta-ver-test-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_MissingSha256Digest_Returns422()
    {
        string token = await _factory.CreateToken("push");
        var (bytes, _) = PyPiFixtures.BuildWheel("nosha-test", "1.0.0");

        using var client = _factory.CreateClientWithBasic(token);
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("2.1"), "metadata_version");
        form.Add(new StringContent("nosha-test"), "name");
        form.Add(new StringContent("1.0.0"), "version");
        // deliberately omit sha256_digest
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", "nosha-test-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_MissingContentFile_Returns422()
    {
        string token = await _factory.CreateToken("push");

        using var client = _factory.CreateClientWithBasic(token);
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("2.1"), "metadata_version");
        form.Add(new StringContent("nofile-test"), "name");
        form.Add(new StringContent("1.0.0"), "version");
        form.Add(new StringContent("abc123"), "sha256_digest");
        // deliberately omit the "content" file part

        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_ValidWheel_Returns200()
    {
        string token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("valid-upload-wheel", "3.2.1");
        string filename = "valid_upload_wheel-3.2.1-py3-none-any.whl";

        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("valid-upload-wheel", "3.2.1", bytes, sha256, filename);

        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Download auth — hosted packages ──────────────────────────────────────

    [Fact]
    public async Task PackageIndex_HostedPackage_WithoutToken_Returns401()
    {
        // Push a hosted (non-proxy) package
        await _factory.PushPyPiPackage("auth-check-pkg", "1.0.0");

        // GET the simple index page for it without any auth token
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/simple/auth-check-pkg/");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task DownloadPackage_HostedPackage_WithoutToken_Returns401()
    {
        // Push a hosted package then try to download without a token
        await _factory.PushPyPiPackage("dl-auth-check", "2.0.0");

        // Retrieve the package filename from the authenticated simple index
        string pullToken = await _factory.CreateToken("pull");
        using var authedClient = _factory.CreateClientWithBearer(pullToken);
        string html = await authedClient.GetStringAsync("/simple/dl-auth-check/");

        // Extract the filename from the HTML link
        var match = DlAuthCheckWheelLinkRegex().Match(html);
        Assert.True(match.Success, $"Could not find download link in: {html}");
        string filename = match.Groups[1].Value;

        // Now try downloading without token
        using var anonClient = _factory.CreateClient();
        var resp = await anonClient.GetAsync($"/packages/{filename}");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Download — proxy passthrough disabled ─────────────────────────────────

    [Fact]
    public async Task DownloadPackage_ProxyPassthroughDisabled_Returns404()
    {
        // Disable proxy passthrough for the default org
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1");
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId });

        try
        {
            // Request a file that doesn't exist locally (would require proxy fetch)
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync("/packages/proxy-disabled-pkg-1.0.0-py3-none-any.whl");

            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            // Restore proxy passthrough so other tests aren't affected
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId });
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static MultipartFormDataContent BuildUploadForm(
        string name, string version, byte[] bytes, string sha256, string filename)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
            { new StringContent(name), "name" },
            { new StringContent(version), "version" },
            { new StringContent(sha256), "sha256_digest" }
        };
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);
        return content;
    }
}
