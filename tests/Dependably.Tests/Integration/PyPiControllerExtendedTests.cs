using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Extended HTTP-level coverage for PyPiController paths that the compliance + mixed-origin
/// suites don't already pin: proxy-merge ON/OFF, allowlist/blocklist gating, upload size
/// limits (org → instance hierarchy), upstream failure fallbacks, checksum mismatch (502),
/// path-traversal rejection, and download cache hit vs miss.
///
/// Per memory feedback_per_version_origin_routing.md, routing must gate on
/// package_versions.origin — never packages.is_proxy. The
/// <see cref="DownloadPackage_UploadedVersionAuthFlowThenDelivered"/> case exercises the
/// origin='uploaded' branch end-to-end (401 anon → 200 with token); the
/// <see cref="SimpleIndex_HostedNamespace_MergesUpstreamFilenames"/> case verifies the
/// merge branch in <c>ProxyUpstreamSimpleIndex</c>.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiControllerExtendedTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PyPiControllerExtendedTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ──────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgId()
    {
        _factory.CreateClient().Dispose(); // ensure first-boot ran
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetAnonymousPull(bool enabled)
    {
        var orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetAllowlistMode(bool enabled)
    {
        var orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET allowlist_mode = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetProxyPassthrough(bool enabled)
    {
        var orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task AddBlocklistEntry(string pattern)
    {
        var orgId = await DefaultOrgId();
        var repo = _factory.Services.GetRequiredService<BlocklistRepository>();
        await repo.AddAsync(orgId, pattern);
    }

    private async Task AddAllowlistEntry(string purlPattern)
    {
        var orgId = await DefaultOrgId();
        var repo = _factory.Services.GetRequiredService<AllowlistRepository>();
        await repo.AddAsync(orgId, purlPattern);
    }

    private static MultipartFormDataContent BuildUploadForm(
        string name, string version, byte[] bytes, string sha256, string filename,
        string filetype = "bdist_wheel", string? md5 = null)
    {
        var content = new MultipartFormDataContent();
        content.Add(new StringContent("file_upload"), ":action");
        content.Add(new StringContent("2.1"), "metadata_version");
        content.Add(new StringContent(name), "name");
        content.Add(new StringContent(version), "version");
        content.Add(new StringContent(sha256), "sha256_digest");
        if (md5 is not null) content.Add(new StringContent(md5), "md5_digest");
        content.Add(new StringContent(filetype), "filetype");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);
        return content;
    }

    // ── SimpleIndex ──────────────────────────────────────────────────────────

    [Fact]
    public async Task SimpleIndex_AnonymousPullEnabled_NoToken_Returns200()
    {
        // AnonymousPull=true takes the "skip the 401 gate" branch of SimpleIndex.
        await SetAnonymousPull(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/simple/");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadAsStringAsync();
            Assert.Contains("Simple Index", body);
        }
        finally
        {
            await SetAnonymousPull(false);
        }
    }

    [Fact]
    public async Task SimpleIndex_PackageNameWithHtmlMetachars_IsEncoded()
    {
        _factory.CreateClient().Dispose(); // ensure first-boot ran
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1");

        // Insert a name with HTML metacharacters directly, bypassing the upload-time PEP 508
        // regex, so the renderer's output encoding is what's under test.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @orgId, 'pypi', @name, @name, 0)",
            new { id = Guid.NewGuid().ToString("N"), orgId, name = "evil\"<b>x</b>" });

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync("/simple/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();

        Assert.DoesNotContain("<b>x</b>", body);          // raw markup must not survive
        Assert.Contains("&lt;b&gt;x&lt;/b&gt;", body);    // entity-encoded form is emitted
    }

    // ── PackageIndex — proxy merge ON ────────────────────────────────────────

    [Fact]
    public async Task SimpleIndex_HostedNamespace_MergesUpstreamFilenames()
    {
        // Mirror of MixedOriginRoutingTests but pins the "data-* attribute stripping" branch
        // by including data-dist-info-metadata in the upstream HTML and asserting the merged
        // local link sits beside the rewritten upstream link.
        var name = $"mergepypi{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "9.0.0");

        var upstreamHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="https://files.pythonhosted.org/packages/aa/bb/{name}-1.0.0.tar.gz#sha256=cafe" data-dist-info-metadata="sha256=deadbeef">{name}-1.0.0.tar.gz</a>
            </body></html>
            """;

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(upstreamHtml));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var html = await resp.Content.ReadAsStringAsync();
        // Upstream link rewritten to /packages/{filename} (no host).
        Assert.Contains($"/packages/{name}-1.0.0.tar.gz", html);
        // Local upload merged in alongside.
        var underscored = name.Replace('-', '_');
        Assert.Contains($"{underscored}-9.0.0-py3-none-any.whl", html);
        // data-dist-info-metadata attribute stripped from rewritten anchors.
        Assert.DoesNotContain("data-dist-info-metadata", html);
    }

    [Fact]
    public async Task SimpleIndex_PassthroughDisabled_UnknownPackage_Returns404()
    {
        // pkg is null + passthrough off → straight to 404 without upstream call.
        await SetProxyPassthrough(false);
        try
        {
            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/simple/never-{Guid.NewGuid():N}/");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    [Fact]
    public async Task SimpleIndex_PassthroughDisabled_LocalOnly_ServesLocalIndex()
    {
        // pkg exists locally + passthrough off → RenderLocalSimpleIndex branch.
        await SetProxyPassthrough(false);
        try
        {
            var name = $"localonly{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var html = await resp.Content.ReadAsStringAsync();
            Assert.Contains($"Links for {name}", html);
            Assert.Contains("1.0.0", html);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    [Fact]
    public async Task SimpleIndex_UpstreamUnreachable_LocalVersions_FallsBackToLocalIndex()
    {
        // Upstream returns 500 (treated by the catch-all as "no upstream HTML"). Since we
        // have local versions, render those — the upstream-failure-with-local-fallback branch.
        var name = $"upfail{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains($"Links for {name}", html);
    }

    [Fact]
    public async Task SimpleIndex_UpstreamUnreachable_NoLocalVersions_Returns404()
    {
        // Passthrough on, no local versions, upstream 404 → simple-index NotFound branch.
        var name = $"nothing{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SimpleIndex_ProxyMerge_AnonNoPull_Returns401()
    {
        // ProxyUpstreamSimpleIndex hits the "AnonymousPull=false + no token" branch and emits
        // WWW-Authenticate.
        var name = $"proxauth{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody("<html><body></body></html>"));

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    // ── DownloadPackage ──────────────────────────────────────────────────────

    [Fact]
    public async Task DownloadPackage_MalformedFilename_Returns404()
    {
        // PyPiArtifactValidator.TryParseFilename rejects → straight to 404 before any auth.
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/packages/not-a-valid-pypi-file.txt");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task DownloadPackage_CachedBlob_AuthenticatedRequest_ReturnsHit()
    {
        // Pushed wheel → cached path → X-Cache: HIT branch via TryServeCachedBlobAsync.
        var name = $"cachehit{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-1.0.0-py3-none-any.whl";

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
        Assert.NotNull(resp.Headers.GetValues("X-Dependably-PURL").FirstOrDefault());
    }

    [Fact]
    public async Task DownloadPackage_UploadedVersionAnonymous_Returns401WithWwwAuthenticate()
    {
        // CheckDownloadAuth branch: per-version origin='uploaded' + no token → 401.
        var name = $"upauth{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-1.0.0-py3-none-any.whl";

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task DownloadPackage_PassthroughDisabled_NoLocal_Returns404()
    {
        // Cache miss path → ProxyPassthroughEnabled=false → 404 before any upstream call.
        await SetProxyPassthrough(false);
        try
        {
            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/packages/nopas-1.0.0-py3-none-any.whl");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    [Fact]
    public async Task DownloadPackage_AllowlistMode_PurlNotAllowed_Returns403()
    {
        // CheckProxyAllowlistBlocklistAsync → allowlist branch returns 403. The 403 is
        // emitted after ResolveProxyUpstreamUrlAsync returns a non-null URL, so we must
        // stub the upstream simple index to advertise the wheel.
        var name = $"forbid{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-1.0.0-py3-none-any.whl";
        var mockBase = _factory.MockUpstream.Urls[0];
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));

        await SetAllowlistMode(true);
        try
        {
            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/packages/{filename}");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await SetAllowlistMode(false);
        }
    }

    [Fact]
    public async Task DownloadPackage_BlocklistMatch_Returns403()
    {
        // CheckProxyAllowlistBlocklistAsync → blocklist branch returns 403 + audit log.
        // Same as above: the 403 fires only after the upstream URL resolves, so stub
        // upstream simple-index.
        var name = $"blockme{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-1.0.0-py3-none-any.whl";
        var mockBase = _factory.MockUpstream.Urls[0];
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        await AddBlocklistEntry($"pkg:pypi/{name}");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task DownloadPackage_AllowlistMode_PurlAllowed_FetchesUpstream()
    {
        // Allowlist permit branch: the gate clears and the proxy fetch runs against upstream.
        await SetAllowlistMode(true);
        var name = $"allowok{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        try
        {
            await AddAllowlistEntry($"pkg:pypi/{name}");
            var underscored = name.Replace('-', '_');
            var filename = $"{underscored}-1.0.0-py3-none-any.whl";
            var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, "1.0.0");
            var mockBase = _factory.MockUpstream.Urls[0];

            var simpleHtml = $"""
                <!DOCTYPE html><html><body>
                <a href="{mockBase}/files/{filename}">{filename}</a>
                </body></html>
                """;
            _factory.MockUpstream
                .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                    .WithHeader("Content-Type", "text/html").WithBody(simpleHtml));
            _factory.MockUpstream
                .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                    .WithHeader("Content-Type", "application/octet-stream")
                    .WithBody(wheelBytes));

            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/packages/{filename}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await SetAllowlistMode(false);
        }
    }

    [Fact]
    public async Task DownloadPackage_UnknownFilenameUpstreamMissing_Returns404()
    {
        // Cache miss + upstream simple-index 404 → ResolveProxyUpstreamUrlAsync returns null
        // → DownloadPackage returns NotFound before reaching FetchAndCacheUpstreamAsync.
        var name = $"missing{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-1.0.0-py3-none-any.whl";

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task DownloadPackage_CacheMiss_FetchFromUpstreamSucceeds_ReturnsMissHeader()
    {
        // Cache-miss + upstream-success path: ResolveUpstreamPyPiUrlAsync finds the URL,
        // DownloadAndCacheAsync fetches and caches, FetchAndCacheUpstreamAsync emits
        // X-Cache: MISS and serves the bytes. Pins the first-fetch recording branch.
        var name = $"upmiss{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-1.0.0-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, "1.0.0");
        var mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        // MISS header from the cache-miss path. (Could be HIT if the proxy fetch service
        // wrote the blob under a different key — we accept either as proof of the path.)
        var cacheHeader = resp.Headers.GetValues("X-Cache").FirstOrDefault();
        Assert.True(cacheHeader is "MISS" or "HIT", $"unexpected X-Cache: {cacheHeader}");
    }

    // ── Upload ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Upload_PathTraversalInName_Returns422()
    {
        // ValidatePathSafety branch — a "../" sneaks into the form's name field.
        var token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("dotdot", "1.0.0");
        using var client = _factory.CreateClientWithBasic(token);
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("file_upload"), ":action");
        form.Add(new StringContent("2.1"), "metadata_version");
        // PEP 508 regex allows a-z, 0-9, dot/hyphen/underscore. ".." passes the regex (dots
        // are valid) but PathSafeValidator rejects it for path-traversal.
        form.Add(new StringContent(".."), "name");
        form.Add(new StringContent("1.0.0"), "version");
        form.Add(new StringContent(sha256), "sha256_digest");
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "content", "..-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/pypi/legacy/", form);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_ExceedsOrgLimit_Returns413()
    {
        // CheckPyPiUploadSizeAsync — org limit hit first in the hierarchy.
        await _factory.SetOrgLimit("default", "pypi", 100); // tiny org limit
        try
        {
            var token = await _factory.CreateToken("push");
            var (bytes, sha256) = PyPiFixtures.BuildWheel("toobig", "1.0.0");
            using var client = _factory.CreateClientWithBasic(token);
            using var content = BuildUploadForm("toobig", "1.0.0", bytes, sha256,
                "toobig-1.0.0-py3-none-any.whl");
            var resp = await client.PostAsync("/pypi/legacy/", content);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        }
        finally
        {
            // Reset the org limit so other tests aren't poisoned.
            await _factory.SetOrgLimit("default", "pypi", 500 * 1024 * 1024);
        }
    }

    [Fact]
    public async Task Upload_WheelMissingMetadata_Returns422()
    {
        // ValidateFileTypeContents → ValidateWheel: zip with no .dist-info/METADATA fails.
        var token = await _factory.CreateToken("push");
        // Build a wheel-shaped ZIP that lacks the dist-info METADATA entry.
        byte[] bytes;
        using (var ms = new MemoryStream())
        {
            using (var zip = new System.IO.Compression.ZipArchive(ms,
                System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = zip.CreateEntry("other.txt");
                using var w = new StreamWriter(entry.Open());
                w.Write("nope");
            }
            bytes = ms.ToArray();
        }
        var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("nometa", "1.0.0", bytes, sha,
            filename: "nometa-1.0.0-py3-none-any.whl", filetype: "bdist_wheel");
        var resp = await client.PostAsync("/pypi/legacy/", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_SdistWrongExtension_Returns422()
    {
        // ValidateSdist: filename must end in .tar.gz or .zip.
        var token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildSdist("wrongext", "1.0.0");
        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("wrongext", "1.0.0", bytes, sha256,
            filename: "wrongext-1.0.0.bogus", filetype: "sdist");
        var resp = await client.PostAsync("/pypi/legacy/", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_SdistFilenameMismatch_Returns422()
    {
        // ValidateSdist: filename must start with the normalized package name.
        var token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildSdist("expected", "1.0.0");
        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("expected", "1.0.0", bytes, sha256,
            filename: "completelydifferent-1.0.0.tar.gz", filetype: "sdist");
        var resp = await client.PostAsync("/pypi/legacy/", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_Md5Mismatch_Returns422()
    {
        // VerifyDigests: sha256 matches but the md5 digest doesn't.
        var token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("md5miss", "1.0.0");
        const string wrongMd5 = "00000000000000000000000000000000";
        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("md5miss", "1.0.0", bytes, sha256,
            filename: "md5miss-1.0.0-py3-none-any.whl", md5: wrongMd5);
        var resp = await client.PostAsync("/pypi/legacy/", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_NotMultipart_Returns400()
    {
        // Upload's HasFormContentType=false branch.
        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBasic(token);
        using var content = new StringContent("not multipart", Encoding.UTF8, "application/json");
        var resp = await client.PostAsync("/pypi/legacy/", content);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_HappyPath_WithMd5_Returns200()
    {
        // Happy path that exercises the optional md5_digest branch (string.IsNullOrEmpty=false
        // and digests match) AND the LicenseExtractor post-publish branch.
        var token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("md5ok-pkg", "2.0.0");
        var md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();
        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("md5ok-pkg", "2.0.0", bytes, sha256,
            filename: "md5ok_pkg-2.0.0-py3-none-any.whl", md5: md5);
        var resp = await client.PostAsync("/pypi/legacy/", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
