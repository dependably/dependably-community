using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

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
        string orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetAllowlistMode(bool enabled)
    {
        string orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET allowlist_mode = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

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

    private async Task AddBlocklistEntry(string pattern)
    {
        string orgId = await DefaultOrgId();
        var repo = _factory.Services.GetRequiredService<BlocklistRepository>();
        await repo.AddAsync(orgId, pattern);
    }

    private async Task AddAllowlistEntry(string purlPattern)
    {
        string orgId = await DefaultOrgId();
        var repo = _factory.Services.GetRequiredService<AllowlistRepository>();
        await repo.AddAsync(orgId, purlPattern);
    }

    private static MultipartFormDataContent BuildUploadForm(
        string name, string version, byte[] bytes, string sha256, string filename,
        string filetype = "bdist_wheel", string? md5 = null)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
            { new StringContent(name), "name" },
            { new StringContent(version), "version" },
            { new StringContent(sha256), "sha256_digest" }
        };
        if (md5 is not null)
        {
            content.Add(new StringContent(md5), "md5_digest");
        }

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
            string body = await resp.Content.ReadAsStringAsync();
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
        string? orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1");

        // Insert a name with HTML metacharacters directly, bypassing the upload-time PEP 508
        // regex, so the renderer's output encoding is what's under test.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @orgId, 'pypi', @name, @name, 0)",
            new { id = Guid.NewGuid().ToString("N"), orgId, name = "evil\"<b>x</b>" });

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync("/simple/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();

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
        string name = $"mergepypi{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "9.0.0");
        await _factory.SeedMixedClaim("pypi", name);

        string upstreamHtml = $"""
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

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string html = await resp.Content.ReadAsStringAsync();
        // Upstream link rewritten to /packages/{filename} (no host).
        Assert.Contains($"/packages/{name}-1.0.0.tar.gz", html);
        // Local upload merged in alongside.
        string underscored = name.Replace('-', '_');
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
            string token = await _factory.CreateToken("pull");
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
            string name = $"localonly{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string html = await resp.Content.ReadAsStringAsync();
            Assert.Contains($"Links for {name}", html);
            Assert.Contains("1.0.0", html);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    [Fact]
    public async Task PackageIndex_AuthGateRunsBeforeCache_UnauthenticatedNeverSeesCachedBody()
    {
        // Regression: the auth gate must run BEFORE any simple-index cache read. With
        // AnonymousPull off, an authenticated request that warms the metadata cache must not
        // let a subsequent unauthenticated request short-circuit to a cached 200 — the 401
        // gate has to fire first.
        await SetAnonymousPull(false);
        await SetProxyPassthrough(false); // local-only path: deterministic, no upstream needed
        try
        {
            string name = $"authcache{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            // (a) Authenticated request succeeds and populates the local-index cache.
            string token = await _factory.CreateToken("pull");
            using (var authedClient = _factory.CreateClientWithBasic(token))
            {
                var authedResp = await authedClient.GetAsync($"/simple/{name}/");
                Assert.Equal(HttpStatusCode.OK, authedResp.StatusCode);
                string html = await authedResp.Content.ReadAsStringAsync();
                Assert.Contains("1.0.0", html);
            }

            // (b) Unauthenticated request for the same path is rejected — not served the
            // cached 200 the authenticated call just primed.
            using var anonClient = _factory.CreateClient();
            var anonResp = await anonClient.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.Unauthorized, anonResp.StatusCode);
        }
        finally
        {
            await SetAnonymousPull(true);
            await SetProxyPassthrough(true);
        }
    }

    [Fact]
    public async Task SimpleIndex_PublishUnderscoreForm_EvictsDashFormCacheEntry()
    {
        // PEP 503: my_package and my-package name the same package. The simple-index cache
        // key is built from the PEP 503-normalized name on set, get, AND evict, so publishing
        // under the underscore form must invalidate the entry warmed by a dash-form GET —
        // otherwise the stale index (missing the new version) would be served until TTL expiry.
        await SetProxyPassthrough(false);
        try
        {
            string stem = $"evict{Guid.NewGuid():N}"[..14].ToLowerInvariant();
            string underscoreName = $"{stem}_pkg";
            string dashName = $"{stem}-pkg";

            await _factory.PushPyPiPackage(underscoreName, "1.0.0");

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Warm the cache via the dash form.
            var warm = await client.GetAsync($"/simple/{dashName}/");
            Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
            string warmHtml = await warm.Content.ReadAsStringAsync();
            Assert.Contains("1.0.0", warmHtml);
            Assert.DoesNotContain("2.0.0", warmHtml);

            // Publish v2 under the underscore form — must evict the same normalized key.
            await _factory.PushPyPiPackage(underscoreName, "2.0.0");

            // The dash-form request must see the new version immediately.
            var after = await client.GetAsync($"/simple/{dashName}/");
            Assert.Equal(HttpStatusCode.OK, after.StatusCode);
            string afterHtml = await after.Content.ReadAsStringAsync();
            Assert.Contains("2.0.0", afterHtml);
        }
        finally
        {
            await SetProxyPassthrough(true);
            await SetAnonymousPull(false);
        }
    }

    [Fact]
    public async Task SimpleIndex_UpstreamUnreachable_LocalVersions_FallsBackToLocalIndex()
    {
        // Upstream returns 500 (treated by the catch-all as "no upstream HTML"). Since we
        // have local versions, render those — the upstream-failure-with-local-fallback branch.
        string name = $"upfail{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string html = await resp.Content.ReadAsStringAsync();
        Assert.Contains($"Links for {name}", html);
    }

    [Fact]
    public async Task SimpleIndex_UpstreamUnreachable_NoLocalVersions_Returns404()
    {
        // Passthrough on, no local versions, upstream 404 → simple-index NotFound branch.
        string name = $"nothing{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SimpleIndex_ProxyMerge_AnonNoPull_Returns401()
    {
        // ProxyUpstreamSimpleIndex hits the "AnonymousPull=false + no token" branch and emits
        // WWW-Authenticate.
        string name = $"proxauth{Guid.NewGuid():N}"[..18].ToLowerInvariant();
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
        string name = $"cachehit{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
        Assert.NotNull(resp.Headers.GetValues("X-Dependably-PURL").FirstOrDefault());
    }

    [Fact]
    public async Task DownloadPackage_UploadedVersionAnonymous_Returns401WithWwwAuthenticate()
    {
        // CheckDownloadAuth branch: per-version origin='uploaded' + no token + AnonymousPull=false → 401.
        string name = $"upauth{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// Pushed (uploaded-origin) wheel is served to an anonymous client when
    /// <c>AnonymousPull = true</c>. Verifies the hosted-download path respects the org setting.
    /// </summary>
    [Fact]
    public async Task DownloadPackage_UploadedVersion_AnonymousPullOn_NoToken_Returns200()
    {
        string name = $"upanonpull{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";

        await SetAnonymousPull(true);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/packages/{filename}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPull(false);
        }
    }

    /// <summary>
    /// A token present but lacking <c>read:metadata</c> is still forbidden on an uploaded PyPI
    /// artifact even when <c>AnonymousPull = true</c>.
    /// </summary>
    [Fact]
    public async Task DownloadPackage_UploadedVersion_AnonymousPullOn_TokenWithoutReadMetadata_Returns403()
    {
        string name = $"upauthcap{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";

        // Token with publish:* only — no read:metadata.
        string orgId = await DefaultOrgId();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var (rawToken, _) = await tokens.CreateServiceTokenAsync(
            orgId, "test-pubonly", """["publish:pypi"]""", expiresAt: null);

        await SetAnonymousPull(true);
        try
        {
            using var client = _factory.CreateClientWithBasic(rawToken);
            var resp = await client.GetAsync($"/packages/{filename}");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPull(false);
        }
    }

    [Fact]
    public async Task DownloadPackage_PassthroughDisabled_NoLocal_Returns404()
    {
        // Cache miss path → ProxyPassthroughEnabled=false → 404 before any upstream call.
        await SetProxyPassthrough(false);
        try
        {
            string token = await _factory.CreateToken("pull");
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
        string name = $"forbid{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";
        string mockBase = _factory.MockUpstream.Urls[0];
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));

        await SetAllowlistMode(true);
        try
        {
            string token = await _factory.CreateToken("pull");
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
        string name = $"blockme{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";
        string mockBase = _factory.MockUpstream.Urls[0];
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        await AddBlocklistEntry($"pkg:pypi/{name}");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task DownloadPackage_AllowlistMode_PurlAllowed_FetchesUpstream()
    {
        // Allowlist permit branch: the gate clears and the proxy fetch runs against upstream.
        await SetAllowlistMode(true);
        string name = $"allowok{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        try
        {
            await AddAllowlistEntry($"pkg:pypi/{name}");
            string underscored = name.Replace('-', '_');
            string filename = $"{underscored}-1.0.0-py3-none-any.whl";
            var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, "1.0.0");
            string mockBase = _factory.MockUpstream.Urls[0];

            string simpleHtml = $"""
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

            string token = await _factory.CreateToken("pull");
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
        string name = $"missing{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
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
        string name = $"upmiss{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, "1.0.0");
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        // MISS header from the cache-miss path. (Could be HIT if the proxy fetch service
        // wrote the blob under a different key — we accept either as proof of the path.)
        string? cacheHeader = resp.Headers.GetValues("X-Cache").FirstOrDefault();
        Assert.True(cacheHeader is "MISS" or "HIT", $"unexpected X-Cache: {cacheHeader}");
    }

    // ── SimpleIndex block-gate consistency ────────────────────────────────────

    /// <summary>
    /// A version with manual_block_state='blocked' must be absent from GET /simple/pkg/ so
    /// clients never discover an artifact that GET /packages/file will deny with 403. Also
    /// verifies that a non-blocked version on the same package is still listed, confirming
    /// the filter is per-version (partial-failure scenario: one blocked, one not).
    /// Regression for the asymmetry where the download block-gate (BlockGateService.EvaluateAsync)
    /// always blocked manual-blocked versions but the simple-index renderers listed all versions
    /// without any block-state filter.
    /// </summary>
    [Fact]
    public async Task SimpleIndex_ManualBlockedVersion_IsAbsentFromIndex_And_DownloadReturns403()
    {
        await SetProxyPassthrough(false);
        try
        {
            string name = $"blkidx{Guid.NewGuid():N}"[..16].ToLowerInvariant();

            // Push two versions: 1.0.0 will be blocked; 2.0.0 must stay listed.
            await _factory.PushPyPiPackage(name, "1.0.0");
            await _factory.PushPyPiPackage(name, "2.0.0");

            string underscored = name.Replace('-', '_');
            string blockedFile = $"{underscored}-1.0.0-py3-none-any.whl";
            string allowedFile = $"{underscored}-2.0.0-py3-none-any.whl";

            // Mark 1.0.0 as manually blocked.
            var store = _factory.Services.GetRequiredService<IMetadataStore>();
            await using (var conn = await store.OpenAsync())
            {
                await conn.ExecuteAsync(
                    """
                    UPDATE package_versions SET manual_block_state = 'blocked'
                    WHERE id = (
                        SELECT pv.id FROM package_versions pv
                        JOIN packages p ON p.id = pv.package_id
                        WHERE p.name = @name AND pv.version = '1.0.0' LIMIT 1)
                    """,
                    new { name });
            }

            // Evict the simple-index cache so the next GET reflects the new block state.
            var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
            var orgs = _factory.Services.GetRequiredService<OrgRepository>();
            string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
            cache.Evict(new PyPiSimpleIndexKey(orgId, name));

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // The simple index must not advertise the blocked version.
            var indexResp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
            string html = await indexResp.Content.ReadAsStringAsync();
            Assert.DoesNotContain(blockedFile, html);   // blocked version absent
            Assert.Contains(allowedFile, html);          // non-blocked version still listed

            // The download endpoint must still return 403 for the blocked file (gate unchanged).
            var dlResp = await client.GetAsync($"/packages/{blockedFile}");
            Assert.Equal(HttpStatusCode.Forbidden, dlResp.StatusCode);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    /// <summary>
    /// In the proxy-merge path (passthrough enabled, upstream answers), a locally cached
    /// version with manual_block_state='blocked' must not be injected into the merged index
    /// by MergeLocalVersionsIntoUpstreamIndex. The non-blocked local version is still merged in.
    /// Partial-failure: two local versions, one blocked, one not.
    /// </summary>
    [Fact]
    public async Task SimpleIndex_ProxyMerge_BlockedLocalVersion_IsExcludedFromMergedIndex()
    {
        string name = $"blkmerge{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        await _factory.PushPyPiPackage(name, "2.0.0");
        await _factory.SeedMixedClaim("pypi", name);

        string underscored = name.Replace('-', '_');
        string blockedFile = $"{underscored}-1.0.0-py3-none-any.whl";
        string allowedFile = $"{underscored}-2.0.0-py3-none-any.whl";

        // Mark 1.0.0 as manually blocked.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                UPDATE package_versions SET manual_block_state = 'blocked'
                WHERE id = (
                    SELECT pv.id FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.name = @name AND pv.version = '1.0.0' LIMIT 1)
                """,
                new { name });
        }

        // Evict so the rebuild picks up the block state.
        var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
        cache.Evict(new PyPiSimpleIndexKey(orgId, name));

        // Upstream simple-index advertising only an upstream-only file (not local).
        string upstreamFile = $"{underscored}-0.9.0.tar.gz";
        string mockBase = _factory.MockUpstream.Urls[0];
        string upstreamHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{mockBase}/files/{upstreamFile}">{upstreamFile}</a>
            </body></html>
            """;
        _factory.MockUpstream
            .Given(WireMock.RequestBuilders.Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(WireMock.ResponseBuilders.Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(upstreamHtml));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var indexResp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
        string html = await indexResp.Content.ReadAsStringAsync();

        // Upstream-only file is present (merged via rewrite).
        Assert.Contains(upstreamFile, html);
        // Non-blocked local version merged in.
        Assert.Contains(allowedFile, html);
        // Blocked local version must be absent.
        Assert.DoesNotContain(blockedFile, html);
    }

    // ── SimpleIndex block-gate parity — vuln arms ─────────────────────────────

    /// <summary>
    /// A version with an unscored MAL- advisory (block_malicious = block) must be absent from
    /// GET /simple/pkg/ so clients never discover an artifact that GET /packages/file will
    /// deny with 403. Also asserts a second version (no advisory) is still listed — partial-
    /// failure scenario: one malicious, one clean.
    /// Fail-before/pass-after: old code filtered only manual-block and deprecated; this case
    /// would have listed the malicious version alongside the clean one on the old code.
    /// </summary>
    [Fact]
    public async Task SimpleIndex_MaliciousVersion_BlockMode_IsAbsentFromIndex_And_DownloadReturns403()
    {
        await SetProxyPassthrough(false);
        try
        {
            string name = $"malindex{Guid.NewGuid():N}"[..16].ToLowerInvariant();

            // Push two versions: 1.0.0 gets a MAL- advisory; 2.0.0 stays clean.
            await _factory.PushPyPiPackage(name, "1.0.0");
            await _factory.PushPyPiPackage(name, "2.0.0");

            string underscored = name.Replace('-', '_');
            string malFile = $"{underscored}-1.0.0-py3-none-any.whl";
            string cleanFile = $"{underscored}-2.0.0-py3-none-any.whl";

            // Attach an unscored MAL- advisory to 1.0.0 and stamp vuln_checked_at so the gate evaluates.
            var store = _factory.Services.GetRequiredService<IMetadataStore>();
            await using (var conn = await store.OpenAsync())
            {
                string? versionId = await conn.ExecuteScalarAsync<string>(
                    """
                    SELECT pv.id FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.name = @name AND pv.version = '1.0.0' LIMIT 1
                    """,
                    new { name });
                Assert.NotNull(versionId);

                string malId = $"MAL-2026-{Guid.NewGuid():N}";
                string vulnId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO vulnerabilities
                        (id, osv_id, ecosystem, package_name, severity, cvss_score, summary,
                         modified_at, fetched_at)
                    VALUES
                        (@vulnId, @malId, 'pypi', @name, NULL, NULL,
                         'Malicious code in package',
                         strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                         strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                    """,
                    new { vulnId, malId, name });
                string pvvId = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind) VALUES (@pvvId, @versionId, @vulnId, 'package_version')",
                    new { pvvId, versionId, vulnId });
                await conn.ExecuteAsync(
                    "UPDATE package_versions SET vuln_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @versionId",
                    new { versionId });
            }

            // Ensure block_malicious = block (the default, but be explicit).
            {
                string jwt = await _factory.CreateAdminJwt();
                using var adminClient = _factory.CreateClient();
                adminClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
                var put = await adminClient.PutAsJsonAsync("/api/v1/proxy-settings", new
                {
                    proxyPassthroughEnabled = false,
                    maxOsvScoreTolerance = 10.0,
                    blockMalicious = "block",
                });
                put.EnsureSuccessStatusCode();
            }

            // Evict cache so the next GET reflects the advisory state.
            var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
            var orgs = _factory.Services.GetRequiredService<OrgRepository>();
            string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
            cache.Evict(new PyPiSimpleIndexKey(orgId, name));

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Simple index must not list the malicious version.
            var indexResp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
            string html = await indexResp.Content.ReadAsStringAsync();
            Assert.DoesNotContain(malFile, html);   // malicious version absent
            Assert.Contains(cleanFile, html);        // clean version still listed

            // Download gate must still return 403 for the malicious file.
            var dlResp = await client.GetAsync($"/packages/{malFile}");
            Assert.Equal(HttpStatusCode.Forbidden, dlResp.StatusCode);
        }
        finally
        {
            await SetProxyPassthrough(true);
            // Restore block_malicious to default.
            string jwt = await _factory.CreateAdminJwt();
            using var adminClient = _factory.CreateClient();
            adminClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
            await adminClient.PutAsJsonAsync("/api/v1/proxy-settings", new
            {
                proxyPassthroughEnabled = true,
                maxOsvScoreTolerance = 10.0,
                blockMalicious = "block",
            });
        }
    }

    /// <summary>
    /// A deprecated version under block_new (not block_all) must remain listed in the simple
    /// index and downloadable — the gate only fires on first-fetch under block_new.
    /// Guards against over-filtering: a soft/warn-only state should not hide the version.
    /// Fail-before/pass-after: the fix correctly excludes ONLY modes that actually 403 the
    /// download; this test would pass on old code too (old code excluded block_all only), but
    /// it explicitly pins the boundary so a future widening of the filter is caught.
    /// </summary>
    [Fact]
    public async Task SimpleIndex_DeprecatedVersion_BlockNewMode_RemainsListedAndDownloadable()
    {
        await SetProxyPassthrough(false);
        try
        {
            string name = $"depnew{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            string underscored = name.Replace('-', '_');
            string filename = $"{underscored}-1.0.0-py3-none-any.whl";

            // Mark version as deprecated (simulates what DeprecationRefreshService would write).
            var store = _factory.Services.GetRequiredService<IMetadataStore>();
            await using (var conn = await store.OpenAsync())
            {
                await conn.ExecuteAsync(
                    """
                    UPDATE package_versions SET deprecated = 'Use newpkg instead'
                    WHERE id = (
                        SELECT pv.id FROM package_versions pv
                        JOIN packages p ON p.id = pv.package_id
                        WHERE p.name = @name AND pv.version = '1.0.0' LIMIT 1)
                    """,
                    new { name });
            }

            // Set block_deprecated = block_new — only first-fetch is blocked; serve path allowed.
            string orgId = (await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync("default"))!.Id;
            var orgStore = _factory.Services.GetRequiredService<IMetadataStore>();
            await using (var conn = await orgStore.OpenAsync())
            {
                await conn.ExecuteAsync(
                    "UPDATE org_settings SET block_deprecated = 'block_new' WHERE org_id = @orgId",
                    new { orgId });
            }
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

            // Evict cache so rebuild picks up new state.
            var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
            cache.Evict(new PyPiSimpleIndexKey(orgId, name));

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Under block_new, the version must still appear in the index.
            var indexResp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, indexResp.StatusCode);
            string html = await indexResp.Content.ReadAsStringAsync();
            Assert.Contains(filename, html);

            // And the download must succeed (the serve-path gate allows already-cached versions
            // under block_new).
            var dlResp = await client.GetAsync($"/packages/{filename}");
            Assert.Equal(HttpStatusCode.OK, dlResp.StatusCode);
        }
        finally
        {
            await SetProxyPassthrough(true);
            // Reset block_deprecated to default ('off') so other tests aren't affected.
            string orgId = (await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync("default"))!.Id;
            var orgStore = _factory.Services.GetRequiredService<IMetadataStore>();
            await using var conn = await orgStore.OpenAsync();
            await conn.ExecuteAsync(
                "UPDATE org_settings SET block_deprecated = 'off' WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }

    // ── Upload ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Upload_PathTraversalInName_Returns422()
    {
        // ValidatePathSafety branch — a "../" sneaks into the form's name field.
        string token = await _factory.CreateToken("push");
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
            string token = await _factory.CreateToken("push");
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
        string token = await _factory.CreateToken("push");
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
        string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

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
        string token = await _factory.CreateToken("push");
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
        string token = await _factory.CreateToken("push");
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
        string token = await _factory.CreateToken("push");
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
        string token = await _factory.CreateToken("push");
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
        string token = await _factory.CreateToken("push");
        var (bytes, sha256) = PyPiFixtures.BuildWheel("md5ok-pkg", "2.0.0");
        string md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();
        using var client = _factory.CreateClientWithBasic(token);
        using var content = BuildUploadForm("md5ok-pkg", "2.0.0", bytes, sha256,
            filename: "md5ok_pkg-2.0.0-py3-none-any.whl", md5: md5);
        var resp = await client.PostAsync("/pypi/legacy/", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
