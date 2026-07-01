using System.Net;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Extended branch coverage for NpmController paths not exercised by NpmControllerTests,
/// NpmComplianceTests, or MixedOriginRoutingTests.
///
/// Covers: scoped GET happy path, GetVersion success, scoped tarball routing, proxy passthrough
/// metadata merging when no local package exists, proxy upstream failure fall-through, anonymous
/// access gates (anonymous pull on/off across proxy + hosted), tarball proxy fetch cache MISS,
/// upstream 404 on tarball, blocklist 403, allowlist 403, 413 instance limit branch, publish
/// validation rejections (invalid JSON, name mismatch, missing attachments, bad base64, length
/// mismatch, version key empty, package.json inner mismatch, invalid name), unauthenticated
/// publish, scoped publish happy path, and the dist-tags rewrite on the packument.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmControllerExtendedTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NpmControllerExtendedTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ──────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgIdAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, anonymous_pull)
            VALUES (@orgId, @flag)
            ON CONFLICT(org_id) DO UPDATE SET anonymous_pull = @flag
            """,
            new { orgId, flag = enabled ? 1 : 0 });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    // ── GetVersion happy path ────────────────────────────────────────────────

    [Fact]
    public async Task GetVersion_KnownVersion_Returns200WithVersionObject()
    {
        await _factory.PushNpmPackage("known-version-pkg", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/known-version-pkg/1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("known-version-pkg", doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("1.0.0", doc.RootElement.GetProperty("version").GetString());
    }

    // ── GetScopedPackage routes through PackageMetadata happy path ───────────

    [Fact]
    public async Task GetScopedPackage_HostedScopedPackage_ReturnsMergedMetadata()
    {
        await _factory.PushNpmPackage("@xtended/scoped-meta", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/@xtended/scoped-meta");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("@xtended/scoped-meta", doc.RootElement.GetProperty("name").GetString());
        Assert.True(doc.RootElement.GetProperty("versions").TryGetProperty("1.0.0", out _));
    }

    // ── Anonymous pull on a proxy-only package → 200 from upstream ───────────

    [Fact]
    public async Task GetPackage_AnonymousPull_NoLocalPackage_ProxyMetadataReturned()
    {
        string name = $"proxyonlyanon{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string upstreamJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": {"latest":"1.0.0"},
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "dist": {"tarball":"https://registry.npmjs.org/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"deadbeef"}
                }
              }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        await SetAnonymousPullAsync(true);
        try
        {
            using var anon = _factory.CreateClient();
            var resp = await anon.GetAsync($"/npm/{name}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            string tarball = doc.RootElement.GetProperty("versions").GetProperty("1.0.0")
                .GetProperty("dist").GetProperty("tarball").GetString()!;
            // Rewritten to host-local tarball path
            Assert.Contains("/npm/tarballs/", tarball);
            Assert.DoesNotContain("registry.npmjs.org", tarball);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // ── Anonymous pull disabled + no token → 401 on proxy passthrough path ──

    [Fact]
    public async Task GetPackage_ProxyPassthroughOn_AnonymousPullOff_NoToken_Returns401()
    {
        string name = $"proxyauth{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        // Upstream isn't even hit because the auth gate fires before ProxyNpmMetadata.
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    // ── Upstream failure with no local versions → 404 ────────────────────────

    [Fact]
    public async Task GetPackage_UpstreamReturns404_NoLocalPkg_Returns404()
    {
        string name = $"upstreammiss{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Tarball cache MISS → upstream fetch + 200 ───────────────────────────

    [Fact]
    public async Task GetTarball_CacheMiss_FetchesFromUpstream()
    {
        string name = $"tarmiss{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        // X-Cache header should be MISS on first fetch.
        Assert.Contains("MISS", resp.Headers.GetValues("X-Cache").FirstOrDefault() ?? "");
    }

    // ── Tarball upstream 404 → 404 ───────────────────────────────────────────

    [Fact]
    public async Task GetTarball_UpstreamReturns404_Returns404()
    {
        string name = $"tar404{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string filename = $"{name}-1.0.0.tgz";

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Scoped tarball download routes through GetScopedTarball ──────────────

    [Fact]
    public async Task GetScopedTarball_HostedScoped_DownloadsViaScopedRoute()
    {
        await _factory.PushNpmPackage("@ext/scoped-tar", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/tarballs/@ext/scoped-tar/scoped-tar-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
    }

    // ── Blocklist matches → 403 even when proxy passthrough allowed ─────────

    [Fact]
    public async Task GetTarball_PackageInBlocklist_Returns403()
    {
        var blocklist = _factory.Services.GetRequiredService<BlocklistRepository>();
        string orgId = await DefaultOrgIdAsync();
        string name = $"blockednpm{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await blocklist.AddAsync(orgId, $"^pkg:npm/{name}$");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{name}-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Allowlist mode → 403 for non-allowlisted package ────────────────────

    [Fact]
    public async Task GetTarball_AllowlistModeOn_NotAllowed_Returns403()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, allowlist_mode)
            VALUES (@orgId, 1)
            ON CONFLICT(org_id) DO UPDATE SET allowlist_mode = 1
            """,
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);
            string name = $"notallowed{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            var resp = await client.GetAsync($"/npm/tarballs/{name}/{name}-1.0.0.tgz");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET allowlist_mode = 0 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }

    // ── Publish — 413 size limit branch ─────────────────────────────────────

    [Fact]
    public async Task Publish_ExceedsOrgEcosystemLimit_Returns413()
    {
        await _factory.SetOrgLimit("default", "npm", 10);
        try
        {
            string token = await _factory.CreateToken("push");
            string body = NpmFixtures.BuildPublishBody("orglimit-pkg", "1.0.0");

            using var client = _factory.CreateClientWithBearer(token);
            using var content = new StringContent(body, Encoding.UTF8, "application/json");

            var resp = await client.PutAsync("/npm/orglimit-pkg", content);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "npm", long.MaxValue);
        }
    }

    // ── Publish — invalid JSON body → 422 ────────────────────────────────────

    [Fact]
    public async Task Publish_InvalidJson_Returns422()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent("{not-json", Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/whatever", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — _attachments empty → 422 ───────────────────────────────────

    [Fact]
    public async Task Publish_NoAttachments_Returns422()
    {
        string token = await _factory.CreateToken("push");
        string body = JsonSerializer.Serialize(new
        {
            name = "noattach-pkg",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = "noattach-pkg", version = "1.0.0" }
            },
            _attachments = new Dictionary<string, object>()
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/noattach-pkg", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — _attachments missing data field → 422 ──────────────────────

    [Fact]
    public async Task Publish_AttachmentMissingData_Returns422()
    {
        string token = await _factory.CreateToken("push");
        string body = JsonSerializer.Serialize(new
        {
            name = "nodata-pkg",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = "nodata-pkg", version = "1.0.0" }
            },
            _attachments = new Dictionary<string, object>
            {
                ["nodata-pkg-1.0.0.tgz"] = new { content_type = "application/octet-stream", length = 0 }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/nodata-pkg", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — invalid base64 in attachment → 422 ────────────────────────

    [Fact]
    public async Task Publish_AttachmentBadBase64_Returns422()
    {
        string token = await _factory.CreateToken("push");
        string body = JsonSerializer.Serialize(new
        {
            name = "badb64-pkg",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = "badb64-pkg", version = "1.0.0" }
            },
            _attachments = new Dictionary<string, object>
            {
                ["badb64-pkg-1.0.0.tgz"] = new
                {
                    content_type = "application/octet-stream",
                    data = "***not-base64***",
                    length = 16
                }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/badb64-pkg", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — declared length mismatch → 422 ─────────────────────────────

    [Fact]
    public async Task Publish_AttachmentLengthMismatch_Returns422()
    {
        string token = await _factory.CreateToken("push");
        var (tarball, _, _) = NpmFixtures.BuildTarball("lenmismatch-pkg", "1.0.0");
        string base64 = Convert.ToBase64String(tarball);

        string body = JsonSerializer.Serialize(new
        {
            name = "lenmismatch-pkg",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = "lenmismatch-pkg", version = "1.0.0" }
            },
            _attachments = new Dictionary<string, object>
            {
                ["lenmismatch-pkg-1.0.0.tgz"] = new
                {
                    content_type = "application/octet-stream",
                    data = base64,
                    length = tarball.Length + 999 // wrong
                }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/lenmismatch-pkg", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — versions object missing → 422 ──────────────────────────────

    [Fact]
    public async Task Publish_VersionsKeyAbsent_Returns422()
    {
        string token = await _factory.CreateToken("push");
        var (tarball, _, _) = NpmFixtures.BuildTarball("missing-versions", "1.0.0");
        string base64 = Convert.ToBase64String(tarball);

        // No "versions" field at all → ValidateBodyMatch's "versionKey is null" branch fires.
        string body = JsonSerializer.Serialize(new
        {
            name = "missing-versions",
            _attachments = new Dictionary<string, object>
            {
                ["missing-versions-1.0.0.tgz"] = new
                {
                    content_type = "application/octet-stream",
                    data = base64,
                    length = tarball.Length
                }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/missing-versions", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — package.json inner version mismatch → 422 ─────────────────

    [Fact]
    public async Task Publish_TarballInnerVersionMismatch_Returns422()
    {
        string token = await _factory.CreateToken("push");
        // Tarball says version 1.0.0; declared version is 2.0.0.
        var (tarball, _, _) = NpmFixtures.BuildTarball("ver-mismatch", "1.0.0");
        string base64 = Convert.ToBase64String(tarball);

        string body = JsonSerializer.Serialize(new
        {
            name = "ver-mismatch",
            versions = new Dictionary<string, object>
            {
                ["2.0.0"] = new { name = "ver-mismatch", version = "2.0.0" }
            },
            _attachments = new Dictionary<string, object>
            {
                ["ver-mismatch-2.0.0.tgz"] = new
                {
                    content_type = "application/octet-stream",
                    data = base64,
                    length = tarball.Length
                }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/ver-mismatch", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — illegal npm name → 422 ─────────────────────────────────────

    [Fact]
    public async Task Publish_InvalidNpmName_Returns422()
    {
        string token = await _factory.CreateToken("push");
        // Body name == URL name but it's invalid (uppercase letters not allowed in npm names).
        string body = JsonSerializer.Serialize(new
        {
            name = "Bad-Name",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = "Bad-Name", version = "1.0.0" }
            },
            _attachments = new Dictionary<string, object>
            {
                ["Bad-Name-1.0.0.tgz"] = new
                {
                    content_type = "application/octet-stream",
                    data = "AAAA",
                    length = 3
                }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        // Route is /npm/{package} — server decodes "Bad-Name" verbatim; validation must reject.
        var resp = await client.PutAsync("/npm/Bad-Name", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — scoped happy path with packument-deprecated field ─────────

    [Fact]
    public async Task Publish_ScopedWithDeprecated_StoresDeprecationFlag()
    {
        string token = await _factory.CreateToken("push");
        var (tarball, _, _) = NpmFixtures.BuildTarball("@dep/scoped-deprecated", "1.0.0");
        string base64 = Convert.ToBase64String(tarball);
        string filename = "@dep/scoped-deprecated-1.0.0.tgz";

        string body = JsonSerializer.Serialize(new
        {
            name = "@dep/scoped-deprecated",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new
                {
                    name = "@dep/scoped-deprecated",
                    version = "1.0.0",
                    deprecated = "use newer-package instead"
                }
            },
            _attachments = new Dictionary<string, object>
            {
                [filename] = new
                {
                    content_type = "application/octet-stream",
                    data = base64,
                    length = tarball.Length
                }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/@dep/scoped-deprecated", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Confirm deprecation persisted via UpdateDeprecatedAsync branch.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? deprecated = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.deprecated FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = 'npm' AND p.purl_name = '@dep/scoped-deprecated' AND pv.version = '1.0.0'
            """);
        Assert.Equal("use newer-package instead", deprecated);
    }

    // ── Publish — scoped via the real npm CLI's %2F-encoded URL ─────────────
    // The npm client PUTs scoped packages to /npm/@scope%2Fname (slash encoded),
    // which lands on the unscoped route. Regression test for that path resolving
    // to a successful scoped publish rather than a 422 name-validation failure.
    [Fact]
    public async Task Publish_ScopedViaEncodedSlash_Succeeds()
    {
        string token = await _factory.CreateToken("push");
        var (tarball, _, _) = NpmFixtures.BuildTarball("@dep/cli-scoped", "1.0.0");
        string base64 = Convert.ToBase64String(tarball);
        string filename = "@dep/cli-scoped-1.0.0.tgz";

        string body = JsonSerializer.Serialize(new
        {
            name = "@dep/cli-scoped",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = "@dep/cli-scoped", version = "1.0.0" }
            },
            _attachments = new Dictionary<string, object>
            {
                [filename] = new
                {
                    content_type = "application/octet-stream",
                    data = base64,
                    length = tarball.Length
                }
            }
        });

        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        // %2F-encoded slash, exactly as the npm CLI sends it.
        var resp = await client.PutAsync("/npm/@dep%2Fcli-scoped", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Stored under the real scoped name, not a mangled "@dep/cli-scoped" plain name.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = 'npm' AND p.purl_name = '@dep/cli-scoped' AND pv.version = '1.0.0'
            """);
        Assert.Equal(1, count);
    }

    // ── Hosted GetPackage — package exists but no versions row → 404 path ──

    [Fact]
    public async Task GetVersion_PackageExistsNoMatchingVersion_Returns404()
    {
        await _factory.PushNpmPackage("just-one-version", "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Request a version that exists but with different casing of suffix
        var resp = await client.GetAsync("/npm/just-one-version/0.0.0-missing");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Publish body cap — oversized body without Content-Length → 413 ────────

    /// <summary>
    /// When an npm publish body exceeds the configured limit and is sent without a
    /// Content-Length header (chunked / unknown-length stream), the middleware cannot
    /// pre-screen it. The LimitedReadStream in ParsePublishBodyAsync catches it and
    /// returns 413 — the body-streaming cap that closes the gap when Content-Length
    /// is absent.
    /// </summary>
    [Fact]
    public async Task Publish_OversizedBodyWithoutContentLength_Returns413FromBodyCap()
    {
        // Use a small limit so the synthetic body (a few KB) crosses it.
        const long smallCap = 512;
        await _factory.SetOrgLimit("default", "npm", smallCap);
        try
        {
            string token = await _factory.CreateToken("push");
            string body = NpmFixtures.BuildPublishBody("bodycap-chunked-pkg", "1.0.0");
            // Body is several KB — well above 512 bytes.
            Assert.True(Encoding.UTF8.GetByteCount(body) > smallCap);

            using var client = _factory.CreateClientWithBearer(token);
            // Wrap in a non-seekable stream so HttpClient cannot compute Content-Length
            // and must send chunked transfer — the middleware's pre-screen is skipped.
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            using var nonSeekable = new NonSeekableStream(new MemoryStream(bodyBytes));
            using var content = new StreamContent(nonSeekable);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var resp = await client.PutAsync("/npm/bodycap-chunked-pkg", content);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "npm", long.MaxValue);
        }
    }

    // Non-seekable stream wrapper — forces chunked transfer by hiding the content length.
    private sealed class NonSeekableStream(Stream inner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => inner.ReadAsync(buffer, offset, count, ct);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => inner.ReadAsync(buffer, ct);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    // ── Publish attachment pre-check — oversized declared length → 413 before decode ──

    /// <summary>
    /// When the attachment's declared decoded length exceeds the configured npm limit,
    /// the controller must reject with 413 before calling Convert.FromBase64String —
    /// avoiding the byte[] allocation for the oversized attachment.
    /// </summary>
    [Fact]
    public async Task Publish_OversizedDeclaredAttachmentLength_Returns413BeforeDecode()
    {
        // Use a small limit that is still large enough for the JSON scaffolding but smaller
        // than the declared attachment length we will inject.
        const long smallCap = 2048;
        await _factory.SetOrgLimit("default", "npm", smallCap);
        try
        {
            string token = await _factory.CreateToken("push");
            var (tarball, _, _) = NpmFixtures.BuildTarball("attach-precap-pkg", "1.0.0");
            string base64 = Convert.ToBase64String(tarball);

            // Declare a decoded length well above the cap — the actual base64 decodes to
            // tarball.Length bytes, which is small, but the declared value is huge.
            long oversizedDeclaredLength = smallCap + 100_000;

            string body = JsonSerializer.Serialize(new
            {
                name = "attach-precap-pkg",
                versions = new Dictionary<string, object>
                {
                    ["1.0.0"] = new { name = "attach-precap-pkg", version = "1.0.0" }
                },
                _attachments = new Dictionary<string, object>
                {
                    ["attach-precap-pkg-1.0.0.tgz"] = new
                    {
                        content_type = "application/octet-stream",
                        data = base64,
                        length = oversizedDeclaredLength
                    }
                }
            });

            using var client = _factory.CreateClientWithBearer(token);
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            var resp = await client.PutAsync("/npm/attach-precap-pkg", content);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "npm", long.MaxValue);
        }
    }

    // ── Publish — normal publish works with no npm limit configured ──────────

    /// <summary>
    /// When no org-level npm limit is configured the publish succeeds, confirming the
    /// fallback to the route hard ceiling does not block a legitimate small publish.
    /// </summary>
    [Fact]
    public async Task Publish_NoLimitConfigured_NormalPublishSucceeds()
    {
        // Ensure no npm limit is set (null = fall back to route ceiling).
        await _factory.SetOrgLimit("default", "npm", null);
        try
        {
            string token = await _factory.CreateToken("push");
            string body = NpmFixtures.BuildPublishBody("nolimit-pub-pkg", "1.0.0");
            using var client = _factory.CreateClientWithBearer(token);
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            var resp = await client.PutAsync("/npm/nolimit-pub-pkg", content);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "npm", long.MaxValue);
        }
    }

    // ── Proxy cache-hit: AnonymousPull disabled + no token → 401 ─────────────

    /// <summary>
    /// Seeds the proxy cache via an authenticated first fetch, then asserts that a subsequent
    /// tokenless GET of the same tarball returns 401 with <c>Bearer</c> when the org has
    /// <c>AnonymousPull = false</c>. Validates the cache-hit gate mirrors the HEAD behaviour.
    /// </summary>
    [Fact]
    public async Task GetTarball_ProxyCacheHit_AnonymousPullOff_NoToken_Returns401()
    {
        string name = $"cahit401{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        // Prime the proxy cache with an authenticated request.
        string token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBearer(token);
        var primeResp = await authClient.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        // AnonymousPull is false by default; the tokenless cache-hit must return 401.
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync($"/npm/tarballs/{name}/{filename}");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// Confirms that an org with <c>AnonymousPull = true</c> still serves a proxy cache-hit
    /// to unauthenticated clients — no regression for the allowed-anonymous configuration.
    /// </summary>
    [Fact]
    public async Task GetTarball_ProxyCacheHit_AnonymousPullOn_NoToken_Returns200()
    {
        string name = $"cahit200{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        // Prime the proxy cache with an authenticated request.
        string token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBearer(token);
        var primeResp = await authClient.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        await SetAnonymousPullAsync(true);
        try
        {
            // AnonymousPull enabled: the cache-hit must be served to unauthenticated clients.
            using var anon = _factory.CreateClient();
            var resp = await anon.GetAsync($"/npm/tarballs/{name}/{filename}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // ── Hosted tarball: AnonymousPull gate for uploaded-origin tarballs ────────

    /// <summary>
    /// Pushed (uploaded-origin) tarball is served to an anonymous client when
    /// <c>AnonymousPull = true</c>. Verifies the hosted-read path respects the org setting.
    /// </summary>
    [Fact]
    public async Task GetTarball_HostedUploaded_AnonymousPullOn_NoToken_Returns200()
    {
        string name = $"hostaon{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        await _factory.PushNpmPackage(name, version);
        string filename = $"{name}-{version}.tgz";

        await SetAnonymousPullAsync(true);
        try
        {
            using var anon = _factory.CreateClient();
            var resp = await anon.GetAsync($"/npm/tarballs/{name}/{filename}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    /// <summary>
    /// Pushed (uploaded-origin) tarball requires a token when <c>AnonymousPull = false</c>.
    /// The default setting; validates the gate holds.
    /// </summary>
    [Fact]
    public async Task GetTarball_HostedUploaded_AnonymousPullOff_NoToken_Returns401()
    {
        string name = $"hostoff{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        await _factory.PushNpmPackage(name, version);
        string filename = $"{name}-{version}.tgz";

        // AnonymousPull is false by default.
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync($"/npm/tarballs/{name}/{filename}");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// A token present but lacking <c>read:artifact</c> is still forbidden on a hosted tarball
    /// even when <c>AnonymousPull = true</c> — capability enforcement applies to real tokens.
    /// </summary>
    [Fact]
    public async Task GetTarball_HostedUploaded_AnonymousPullOn_TokenWithoutReadArtifact_Returns403()
    {
        string name = $"hostaocap{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "1.0.0";
        await _factory.PushNpmPackage(name, version);
        string filename = $"{name}-{version}.tgz";

        // Token with read:metadata only — no read:artifact.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var (rawToken, _) = await tokens.CreateServiceTokenAsync(
            orgId, "test-meta-only", """["read:metadata"]""", expiresAt: null);

        await SetAnonymousPullAsync(true);
        try
        {
            using var client = _factory.CreateClientWithBearer(rawToken);
            var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // ── Publish — 4xx rejection body carries an npm-readable `error` member ───

    /// <summary>
    /// The npm CLI renders only the <c>error</c> member of a registry error body; it ignores
    /// RFC 7807 <c>detail</c>/<c>title</c>. NpmErrorEnvelope mirrors <c>detail</c> into <c>error</c>
    /// so a rejected publish shows its reason instead of a bare "422 Unprocessable Entity".
    /// </summary>
    [Fact]
    public async Task Publish_Rejection_BodyCarriesNpmErrorMember()
    {
        string token = await _factory.CreateToken("push");
        // Body name disagrees with the URL package — ValidatePackageName rejects with 422.
        string body = JsonSerializer.Serialize(new { name = "other-name" });
        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/mismatch-pkg", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("error", out var error), "npm requires a top-level 'error' member.");
        Assert.False(string.IsNullOrWhiteSpace(error.GetString()));
        // The envelope mirrors RFC 7807 detail, which is preserved for non-npm clients.
        Assert.Equal(root.GetProperty("detail").GetString(), error.GetString());
    }
}
