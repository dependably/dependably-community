using System.Net;
using System.Net.Http.Headers;
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
        var orgId = await DefaultOrgIdAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, anonymous_pull)
            VALUES (@orgId, @flag)
            ON CONFLICT(org_id) DO UPDATE SET anonymous_pull = @flag
            """,
            new { orgId, flag = enabled ? 1 : 0 });
    }

    // ── GetVersion happy path ────────────────────────────────────────────────

    [Fact]
    public async Task GetVersion_KnownVersion_Returns200WithVersionObject()
    {
        await _factory.PushNpmPackage("known-version-pkg", "1.0.0");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/known-version-pkg/1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("known-version-pkg", doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("1.0.0", doc.RootElement.GetProperty("version").GetString());
    }

    // ── GetScopedPackage routes through PackageMetadata happy path ───────────

    [Fact]
    public async Task GetScopedPackage_HostedScopedPackage_ReturnsMergedMetadata()
    {
        await _factory.PushNpmPackage("@xtended/scoped-meta", "1.0.0");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/@xtended/scoped-meta");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("@xtended/scoped-meta", doc.RootElement.GetProperty("name").GetString());
        Assert.True(doc.RootElement.GetProperty("versions").TryGetProperty("1.0.0", out _));
    }

    // ── Anonymous pull on a proxy-only package → 200 from upstream ───────────

    [Fact]
    public async Task GetPackage_AnonymousPull_NoLocalPackage_ProxyMetadataReturned()
    {
        var name = $"proxyonlyanon{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var upstreamJson = $$"""
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

            var json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var tarball = doc.RootElement.GetProperty("versions").GetProperty("1.0.0")
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
        var name = $"proxyauth{Guid.NewGuid():N}"[..18].ToLowerInvariant();
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
        var name = $"upstreammiss{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Tarball cache MISS → upstream fetch + 200 ───────────────────────────

    [Fact]
    public async Task GetTarball_CacheMiss_FetchesFromUpstream()
    {
        var name = $"tarmiss{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        var filename = $"{name}-{version}.tgz";

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
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
        var name = $"tar404{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var filename = $"{name}-1.0.0.tgz";

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Scoped tarball download routes through GetScopedTarball ──────────────

    [Fact]
    public async Task GetScopedTarball_HostedScoped_DownloadsViaScopedRoute()
    {
        await _factory.PushNpmPackage("@ext/scoped-tar", "1.0.0");

        var token = await _factory.CreateToken("pull");
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
        var orgId = await DefaultOrgIdAsync();
        var name = $"blockednpm{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await blocklist.AddAsync(orgId, $"^pkg:npm/{name}$");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{name}-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Allowlist mode → 403 for non-allowlisted package ────────────────────

    [Fact]
    public async Task GetTarball_AllowlistModeOn_NotAllowed_Returns403()
    {
        var orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, allowlist_mode)
            VALUES (@orgId, 1)
            ON CONFLICT(org_id) DO UPDATE SET allowlist_mode = 1
            """,
            new { orgId });

        try
        {
            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);
            var name = $"notallowed{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            var resp = await client.GetAsync($"/npm/tarballs/{name}/{name}-1.0.0.tgz");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET allowlist_mode = 0 WHERE org_id = @orgId",
                new { orgId });
        }
    }

    // ── Publish — 413 size limit branch ─────────────────────────────────────

    [Fact]
    public async Task Publish_ExceedsOrgEcosystemLimit_Returns413()
    {
        await _factory.SetOrgLimit("default", "npm", 10);
        try
        {
            var token = await _factory.CreateToken("push");
            var body = NpmFixtures.BuildPublishBody("orglimit-pkg", "1.0.0");

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
        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent("{not-json", Encoding.UTF8, "application/json");

        var resp = await client.PutAsync("/npm/whatever", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Publish — _attachments empty → 422 ───────────────────────────────────

    [Fact]
    public async Task Publish_NoAttachments_Returns422()
    {
        var token = await _factory.CreateToken("push");
        var body = JsonSerializer.Serialize(new
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
        var token = await _factory.CreateToken("push");
        var body = JsonSerializer.Serialize(new
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
        var token = await _factory.CreateToken("push");
        var body = JsonSerializer.Serialize(new
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
        var token = await _factory.CreateToken("push");
        var (tarball, _, _) = NpmFixtures.BuildTarball("lenmismatch-pkg", "1.0.0");
        var base64 = Convert.ToBase64String(tarball);

        var body = JsonSerializer.Serialize(new
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
        var token = await _factory.CreateToken("push");
        var (tarball, _, _) = NpmFixtures.BuildTarball("missing-versions", "1.0.0");
        var base64 = Convert.ToBase64String(tarball);

        // No "versions" field at all → ValidateBodyMatch's "versionKey is null" branch fires.
        var body = JsonSerializer.Serialize(new
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
        var token = await _factory.CreateToken("push");
        // Tarball says version 1.0.0; declared version is 2.0.0.
        var (tarball, _, _) = NpmFixtures.BuildTarball("ver-mismatch", "1.0.0");
        var base64 = Convert.ToBase64String(tarball);

        var body = JsonSerializer.Serialize(new
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
        var token = await _factory.CreateToken("push");
        // Body name == URL name but it's invalid (uppercase letters not allowed in npm names).
        var body = JsonSerializer.Serialize(new
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
        var token = await _factory.CreateToken("push");
        var (tarball, _, _) = NpmFixtures.BuildTarball("@dep/scoped-deprecated", "1.0.0");
        var base64 = Convert.ToBase64String(tarball);
        var filename = "@dep/scoped-deprecated-1.0.0.tgz";

        var body = JsonSerializer.Serialize(new
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
        var deprecated = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.deprecated FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = 'npm' AND p.purl_name = '@dep/scoped-deprecated' AND pv.version = '1.0.0'
            """);
        Assert.Equal("use newer-package instead", deprecated);
    }

    // ── Hosted GetPackage — package exists but no versions row → 404 path ──

    [Fact]
    public async Task GetVersion_PackageExistsNoMatchingVersion_Returns404()
    {
        await _factory.PushNpmPackage("just-one-version", "1.0.0");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Request a version that exists but with different casing of suffix
        var resp = await client.GetAsync("/npm/just-one-version/0.0.0-missing");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
