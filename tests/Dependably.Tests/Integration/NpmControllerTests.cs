using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for NpmController paths not exercised by NpmComplianceTests.
/// Targets the uncovered branches: hosted-package auth gate, unknown-version 404,
/// tarball auth + proxy-passthrough-disabled, and cross-org token rejection on publish.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NpmControllerTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Hosted package metadata — auth gate ──────────────────────────────────

    /// <summary>
    /// Hosted (non-proxy) packages require a Bearer token. An unauthenticated GET must
    /// return 401 with a WWW-Authenticate: Bearer header — exercising the "pkg is not null
    /// and !pkg.IsProxy and token is null → Unauthorized" branch in GetPackageMetadata.
    /// </summary>
    [Fact]
    public async Task GetPackage_HostedPackage_WithoutToken_Returns401()
    {
        await _factory.PushNpmPackage("hosted-auth-gate", "1.0.0");

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/npm/hosted-auth-gate");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    // ── Version endpoint — unknown version 404 ───────────────────────────────

    /// <summary>
    /// GET /npm/{name}/{version} must return 404 when the package exists but the
    /// requested version is not in the versions object — exercising the
    /// versionData is null → NotFound() branch in GetVersion.
    /// </summary>
    [Fact]
    public async Task GetVersion_UnknownVersion_Returns404()
    {
        await _factory.PushNpmPackage("version-404-pkg", "1.0.0");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/version-404-pkg/99.0.0");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Tarball download — hosted package ───────────────────────────────────

    /// <summary>
    /// Downloading the tarball of a hosted package with a valid token must return 200.
    /// Exercises the ServeHostedTarballAsync happy path.
    /// </summary>
    [Fact]
    public async Task GetTarball_HostedPackage_WithToken_Returns200()
    {
        await _factory.PushNpmPackage("hosted-tarball-ok", "1.0.0");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Resolve tarball URL from the metadata response.
        var json = await client.GetStringAsync("/npm/hosted-tarball-ok");
        using var doc = JsonDocument.Parse(json);
        var tarballUrl = doc.RootElement
            .GetProperty("versions").GetProperty("1.0.0")
            .GetProperty("dist").GetProperty("tarball").GetString()!;

        var resp = await client.GetAsync(new Uri(tarballUrl).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    /// <summary>
    /// Downloading a hosted tarball without a token must return 401 with
    /// WWW-Authenticate: Bearer — exercising the "token is null → Unauthorized" branch
    /// in ServeHostedTarballAsync.
    /// </summary>
    [Fact]
    public async Task GetTarball_HostedPackage_WithoutToken_Returns401()
    {
        await _factory.PushNpmPackage("hosted-tarball-noauth", "1.0.0");

        // Need a token to read the metadata (hosted auth gate), then drop auth for tarball.
        var readToken = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBearer(readToken);

        var json = await authClient.GetStringAsync("/npm/hosted-tarball-noauth");
        using var doc = JsonDocument.Parse(json);
        var tarballUrl = doc.RootElement
            .GetProperty("versions").GetProperty("1.0.0")
            .GetProperty("dist").GetProperty("tarball").GetString()!;

        // Request without any auth header.
        using var anonClient = _factory.CreateClient();
        var resp = await anonClient.GetAsync(new Uri(tarballUrl).PathAndQuery);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    // ── Proxy passthrough disabled → 404 ────────────────────────────────────

    /// <summary>
    /// When proxy passthrough is disabled for the org, a tarball request for an unknown
    /// (not yet cached) package must return 404 — exercising the
    /// !settings.ProxyPassthroughEnabled → NotFound() branch.
    /// </summary>
    [Fact]
    public async Task GetTarball_ProxyPassthroughDisabled_Returns404()
    {
        // Disable proxy passthrough via direct DB write (mirrors UpsertProxySettingsAsync).
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, proxy_passthrough_enabled, max_osv_score_tolerance)
            VALUES (@orgId, 0, 10.0)
            ON CONFLICT(org_id) DO UPDATE SET proxy_passthrough_enabled = 0
            """,
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);

        try
        {
            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            var resp = await client.GetAsync("/npm/tarballs/never-pushed-pkg/never-pushed-pkg-1.0.0.tgz");

            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            // Restore default so other tests are not affected.
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        }
    }

    // ── Publish — cross-org token rejected ──────────────────────────────────

    /// <summary>
    /// Publishing to the default org with a token issued for a different org must return 401.
    /// Exercises the token.OrgId != orgId guard in PublishPackage.
    /// </summary>
    [Fact]
    public async Task Publish_TokenOrgMismatch_Returns401()
    {
        // Create a second org directly in the DB so we can issue a token for it.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();

        await using var conn = await store.OpenAsync();
        var otherOrgId = Guid.NewGuid().ToString("N");
        var otherOrgSlug = $"other-org-{otherOrgId[..8]}";
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = otherOrgId, slug = otherOrgSlug });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@orgId)",
            new { orgId = otherOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(otherOrgId);

        // Token issued for the OTHER org.
        var (rawToken, _) = await tokens.CreateServiceTokenAsync(
            otherOrgId,
            $"cross-org-token-{otherOrgId[..8]}",
            """["publish:*","read:artifact","read:metadata","yank:*"]""",
            expiresAt: null);

        var body = NpmFixtures.BuildPublishBody("cross-org-pkg", "1.0.0");
        using var client = _factory.CreateClientWithBearer(rawToken);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");

        // POST to the DEFAULT org's endpoint — token is for the other org.
        var resp = await client.PutAsync("/npm/cross-org-pkg", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
