using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the block_malicious proxy gate: a version linked to an OSV
/// <c>MAL-</c> advisory (which carries no CVSS score, so the score-tolerance gate never sees
/// it) is denied with 403 under 'block', allowed under 'off'/'warn', and the manual allow
/// override still wins. Also covers the /api/v1/proxy-settings surface for the new field.
/// Tests within this class run sequentially (xUnit class collection), so each download test
/// pins the default org's proxy settings to the state it needs before acting.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MaliciousGateTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public MaliciousGateTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    // ── download gate ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Download_UnscoredMalAdvisory_BlockMode_Returns403_AndLogsActivity()
    {
        string pkg = $"mal-blocked-{Guid.NewGuid():N}";
        await SetProxySettingsAsync(blockMalicious: "block");
        string malId = await SeedMalAdvisoryAsync(pkg, "1.0.0");

        var resp = await DownloadTarballAsync(pkg, "1.0.0");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);

        // Activity rows are written through the async batching writer — drain before asserting.
        await _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            """
            SELECT detail FROM activity
            WHERE event_type = 'blocked_malicious' AND purl LIKE @purlPrefix
            """,
            new { purlPrefix = $"pkg:npm/{pkg}@%" });
        Assert.NotNull(detail);
        Assert.Contains(malId, detail);
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public async Task Download_UnscoredMalAdvisory_NonBlockingMode_Returns200(string mode)
    {
        string pkg = $"mal-{mode}-{Guid.NewGuid():N}";
        await SetProxySettingsAsync(blockMalicious: mode);
        await SeedMalAdvisoryAsync(pkg, "1.0.0");

        var resp = await DownloadTarballAsync(pkg, "1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Download_MalAdvisory_ManualAllowOverride_Returns200()
    {
        // The false-positive escape hatch: an operator allow on the version outranks the gate.
        string pkg = $"mal-override-{Guid.NewGuid():N}";
        await SetProxySettingsAsync(blockMalicious: "block");
        await SeedMalAdvisoryAsync(pkg, "1.0.0");

        using var admin = await AdminClient();
        var unblock = await admin.PostAsync($"/api/v1/packages/npm/{pkg}/1.0.0/unblock", content: null);
        unblock.EnsureSuccessStatusCode();

        var resp = await DownloadTarballAsync(pkg, "1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── /api/v1/proxy-settings surface ────────────────────────────────────────

    [Fact]
    public async Task ProxySettings_Get_NoSettingsRow_DefaultsBlockMaliciousToBlock()
    {
        // An org with no org_settings row at all (the pre-first-save state) must read the
        // secure default.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM org_settings WHERE org_id = (SELECT id FROM orgs WHERE slug = 'default')");
        }

        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/proxy-settings");
        resp.EnsureSuccessStatusCode();
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("block", doc.RootElement.GetProperty("block_malicious").GetString());
    }

    [Fact]
    public async Task ProxySettings_Put_RoundTripsBlockMalicious()
    {
        using var c = await AdminClient();
        await SetProxySettingsAsync(blockMalicious: "warn");

        var resp = await c.GetAsync("/api/v1/proxy-settings");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("warn", doc.RootElement.GetProperty("block_malicious").GetString());

        await SetProxySettingsAsync(blockMalicious: "block");
    }

    [Fact]
    public async Task ProxySettings_Put_AbsentBlockMalicious_ResetsToSecureDefault()
    {
        using var c = await AdminClient();
        await SetProxySettingsAsync(blockMalicious: "warn");

        // A payload without the field (pre-gate automation) must not preserve a weaker mode.
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
        });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var resp = await c.GetAsync("/api/v1/proxy-settings");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("block", doc.RootElement.GetProperty("block_malicious").GetString());
    }

    [Fact]
    public async Task ProxySettings_Put_InvalidBlockMalicious_Returns422()
    {
        using var c = await AdminClient();
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockMalicious = "block_new", // valid for block_deprecated, not here
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, put.StatusCode);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task SetProxySettingsAsync(string blockMalicious)
    {
        using var c = await AdminClient();
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            blockMalicious,
        });
        put.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Pushes a hosted npm package, links an unscored MAL- advisory to its version, and stamps
    /// <c>vuln_checked_at</c> so the serve-path gate evaluates advisory data. Returns the
    /// advisory's OSV id.
    /// </summary>
    private async Task<string> SeedMalAdvisoryAsync(string pkgName, string version)
    {
        await _factory.PushNpmPackage(pkgName, version);
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string? versionId = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.name = @pkgName AND pv.version = @version
            LIMIT 1
            """,
            new { pkgName, version });
        Assert.NotNull(versionId);

        string malId = $"MAL-2026-{Guid.NewGuid():N}";
        string vulnId = Guid.NewGuid().ToString("N");
        // Severity and cvss_score deliberately NULL — the real-world MAL- advisory shape that
        // slips past a score-only gate.
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities
                (id, osv_id, ecosystem, package_name, severity, cvss_score, summary, modified_at, fetched_at)
            VALUES
                (@vulnId, @malId, 'npm', @pkgName, NULL, NULL, 'Malicious code in package',
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { vulnId, malId, pkgName });
        string pvvId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind) VALUES (@pvvId, @versionId, @vulnId, 'package_version')",
            new { pvvId, versionId, vulnId });
        await conn.ExecuteAsync(
            "UPDATE package_versions SET vuln_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @versionId",
            new { versionId });
        return malId;
    }

    private async Task<HttpResponseMessage> DownloadTarballAsync(string pkgName, string version)
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Construct the tarball URL directly — blocked versions are absent from the packument
        // after block-gate filtering, so reading tarball from the packument would fail.
        string tarballPath = $"/npm/tarballs/{pkgName}/{pkgName}-{version}.tgz";
        return await client.GetAsync(tarballPath);
    }
}
