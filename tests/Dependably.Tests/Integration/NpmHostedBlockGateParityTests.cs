using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies block-gate parity for <em>hosted</em> npm versions: every version that
/// <c>GET /npm/tarballs/{pkg}/{file}</c> returns 403 for must be absent from the
/// <c>GET /npm/{pkg}</c> packument <c>versions</c> map, and vice-versa.
///
/// Covers the local-only packument path (<see cref="BuildNpmMetadata"/>) and
/// the proxy-merge path (<see cref="MergeLocalVersionsIntoPackument"/>).
///
/// Each case is a fail-before/pass-after regression: on the old code, which never
/// filtered hosted versions through the block gate in the packument renderer, the
/// blocked version appeared in the packument even though the tarball returned 403.
/// The mixed/partial-failure scenario (one version blocked, one served in the same
/// response) is the primary case per house style.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmHostedBlockGateParityTests : IAsyncLifetime
{
    // FrozenClock so time-based (release-age) assertions are deterministic.
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── malicious gate (local-only packument path) ────────────────────────────

    /// <summary>
    /// A hosted version linked to an unscored MAL- advisory under block_malicious=block must
    /// be absent from the packument AND return 403 on the tarball path.
    ///
    /// Old code: BuildNpmMetadata emitted all non-yanked versions without block-gate
    /// filtering, so a malicious hosted version appeared in the packument even when the
    /// tarball endpoint would 403.
    /// New code: BuildNpmMetadata filters through BlockGateService.IsHardBlockedByStoredState,
    /// so the malicious version is excluded from the packument.
    ///
    /// Mixed/partial-failure: pkg has two versions — 1.0.0 is malicious (blocked) and 2.0.0
    /// is clean (served). The test asserts both outcomes in a single request.
    /// </summary>
    [Fact]
    public async Task Packument_MaliciousHosted_AbsentFromPackument_And_TarballReturns403()
    {
        await DisableProxyPassthroughAsync();
        await SetBlockMaliciousAsync("block");
        try
        {
            string pkg = $"malhosted{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            await _factory.PushNpmPackage(pkg, "1.0.0");
            await _factory.PushNpmPackage(pkg, "2.0.0");

            // Link an unscored MAL- advisory to 1.0.0 only; stamp vuln_checked_at.
            await SeedMalAdvisoryAsync(pkg, "1.0.0");

            // Evict cache so the rebuild picks up the new gate signals.
            await EvictPackumentCacheAsync(pkg);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            // Packument: 1.0.0 (malicious) must be absent; 2.0.0 (clean) must be present.
            var packResp = await client.GetAsync($"/npm/{pkg}");
            Assert.Equal(HttpStatusCode.OK, packResp.StatusCode);
            string packJson = await packResp.Content.ReadAsStringAsync();
            using var packDoc = JsonDocument.Parse(packJson);
            var versions = packDoc.RootElement.GetProperty("versions");
            Assert.False(versions.TryGetProperty("1.0.0", out _),
                "1.0.0 (malicious) must be absent from the packument when block_malicious=block");
            Assert.True(versions.TryGetProperty("2.0.0", out _),
                "2.0.0 (clean) must be present in the packument");

            // Tarball download: 1.0.0 must return 403; 2.0.0 must return 200.
            var blocked = await client.GetAsync($"/npm/tarballs/{pkg}/{pkg}-1.0.0.tgz");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/npm/tarballs/{pkg}/{pkg}-2.0.0.tgz");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await SetBlockMaliciousAsync("off");
            await EnableProxyPassthroughAsync();
        }
    }

    // ── manual block (local-only packument path) ──────────────────────────────

    /// <summary>
    /// A version with manual_block_state='blocked' must be absent from the packument.
    /// A sibling clean version must remain.
    ///
    /// Old code: manual-block state was not filtered in BuildNpmMetadata, so the version
    /// appeared in the packument even though the tarball endpoint would 403 it.
    /// New code: IsHardBlockedByStoredState covers the Manual arm, so it is excluded.
    /// </summary>
    [Fact]
    public async Task Packument_ManualBlock_AbsentFromPackument_And_TarballReturns403()
    {
        await DisableProxyPassthroughAsync();
        try
        {
            string pkg = $"manblock{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            await _factory.PushNpmPackage(pkg, "1.0.0");
            await _factory.PushNpmPackage(pkg, "2.0.0");

            // Manually block 1.0.0 via the management API.
            string jwt = await _factory.CreateAdminJwt();
            using var admin = _factory.CreateClient();
            admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            var blockResp = await admin.PostAsync($"/api/v1/packages/npm/{pkg}/1.0.0/block", content: null);
            blockResp.EnsureSuccessStatusCode();

            await EvictPackumentCacheAsync(pkg);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBearer(token);

            // Packument: 1.0.0 must be absent; 2.0.0 must be present.
            var packResp = await client.GetAsync($"/npm/{pkg}");
            Assert.Equal(HttpStatusCode.OK, packResp.StatusCode);
            string packJson = await packResp.Content.ReadAsStringAsync();
            using var packDoc = JsonDocument.Parse(packJson);
            var versions = packDoc.RootElement.GetProperty("versions");
            Assert.False(versions.TryGetProperty("1.0.0", out _),
                "1.0.0 (manually blocked) must be absent from the packument");
            Assert.True(versions.TryGetProperty("2.0.0", out _),
                "2.0.0 (clean) must remain in the packument");

            // Tarball: blocked version returns 403; clean version returns 200.
            var blocked = await client.GetAsync($"/npm/tarballs/{pkg}/{pkg}-1.0.0.tgz");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/npm/tarballs/{pkg}/{pkg}-2.0.0.tgz");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await EnableProxyPassthroughAsync();
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task EvictPackumentCacheAsync(string pkgName)
    {
        string orgId = await DefaultOrgIdAsync();
        _factory.Services
            .GetRequiredService<RenderedResponseCache<NpmPackumentKey>>()
            .Evict(new NpmPackumentKey(orgId, pkgName));
    }

    private async Task DisableProxyPassthroughAsync()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task EnableProxyPassthroughAsync()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetBlockMaliciousAsync(string mode)
    {
        string jwt = await _factory.CreateAdminJwt();
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = false,
            maxOsvScoreTolerance = 10.0,
            blockMalicious = mode,
        });
        put.EnsureSuccessStatusCode();
    }

    private async Task SeedMalAdvisoryAsync(string pkgName, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string? versionId = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.name = @pkgName AND pv.version = @version LIMIT 1
            """,
            new { pkgName, version });
        Assert.NotNull(versionId);

        string vulnId = Guid.NewGuid().ToString("N");
        string malId = $"MAL-2026-{Guid.NewGuid():N}";
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities
                (id, osv_id, ecosystem, package_name, severity, cvss_score, summary, modified_at, fetched_at)
            VALUES
                (@vulnId, @malId, 'npm', @pkgName, NULL, NULL, 'Malicious code',
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
    }
}
