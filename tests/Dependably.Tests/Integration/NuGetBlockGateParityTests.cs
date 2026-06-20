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
/// Verifies block-gate parity for NuGet: every version that
/// <c>GET /nuget/flatcontainer/{id}/{version}/{file}</c> returns 403 for must be absent
/// from both the registration index (<c>GET /nuget/registration/{id}/index.json</c>)
/// and the flatcontainer version list (<c>GET /nuget/flatcontainer/{id}/index.json</c>).
///
/// NuGet is local-row-only on its registration and flatcontainer surfaces — it does not
/// splice upstream-only versions into those listings; the upstream merge in registration
/// is a full upstream JSON passthrough (URL rewrite only) and the flatcontainer merge
/// adds upstream version strings from the upstream index. Block-gate filtering covers
/// only local-row (uploaded/proxy-cached) versions, which is the complete evaluable set.
///
/// Each case is a fail-before/pass-after regression: on the old code, the listing
/// surfaces advertised every version regardless of the block gate. The mixed/partial-failure
/// scenario (one version blocked, one served) is the primary case per house style.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetBlockGateParityTests : IAsyncLifetime
{
    // FrozenClock so time-based (release-age) assertions are deterministic.
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── manual block ─────────────────────────────────────────────────────────

    /// <summary>
    /// A manually-blocked NuGet version must be absent from both the registration index
    /// and the flatcontainer version list. A sibling clean version must remain in both.
    /// The download endpoint must return 403 for the blocked version and 200 for the clean one.
    ///
    /// Old code: both BuildLocalRegistration and FlatcontainerVersions emitted all non-yanked
    /// versions without block-gate filtering, so the blocked version appeared in both listings
    /// even though the flatcontainer download path would 403.
    /// New code: IsHardBlockedByStoredState filters the version from both surfaces.
    ///
    /// Mixed/partial-failure: pkg has two versions — 1.0.0 is manually blocked, 2.0.0 is clean.
    /// </summary>
    [Fact]
    public async Task Registration_And_Flatcontainer_ManualBlock_AbsentFromBothListings_And_DownloadReturns403()
    {
        await DisableProxyPassthroughAsync();
        try
        {
            string id = $"nugetblock{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            await _factory.PushNuGetPackage(id, "1.0.0");
            await _factory.PushNuGetPackage(id, "2.0.0");

            // Manually block 1.0.0 via the management API.
            string jwt = await _factory.CreateAdminJwt();
            using var admin = _factory.CreateClient();
            admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
            var blockResp = await admin.PostAsync($"/api/v1/packages/nuget/{id}/1.0.0/block", content: null);
            blockResp.EnsureSuccessStatusCode();

            // Evict registration cache so the rebuild picks up the new state.
            await EvictRegistrationCacheAsync(id);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Registration index: 1.0.0 must be absent; 2.0.0 must be present.
            var regResp = await client.GetAsync($"/nuget/registration/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);
            string regJson = await regResp.Content.ReadAsStringAsync();
            Assert.DoesNotContain("\"1.0.0\"", regJson, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("\"2.0.0\"", regJson, StringComparison.OrdinalIgnoreCase);

            // Flatcontainer version list: 1.0.0 must be absent; 2.0.0 must be present.
            var fcListResp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, fcListResp.StatusCode);
            string fcListJson = await fcListResp.Content.ReadAsStringAsync();
            using var fcListDoc = JsonDocument.Parse(fcListJson);
            var fcVersions = fcListDoc.RootElement.GetProperty("versions")
                .EnumerateArray().Select(v => v.GetString()).ToList();
            Assert.DoesNotContain("1.0.0", fcVersions, StringComparer.OrdinalIgnoreCase);
            Assert.Contains("2.0.0", fcVersions, StringComparer.OrdinalIgnoreCase);

            // Flatcontainer download: 1.0.0 must return 403; 2.0.0 must return 200.
            var blocked = await client.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/nuget/flatcontainer/{id}/2.0.0/{id}.2.0.0.nupkg");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await EnableProxyPassthroughAsync();
        }
    }

    // ── malicious gate ───────────────────────────────────────────────────────

    /// <summary>
    /// A NuGet version linked to an unscored MAL- advisory under block_malicious=block must
    /// be absent from both the registration index and the flatcontainer version list, and
    /// its download must return 403.
    ///
    /// Old code: neither listing surface evaluated the malicious arm, so a malicious version
    /// appeared in both listings even though the download path would 403.
    /// New code: IsHardBlockedByStoredState covers the Malicious arm, so it is excluded
    /// from both surfaces.
    ///
    /// Mixed/partial-failure: 1.0.0 is malicious (blocked), 2.0.0 is clean (served).
    /// </summary>
    [Fact]
    public async Task Registration_And_Flatcontainer_MaliciousVersion_AbsentFromBothListings()
    {
        await DisableProxyPassthroughAsync();
        await SetBlockMaliciousAsync("block");
        try
        {
            string id = $"nugetmal{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            await _factory.PushNuGetPackage(id, "1.0.0");
            await _factory.PushNuGetPackage(id, "2.0.0");

            // Link an unscored MAL- advisory to 1.0.0 and stamp vuln_checked_at.
            await SeedMalAdvisoryAsync(id, "1.0.0");

            // Evict registration cache so the rebuild picks up the new gate signals.
            await EvictRegistrationCacheAsync(id);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // Registration index: 1.0.0 must be absent; 2.0.0 must be present.
            var regResp = await client.GetAsync($"/nuget/registration/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);
            string regJson = await regResp.Content.ReadAsStringAsync();
            Assert.DoesNotContain("\"1.0.0\"", regJson, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("\"2.0.0\"", regJson, StringComparison.OrdinalIgnoreCase);

            // Flatcontainer version list: 1.0.0 must be absent; 2.0.0 must be present.
            var fcListResp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, fcListResp.StatusCode);
            string fcListJson = await fcListResp.Content.ReadAsStringAsync();
            using var fcListDoc = JsonDocument.Parse(fcListJson);
            var fcVersions = fcListDoc.RootElement.GetProperty("versions")
                .EnumerateArray().Select(v => v.GetString()).ToList();
            Assert.DoesNotContain("1.0.0", fcVersions, StringComparer.OrdinalIgnoreCase);
            Assert.Contains("2.0.0", fcVersions, StringComparer.OrdinalIgnoreCase);

            // Flatcontainer download: 1.0.0 must return 403; 2.0.0 must return 200.
            var blocked = await client.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/nuget/flatcontainer/{id}/2.0.0/{id}.2.0.0.nupkg");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await SetBlockMaliciousAsync("off");
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

    private async Task EvictRegistrationCacheAsync(string id)
    {
        string orgId = await DefaultOrgIdAsync();
        var cache = _factory.Services.GetRequiredService<RenderedResponseCache<NuGetRegistrationKey>>();
        cache.Evict(new NuGetRegistrationKey(orgId, id.ToLowerInvariant(), false));
        cache.Evict(new NuGetRegistrationKey(orgId, id.ToLowerInvariant(), true));
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
                (@vulnId, @malId, 'nuget', @pkgName, NULL, NULL, 'Malicious code',
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
