using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Both NuGet symbol read surfaces — the whole-<c>.snupkg</c> download
/// (<c>GET /nuget/symbols/{id}/{version}/{file}</c>) and the SSQP per-PDB route
/// (<c>GET /nuget/symbols/{pdb}/{key}/{pdb}</c>) — must run the same per-version block gate the
/// four flatcontainer serve surfaces run.
///
/// Before this, both paths' entire authorization decision was AnonymousPull + token resolution,
/// so a version that was manually blocked, license-blocked, flagged malicious/KEV, or revoked
/// still served its symbols. That matters more than the package itself: PDBs embed full source
/// file paths, and with embedded sources or SourceLink they reference or carry source directly.
///
/// Every blocked case is paired with its adversarial twin — an equivalent NON-blocked version
/// that must still serve 200 on the same route — so a gate that simply denies everything cannot
/// pass this suite.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetSymbolBlockGateTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── manual block ──────────────────────────────────────────────────────────

    [Fact]
    public async Task ManualBlock_RefusesSnupkgDownload_ButServesUnblockedTwin()
    {
        var blocked = await SeedSymbolPackageAsync();
        var allowed = await SeedSymbolPackageAsync();
        await SetManualBlockStateAsync(blocked.VersionId, "blocked");

        using var client = await ReadClientAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SnupkgUrl(blocked))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SnupkgUrl(allowed))).StatusCode);
    }

    [Fact]
    public async Task ManualBlock_RefusesSsqpPdb_ButServesUnblockedTwin()
    {
        var blocked = await SeedSymbolPackageAsync();
        var allowed = await SeedSymbolPackageAsync();
        await SetManualBlockStateAsync(blocked.VersionId, "blocked");

        using var client = await ReadClientAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SsqpUrl(blocked))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SsqpUrl(allowed))).StatusCode);
    }

    // ── revocation ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Revoked_RefusesBothSymbolRoutes_ButServesUnrevokedTwin()
    {
        await SetProxySettingAsync(blockRevoked: "block");
        var revoked = await SeedSymbolPackageAsync();
        var allowed = await SeedSymbolPackageAsync();
        await MarkRevokedAsync(revoked.VersionId);

        using var client = await ReadClientAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SnupkgUrl(revoked))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SsqpUrl(revoked))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SnupkgUrl(allowed))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SsqpUrl(allowed))).StatusCode);
    }

    // ── malicious advisory ────────────────────────────────────────────────────

    [Fact]
    public async Task Malicious_RefusesBothSymbolRoutes_ButServesCleanTwin()
    {
        await SetProxySettingAsync(blockMalicious: "block");
        var malicious = await SeedSymbolPackageAsync();
        var clean = await SeedSymbolPackageAsync();
        await SeedMalAdvisoryAsync(malicious);

        using var client = await ReadClientAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SnupkgUrl(malicious))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SsqpUrl(malicious))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SnupkgUrl(clean))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SsqpUrl(clean))).StatusCode);
    }

    // ── license enforcement ───────────────────────────────────────────────────

    [Fact]
    public async Task LicenseBlocked_RefusesBothSymbolRoutes_ButServesAllowedTwin()
    {
        var blocked = await SeedSymbolPackageAsync();
        var allowed = await SeedSymbolPackageAsync();
        // license_enforcement_mode='block' is allowlist-only: a leaf passes only when it is on the
        // org allowlist and off the blocklist (LicenseRepository.CheckPolicyAsync). So the twin
        // needs BOTH a recorded licence and that licence allowlisted; the blocked one keeps the
        // fixture nuspec's zero recorded entries, which for NuGet — a DeclaredLicenseEcosystems
        // member — is an unknown licence and denies.
        await SetLicenseSpdxAsync(allowed.VersionId, "MIT");
        await AllowlistLicenseAsync("MIT");
        await SetLicenseEnforcementModeAsync("block");

        using var client = await ReadClientAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SnupkgUrl(blocked))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync(SsqpUrl(blocked))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SnupkgUrl(allowed))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(SsqpUrl(allowed))).StatusCode);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private sealed record SeededSymbols(string Id, string Version, string VersionId, string SsqpKey);

    private static string SnupkgUrl(SeededSymbols s) =>
        $"/nuget/symbols/{s.Id}/{s.Version}/{s.Id}.{s.Version}.snupkg";

    private static string SsqpUrl(SeededSymbols s) =>
        $"/nuget/symbols/{s.Id}.pdb/{s.SsqpKey}/{s.Id}.pdb";

    private async Task<HttpClient> ReadClientAsync() =>
        _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

    // Publishes a .nupkg plus a .snupkg carrying one real Portable PDB, so both symbol read
    // surfaces are reachable for the returned coordinate.
    private async Task<SeededSymbols> SeedSymbolPackageAsync()
    {
        string id = $"SymGate{Guid.NewGuid():N}"[..16];
        const string version = "1.0.0";
        var signature = Guid.NewGuid();
        byte[] pdb = NuGetFixtures.BuildPortablePdb(signature);
        byte[] snupkg = NuGetFixtures.BuildSnupkgWithPdbs(id, version, ($"{id}.pdb", pdb));

        await _factory.PushNuGetPackage(id, version);

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = new MultipartFormDataContent();
        var fc = new ByteArrayContent(snupkg);
        fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fc, "package", $"{id}.{version}.snupkg");
        var resp = await client.PutAsync("/nuget/symbols", content);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        return new SeededSymbols(id, version, await VersionIdAsync(id, version),
            NuGetSymbolKey.PortableKey(signature));
    }

    private async Task<string> VersionIdAsync(string id, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? versionId = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.purl_name = @purlName AND pv.version = @version LIMIT 1
            """,
            new { purlName = id.ToLowerInvariant(), version });
        Assert.NotNull(versionId);
        return versionId!;
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetManualBlockStateAsync(string versionId, string state)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET manual_block_state = @state WHERE id = @versionId",
            new { versionId, state });
    }

    private async Task MarkRevokedAsync(string versionId)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @versionId",
            new { versionId });
    }

    private async Task SetLicenseSpdxAsync(string versionId, string spdx)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses (id, package_version_id, owner_kind, license_spdx, source)
            VALUES (@id, @versionId, 'package_version', @spdx, 'upstream')
            """,
            new { id = Guid.NewGuid().ToString("N"), versionId, spdx });
    }

    private async Task AllowlistLicenseAsync(string spdx)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_allowlist (id, org_id, license_spdx) VALUES (@id, @orgId, @spdx)",
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx });
    }

    private async Task SeedMalAdvisoryAsync(SeededSymbols seeded)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

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
            new { vulnId, malId, pkgName = seeded.Id.ToLowerInvariant() });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind)
            VALUES (@id, @versionId, @vulnId, 'package_version')
            """,
            new { id = Guid.NewGuid().ToString("N"), versionId = seeded.VersionId, vulnId });
        // A stamped vuln_checked_at is what ENABLES the malicious arm — an unscanned row is
        // deferred, not blocked.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET vuln_checked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = @versionId",
            new { versionId = seeded.VersionId });
    }

    private async Task SetProxySettingAsync(string? blockMalicious = null, string? blockRevoked = null)
    {
        string jwt = await _factory.CreateAdminJwt();
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var put = await c.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = false,
            maxOsvScoreTolerance = 10.0,
            blockMalicious,
            blockRevoked,
        });
        put.EnsureSuccessStatusCode();
    }

    private async Task SetLicenseEnforcementModeAsync(string mode)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET license_enforcement_mode = @mode WHERE org_id = @orgId",
            new { orgId, mode });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }
}
