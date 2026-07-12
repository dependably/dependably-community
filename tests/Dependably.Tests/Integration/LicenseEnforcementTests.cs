using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Hard-block enforcement for the SPDX license policy on the serve/proxy path, governed by the
/// existing <c>org_settings.license_enforcement_mode</c> ('off'/'warn'/'block'). Only 'block'
/// engages the <see cref="Dependably.Protocol.BlockGateService"/> license arm; 'warn'/'off' keep
/// the license signal advisory and never deny a download.
///
/// Two gate construction paths are covered:
///   • FIRST-FETCH (PyPI, via <see cref="ProxyFetchService"/>): the block-gate request is built
///     field-by-field from <c>ProxyFetchRequest</c>, NOT via the factories — so a blocklisted
///     license must 403 on the FIRST download, before any cache-hit path exists. On the old code
///     (no LicenseEnforcementMode threaded through ProxyFetchRequest) that first fetch served 200.
///   • CACHE-HIT (Cargo, via <c>BlockGateRequest.ForProxyCacheFacts</c>): a seeded global-plane
///     artifact with a license row exercises the factory path, compound OR/AND semantics, and the
///     manual-allow override (which must win over the license arm).
///
/// Mixed-mode shape per house style: the same blocklisted artifact serves under 'warn'/'off' and
/// 403s under 'block'; a compound "MIT OR &lt;blocked&gt;" serves while "MIT AND &lt;blocked&gt;" 403s.
/// </summary>
[Trait("Category", "Integration")]
public sealed class LicenseEnforcementTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string AllowedLicense = "MIT";
    private const string BlockedLicense = "GPL-3.0-only";

    private readonly DependablyFactory _factory;

    public LicenseEnforcementTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── first-fetch (PyPI, direct-construction gate path — pins BLOCKER 1) ────

    [Fact]
    public async Task PyPiFirstFetch_BlocklistedLicense_UnderBlock_403OnFirstRequest()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        try
        {
            var (name, filename, resp) = await FirstFetchWheelAsync(BlockedLicense);
            // The FIRST download must be refused — not the second. This is the regression that
            // fails on the pre-fix code (LicenseEnforcementMode null on the direct path → 200).
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
            _ = (name, filename);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task PyPiFirstFetch_BlocklistedLicense_UnderWarn_Serves()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "warn");
        try
        {
            var (_, _, resp) = await FirstFetchWheelAsync(BlockedLicense);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task PyPiFirstFetch_BlocklistedLicense_UnderOff_Serves()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "off");
        try
        {
            var (_, _, resp) = await FirstFetchWheelAsync(BlockedLicense);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    // ── cache-hit (Cargo, factory gate path) ──────────────────────────────────

    [Fact]
    public async Task CargoCacheHit_AllowlistedLicense_UnderBlock_Serves()
    {
        string orgId = await ResetOrgAsync();
        await SeedAllowAsync(orgId, AllowedLicense);
        await SetLicenseModeAsync(orgId, "block");
        await SetAnonymousPullAsync(orgId, true);
        try
        {
            string name = CrateName();
            await SeedCargoCachedAsync(orgId, name, "1.0.0", AllowedLicense, manualState: null);
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/1.0.0/download");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task CargoCacheHit_CompoundOr_OneAllowed_UnderBlock_Serves()
    {
        string orgId = await ResetOrgAsync();
        await SeedAllowAsync(orgId, AllowedLicense);
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        await SetAnonymousPullAsync(orgId, true);
        try
        {
            string name = CrateName();
            // OR is satisfied by the allowlisted MIT even though the sibling is blocklisted.
            await SeedCargoCachedAsync(orgId, name, "1.0.0", $"{AllowedLicense} OR {BlockedLicense}", manualState: null);
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/1.0.0/download");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task CargoCacheHit_CompoundAnd_OneBlocked_UnderBlock_403()
    {
        string orgId = await ResetOrgAsync();
        await SeedAllowAsync(orgId, AllowedLicense);
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        await SetAnonymousPullAsync(orgId, true);
        try
        {
            string name = CrateName();
            // AND requires every leaf; the blocklisted GPL leaf sinks it.
            await SeedCargoCachedAsync(orgId, name, "1.0.0", $"{AllowedLicense} AND {BlockedLicense}", manualState: null);
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/1.0.0/download");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task CargoCacheHit_ManualAllowOverride_UnderBlock_Serves()
    {
        string orgId = await ResetOrgAsync();
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        await SetAnonymousPullAsync(orgId, true);
        try
        {
            string name = CrateName();
            // Operator override wins: a manually-allowed artifact serves even under a blocklisted
            // license — the license arm is skipped when ManualState == "allowed".
            await SeedCargoCachedAsync(orgId, name, "1.0.0", BlockedLicense, manualState: "allowed");
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/cargo/api/v1/crates/{name}/1.0.0/download");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    [Fact]
    public async Task CargoCacheHit_BlocklistedLicense_UnderBlock_403_CleanSibling_Serves()
    {
        string orgId = await ResetOrgAsync();
        await SeedAllowAsync(orgId, AllowedLicense);
        await SeedBlockAsync(orgId, BlockedLicense);
        await SetLicenseModeAsync(orgId, "block");
        await SetAnonymousPullAsync(orgId, true);
        try
        {
            string name = CrateName();
            // Mixed partial-failure shape: one blocklisted-license coordinate and one allowlisted
            // sibling in the same org — only the blocklisted one is denied.
            await SeedCargoCachedAsync(orgId, name, "1.0.0", BlockedLicense, manualState: null);
            await SeedCargoCachedAsync(orgId, name, "2.0.0", AllowedLicense, manualState: null);
            using var client = _factory.CreateClient();

            var blocked = await client.GetAsync($"/cargo/api/v1/crates/{name}/1.0.0/download");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/cargo/api/v1/crates/{name}/2.0.0/download");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await ResetOrgAsync();
        }
    }

    // ── first-fetch driver ────────────────────────────────────────────────────

    private async Task<(string Name, string Filename, HttpResponseMessage Resp)> FirstFetchWheelAsync(string license)
    {
        string name = $"lic-ff-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";
        var (wheelBytes, sha256Hex) = BuildWheelWithLicense(name, "1.0.0", license);

        StubWheelUpstream(name, filename, wheelBytes, sha256Hex);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        // Sanity: this is a genuine first fetch (cache MISS), so the direct-construction gate path
        // (not a cache-hit) produced the outcome under test.
        Assert.Equal("MISS", resp.Headers.GetValues("X-Cache").FirstOrDefault());
        return (name, filename, resp);
    }

    // Stubs the WireMock upstream to serve the wheel at the simple-index and file download paths;
    // the simple-index #sha256= fragment lets UpstreamClient verify inline.
    private void StubWheelUpstream(string name, string filename, byte[] wheelBytes, string sha256Hex)
    {
        string mockBase = _factory.MockUpstream.Urls[0];
        string simpleHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{mockBase}/files/{filename}#sha256={sha256Hex}">{filename}</a>
            </body></html>
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(simpleHtml));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(wheelBytes));
    }

    // Minimal valid .whl carrying a PEP 639 License-Expression in METADATA so the proxy licence
    // extractor persists it before the block gate runs on first fetch.
    private static (byte[] Bytes, string Sha256Hex) BuildWheelWithLicense(string name, string version, string license)
    {
        string normalized = name.ToLowerInvariant().Replace('-', '_').Replace('.', '_');
        string distInfoDir = $"{normalized}-{version}.dist-info";
        string metadata = $"""
            Metadata-Version: 2.4
            Name: {name}
            Version: {version}
            Summary: Synthetic licence-enforcement test package
            License-Expression: {license}
            """;
        string wheel = """
            Wheel-Version: 1.0
            Generator: dependably-test
            Root-Is-Purelib: true
            Tag: py3-none-any
            """;

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(zip, $"{distInfoDir}/METADATA", metadata);
            WriteEntry(zip, $"{distInfoDir}/WHEEL", wheel);
        }
        byte[] bytes = ms.ToArray();
        string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }

    private static void WriteEntry(ZipArchive zip, string entryName, string content)
    {
        var entry = zip.CreateEntry(entryName);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }

    // ── cache-hit seeding (cargo) ─────────────────────────────────────────────

    private static string CrateName() => $"lic{Guid.NewGuid():N}"[..15].ToLowerInvariant();

    private async Task SeedCargoCachedAsync(
        string orgId, string name, string version, string licenseExpr, string? manualState)
    {
        // Cargo serves the cache hit from BlobKeys.Cargo; StoreKey is identity for that key.
        string blobKey = BlobKeys.Cargo(orgId, name, version);
        byte[] bytes = Encoding.UTF8.GetBytes($"crate-{name}-{version}");
        await _factory.BlobStore.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(bytes));
        await InsertGlobalPlaneWithLicenseAsync(
            orgId, "cargo", name, version, $"{name}-{version}.crate", blobKey, bytes, licenseExpr, manualState);
    }

    // Inserts a cache_artifact row, its per-tenant tenant_artifact_access row (optionally pre-set
    // to a manual_block_state), and a cache_artifact-owned license row carrying the raw expression.
    private async Task InsertGlobalPlaneWithLicenseAsync(
        string orgId, string ecosystem, string name, string version, string filename,
        string blobKey, byte[] bytes, string licenseExpr, string? manualState)
    {
        string contentHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string caId = Guid.NewGuid().ToString("N");
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES
                (@caId, @ecosystem, @name, @version, @filename, @blobKey, @contentHash, @size, @purl)
            """,
            new
            {
                caId,
                ecosystem,
                name,
                version,
                filename,
                blobKey,
                contentHash,
                size = bytes.Length,
                purl = $"pkg:{ecosystem}/{name}@{version}",
            });
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state)
            VALUES (@orgId, @caId, @state)
            """,
            new { orgId, caId, state = manualState });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses
                (id, cache_artifact_id, owner_kind, license_spdx, source)
            VALUES (@id, @caId, 'cache_artifact', @spdx, 'upstream')
            """,
            new { id = Guid.NewGuid().ToString("N"), caId, spdx = licenseExpr });
    }

    // ── org / policy helpers ──────────────────────────────────────────────────

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    // Restores the org to a clean baseline (mode off, anonymous pull off, empty allow/block lists)
    // so tests are order-independent within the shared fixture. Returns the default org id.
    private async Task<string> ResetOrgAsync()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET license_enforcement_mode = 'off', anonymous_pull = 0 WHERE org_id = @orgId",
            new { orgId });
        await conn.ExecuteAsync("DELETE FROM license_allowlist WHERE org_id = @orgId", new { orgId });
        await conn.ExecuteAsync("DELETE FROM license_blocklist WHERE org_id = @orgId", new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        return orgId;
    }

    private async Task SetLicenseModeAsync(string orgId, string mode)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET license_enforcement_mode = @mode WHERE org_id = @orgId",
            new { mode, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetAnonymousPullAsync(string orgId, bool enabled)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SeedAllowAsync(string orgId, string licenseSpdx)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_allowlist (id, org_id, license_spdx) VALUES (@id, @orgId, @spdx)",
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx = licenseSpdx });
    }

    private async Task SeedBlockAsync(string orgId, string licenseSpdx)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO license_blocklist (id, org_id, license_spdx) VALUES (@id, @orgId, @spdx)",
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx = licenseSpdx });
    }
}
