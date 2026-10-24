using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The OCI pull gate across real tenants in <c>DEPLOYMENT_MODE=multi</c> pulling one proxied image,
/// which lives once on the shared cache plane: each org's verdict comes from its own scan result
/// only. One org's KEV finding does not refuse another, and one org's clean result does not admit
/// a third org's unscanned pull.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanPullGateMultiTenantTests : IAsyncLifetime
{
    private const string Repo = "library/shared-gated";

    private readonly FakeOciRegistry _upstream = new(Repo);
    private readonly DependablyMultiFactory _factory;

    public OciScanPullGateMultiTenantTests()
    {
        _factory = new DependablyMultiFactory
        {
            Settings = new Dictionary<string, string> { ["OCI_SCAN_ENABLED"] = "true" },
            OciUpstreamHandler = _upstream.Respond,
        };
    }

    public async Task InitializeAsync() => await ((IAsyncLifetime)_factory).InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task EachOrg_GetsAVerdictFromItsOwnScanResultOnly()
    {
        var image = _upstream.AddImage("shared");
        string kevSlug = "kev-" + Guid.NewGuid().ToString("N")[..8];
        string cleanSlug = "cln-" + Guid.NewGuid().ToString("N")[..8];
        string noneSlug = "non-" + Guid.NewGuid().ToString("N")[..8];
        using (var sys = await _factory.CreateSystemAdminClient())
        {
            foreach (string slug in new[] { kevSlug, cleanSlug, noneSlug })
            {
                using var resp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new { slug, ownerEmail = $"{slug}@example.com" });
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            }
        }

        var (kevOrg, kev) = await TenantAsync(kevSlug);
        var (cleanOrg, clean) = await TenantAsync(cleanSlug);
        var (_, none) = await TenantAsync(noneSlug);
        using var kevClient = kev;
        using var cleanClient = clean;
        using var noneClient = none;

        string path = $"/v2/{Repo}/manifests/{image.Digest}";

        // Every org's first pull is refused (unscanned) but caches and catalogues the image on the
        // one shared cache-plane row.
        foreach (var client in new[] { kevClient, cleanClient, noneClient })
        {
            using var first = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Forbidden, first.StatusCode);
        }

        var db = Store();
        string shared;
        await using (var conn = await db.OpenAsync())
        {
            // xtenant: the harness reads the one shared cache-plane row every org's access points at.
            shared = await conn.QuerySingleAsync<string>(
                "SELECT id FROM cache_artifact WHERE ecosystem = 'oci' AND name = @repo AND version = @digest",
                new { repo = Repo, digest = image.Digest });
        }

        await OciScanSeeder.ResultAsync(db, kevOrg, OciScanOwner.Proxied(shared), "linux/amd64", [],
            [new SeedComponent("openssl", 0, [new SeedFinding("DSA-BOLA-KEV")])]);
        await OciScanSeeder.ResultAsync(db, cleanOrg, OciScanOwner.Proxied(shared), "linux/amd64", [],
            [new SeedComponent("zlib", 0, [])]);
        await using (var conn = await db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE vulnerabilities SET is_kev = 1 WHERE osv_id = 'DSA-BOLA-KEV'");
        }

        // The KEV org is refused for its own finding.
        using (var refused = await kevClient.GetAsync(path))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("kev", refused.Headers.GetValues("X-Dependably-Block-Reason").Single());
        }

        // The clean org is served: the KEV org's finding is not its verdict.
        using (var served = await cleanClient.GetAsync(path))
        {
            Assert.Equal(HttpStatusCode.OK, served.StatusCode);
            Assert.Equal(image.Manifest, await served.Content.ReadAsByteArrayAsync());
        }

        // The org with no result stays unscanned: the clean org's result does not admit it.
        using var unscanned = await noneClient.GetAsync(path);
        Assert.Equal(HttpStatusCode.Forbidden, unscanned.StatusCode);
        Assert.Equal("unscanned", unscanned.Headers.GetValues("X-Dependably-Block-Reason").Single());
    }

    // Reaching into the host's services as the test harness, so seeding runs as the owner under
    // row-level security rather than as an undeclared background tenant.
    private IMetadataStore Store()
    {
        TestHarnessDbScope.Enter();
        return _factory.Services.GetRequiredService<IMetadataStore>();
    }

    // The tenant's org id and a pull client on its subdomain. Its OCI posture is set to block,
    // with block_kev at block, before the first pull reads (and caches) its settings.
    private async Task<(string OrgId, HttpClient Client)> TenantAsync(string slug)
    {
        TestHarnessDbScope.Enter();
        var org = await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync(slug)
            ?? throw new InvalidOperationException($"Org '{slug}' not found.");
        await using (var conn = await Store().OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO org_settings (org_id, oci_scan_enforcement, block_kev) VALUES (@orgId, 'block', 'block')
                ON CONFLICT (org_id) DO UPDATE SET oci_scan_enforcement = 'block', block_kev = 'block'
                """,
                new { orgId = org.Id });
        }

        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(org.Id);
        var (raw, _) = await _factory.Services.GetRequiredService<TokenRepository>().CreateServiceTokenAsync(
            org.Id, $"pull-{Guid.NewGuid():N}"[..20], """["read:artifact"]""", expiresAt: null);
        var client = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        return (org.Id, client);
    }
}
