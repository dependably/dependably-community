using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The OCI scan-detail read across two real tenants in <c>DEPLOYMENT_MODE=multi</c>, each routed
/// by its own subdomain: neither reads the other's hosted image, nor a proxied manifest only the
/// other pulled, and on a manifest both pulled each reads its own result and never the other's.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanDetailMultiTenantTests : IAsyncLifetime
{
    private const string Digest = "sha256:abababababababababababababababababababababababababababababababab";
    private const string SharedDigest = "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    private readonly DependablyMultiFactory _factory = new()
    {
        Settings = new Dictionary<string, string> { ["OCI_SCAN_ENABLED"] = "true" },
    };

    public async Task InitializeAsync() => await ((IAsyncLifetime)_factory).InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task EachTenant_ReadsOnlyItsOwnImagesAndResults()
    {
        string slugA = "sda-" + Guid.NewGuid().ToString("N")[..8];
        string slugB = "sdb-" + Guid.NewGuid().ToString("N")[..8];
        using (var sys = await _factory.CreateSystemAdminClient())
        {
            await CreateTenantAsync(sys, slugA);
            await CreateTenantAsync(sys, slugB);
        }

        var (orgA, clientA) = await TenantAsync(slugA);
        var (orgB, clientB) = await TenantAsync(slugB);
        using var a = clientA;
        using var b = clientB;

        var db = Store();
        var hostedA = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(db, orgA, "team/app", Digest));
        await OciScanSeeder.ResultAsync(db, orgA, hostedA, "linux/amd64", [], [new SeedComponent("a-hosted", 0, [new SeedFinding("DSA-MA-1")])]);
        var shared = OciScanOwner.Proxied(await OciScanSeeder.ProxiedManifestAsync(db, "library/shared", SharedDigest));
        await OciScanSeeder.GrantAsync(db, orgA, shared.Id);
        await OciScanSeeder.ResultAsync(db, orgA, shared, "linux/amd64", ["a-gap"], [new SeedComponent("a-proxied", 0, [new SeedFinding("DSA-MA-2")])]);

        string hostedPath = $"/api/v1/packages/oci/team%2Fapp/{Digest}/scan";
        string sharedPath = $"/api/v1/packages/oci/library%2Fshared/{SharedDigest}/scan?affectedOnly=false";

        // Positive controls: A reads both of its images. A failure here is a mis-provisioned
        // fixture, not a pass for the denials below.
        Assert.Equal(["a-hosted"], await ComponentNamesAsync(a, hostedPath));
        Assert.Equal(["a-proxied"], await ComponentNamesAsync(a, sharedPath));

        // B: A's hosted image, and a manifest only A pulled, are both the same 404.
        using (var hosted = await b.GetAsync(hostedPath))
        {
            Assert.Equal(HttpStatusCode.NotFound, hosted.StatusCode);
        }

        using (var notPulled = await b.GetAsync(sharedPath))
        {
            Assert.Equal(HttpStatusCode.NotFound, notPulled.StatusCode);
        }

        // Twin: B pulls the same manifest and has its own result. Each sees only its own.
        db = Store();
        await OciScanSeeder.GrantAsync(db, orgB, shared.Id);
        await OciScanSeeder.ResultAsync(db, orgB, shared, "linux/amd64", [], [new SeedComponent("b-proxied", 0, [new SeedFinding("DSA-MB-1")])]);

        using (var mine = await b.GetAsync(sharedPath))
        {
            Assert.Equal(HttpStatusCode.OK, mine.StatusCode);
            string body = await mine.Content.ReadAsStringAsync();
            Assert.DoesNotContain("a-proxied", body);
            Assert.DoesNotContain("a-gap", body);
            Assert.DoesNotContain("DSA-MA", body);
        }

        Assert.Equal(["b-proxied"], await ComponentNamesAsync(b, sharedPath));
        Assert.Equal(["a-proxied"], await ComponentNamesAsync(a, sharedPath));
    }

    // Reaching into the host's services as the test harness, so seeding runs as the owner under
    // row-level security rather than as an undeclared background tenant.
    private IMetadataStore Store()
    {
        TestHarnessDbScope.Enter();
        return _factory.Services.GetRequiredService<IMetadataStore>();
    }

    private static async Task<IReadOnlyList<string?>> ComponentNamesAsync(HttpClient client, string path)
    {
        using var response = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("components").GetProperty("items").EnumerateArray()
            .Select(i => i.GetProperty("name").GetString()).ToList();
    }

    private static async Task CreateTenantAsync(HttpClient sys, string slug)
    {
        using var resp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new { slug, ownerEmail = $"{slug}@example.com" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private async Task<(string OrgId, HttpClient Client)> TenantAsync(string slug)
    {
        TestHarnessDbScope.Enter();
        var org = await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync(slug)
            ?? throw new InvalidOperationException($"Org '{slug}' not found.");
        var (raw, _) = await _factory.Services.GetRequiredService<TokenRepository>().CreateServiceTokenAsync(
            org.Id, $"scan-read-{Guid.NewGuid():N}"[..20], """["read:packages"]""", expiresAt: null);
        var client = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        return (org.Id, client);
    }
}
