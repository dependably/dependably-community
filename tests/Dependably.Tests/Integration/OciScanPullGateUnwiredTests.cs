using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// An OCI pull gate with no scan resolver wired must not degrade to the licence-only answer while
/// the org's posture asks for scan enforcement: a gate input that cannot be read is never "nothing
/// to block on". Under block the pull is refused as unscanned; under warn it is served.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciScanPullGateUnwiredTests : IAsyncLifetime
{
    private const string Repo = "library/unwired-app";

    private readonly FakeOciRegistry _upstream = new(Repo);
    private DependablyFactory _factory = null!;

    public async Task InitializeAsync()
    {
        _factory = new DependablyFactory
        {
            OciUpstreamHandler = _upstream.Respond,
            ExtraSettings = new Dictionary<string, string?> { ["OCI_SCAN_ENABLED"] = "true" },
            ServiceOverrides = services => services.AddScoped(sp =>
                ActivatorUtilities.CreateInstance<OciControllerServices>(sp) with { PullGate = null }),
        };
        await _factory.InitializeAsync();
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // Moving off 'off' needs a scanner that has called at least once; a stale one keeps the org
    // without a live scanner.
    private async Task SetPostureAsync(string posture)
    {
        TestHarnessDbScope.Enter();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'")
                ?? throw new InvalidOperationException("no org");
        }

        await OciScanSeeder.StaleScannerAsync(store, orgId, _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow());

        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var put = await admin.PutAsJsonAsync("/api/v1/proxy-settings", new { ociScanEnforcement = posture });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);
    }

    [Theory]
    [InlineData("block", HttpStatusCode.Forbidden)]
    [InlineData("warn", HttpStatusCode.OK)]
    public async Task AMissingResolver_FailsClosedUnderBlock_AndServesUnderWarn(string posture, HttpStatusCode expected)
    {
        var image = _upstream.AddImage("unwired");
        _upstream.Tag("v1", image.Digest);
        await SetPostureAsync(posture);

        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        using var response = await client.GetAsync($"/v2/{Repo}/manifests/v1");

        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.Forbidden)
        {
            Assert.Equal("unscanned", response.Headers.GetValues("X-Dependably-Block-Reason").Single());
            // The null-resolver refusal's own wording: the real gate refuses an unscanned image
            // with "queued for scanning", so a silently ignored PullGate override cannot pass here.
            string body = await response.Content.ReadAsStringAsync();
            Assert.Contains("its scan result could not be read", body, StringComparison.Ordinal);
            Assert.DoesNotContain("queued for scanning", body, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("block")]
    [InlineData("warn")]
    public async Task AMissingResolver_StillStatesThePostureForAnEdge(string posture)
    {
        var image = _upstream.AddImage($"unwired-header-{posture}");
        _upstream.Tag("v1", image.Digest);
        await SetPostureAsync(posture);

        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        using var response = await client.GetAsync($"/v2/{Repo}/manifests/v1");

        Assert.Equal(posture, response.Headers.GetValues("X-Dependably-Oci-Scan-Enforcement").Single());
    }
}
