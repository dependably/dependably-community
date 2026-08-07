using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for the reserved-namespace vocabulary gap: <c>terraform</c> was absent
/// from <see cref="Dependably.Protocol.ReservedNamespaceService.SupportedEcosystems"/>, so
/// <c>OrgListsController</c> rejected every attempt to reserve a Terraform provider source
/// address and the dependency-confusion guard already present in
/// <c>TerraformController.ServeArchiveAsync</c> was unreachable dead code — no
/// <c>reserved_namespace</c> row with <c>ecosystem='terraform'</c> could ever exist.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TerraformReservedNamespaceTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public TerraformReservedNamespaceTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    /// <summary>
    /// Replaces whatever terraform upstream the org has (the seeded public registry row, by
    /// default) with a single mirror-protocol row pointed at the WireMock upstream, so
    /// resolution is deterministic and every fetch this test triggers is observable.
    /// </summary>
    private async Task SeedMirrorUpstreamAsync(string orgId)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'terraform'",
            new { orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, upstream_protocol)
            VALUES (@id, @orgId, 'terraform', @url, 0, 'mirror')
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, url = _factory.MockUpstream.Urls[0] });
    }

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task ReservedNamespaces_AcceptsTerraform()
    {
        // The write path (OrgListsController.AddReservedNamespace) gated on
        // ReservedNamespaceService.SupportedEcosystems, which omitted terraform — this 422'd
        // before the fix.
        using var admin = await AdminClient();
        var resp = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "terraform", pattern = $"tf{Guid.NewGuid():N}.example.com/acme/*" });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    [Fact]
    public async Task ReservedTerraformProvider_NeverConsultsUpstream_UnreservedProviderDoes()
    {
        string orgId = await DefaultOrgIdAsync();
        await SeedMirrorUpstreamAsync(orgId);

        string hostname = $"tf{Guid.NewGuid():N}"[..12].ToLowerInvariant() + ".example.com";
        string reservedNamespace = "acme";
        string openNamespace = "other";
        string type = "provider";

        using var admin = await AdminClient();
        var add = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "terraform", pattern = $"{hostname}/{reservedNamespace}/*" });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Reserved: the guard in ServeArchiveAsync must short-circuit before any upstream call —
        // same silent-404 semantics as local_only, never a leak of the private provider's name.
        string reservedPath = $"/terraform/{hostname}/{reservedNamespace}/{type}/1.0.0/linux_amd64.zip";
        var reservedResp = await client.GetAsync(reservedPath);
        Assert.Equal(HttpStatusCode.NotFound, reservedResp.StatusCode);
        Assert.DoesNotContain(_factory.MockUpstream.LogEntries,
            e => e.RequestMessage?.Path?.Contains(hostname, StringComparison.Ordinal) == true);

        // Control: a name under the same host but outside the reserved pattern (a different
        // namespace) is not local_only, so the mirror upstream must be consulted — and 404s
        // here only because the version document is unstubbed, not because the guard fired.
        string openPath = $"/terraform/{hostname}/{openNamespace}/{type}/1.0.0/linux_amd64.zip";
        var openResp = await client.GetAsync(openPath);
        Assert.Equal(HttpStatusCode.NotFound, openResp.StatusCode);
        Assert.Contains(_factory.MockUpstream.LogEntries,
            e => e.RequestMessage?.Path?.Contains(hostname, StringComparison.Ordinal) == true);
    }
}
