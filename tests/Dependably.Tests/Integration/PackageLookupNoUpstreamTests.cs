using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>GET /api/v1/lookup</c> for an ecosystem the org has no upstream configured for. Its own host
/// rather than the shared fixture: the empty <c>Hex:Upstream</c> setting stops first boot seeding
/// a hex upstream at all, so the test needs no change to an org another test class reads.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PackageLookupNoUpstreamTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        ExtraSettings = new Dictionary<string, string?> { ["Hex:Upstream"] = "" },
    };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // An ecosystem with no upstream configured is the operator's off switch for proxying it, so
    // a version-less lookup there is a 422 with its own reason, not an outage.
    [Fact]
    public async Task NoUpstreamConfigured_NoVersion_Returns422UpstreamNotConfigured_Not503()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            long hexUpstreams = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM upstream_registry r JOIN orgs o ON o.id = r.org_id
                WHERE o.slug = 'default' AND r.ecosystem = 'hex'
                """);
            Assert.Equal(0, hexUpstreams);
        }

        string userId = await _factory.CreateUser($"lookup-{Guid.NewGuid():N}@example.com", "Password12345");
        using var client = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(userId, "member"));

        var resp = await client.GetAsync("/api/v1/lookup?ecosystem=hex&name=some_package");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        var problem = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("version", problem.GetProperty("field").GetString());
        Assert.Equal("upstream_not_configured", problem.GetProperty("reason").GetString());
        Assert.Contains("No upstream registry is configured for 'hex'",
            problem.GetProperty("detail").GetString(), StringComparison.Ordinal);
    }
}
