using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Go module versions are case-sensitive tags, so <c>v1.0.0-RC1</c> and <c>v1.0.0-rc1</c> are two
/// versions: neither shadows the other across the uploaded and proxied catalogues, and blocking one
/// never withholds the other from <c>@v/list</c> or <c>@latest</c>.
/// </summary>
[Trait("Category", "Integration")]
public sealed class GoVersionCaseTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Upper = "v1.0.0-RC1";
    private const string Lower = "v1.0.0-rc1";

    private readonly DependablyFactory _factory;

    public GoVersionCaseTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Store => _factory.Services.GetRequiredService<IMetadataStore>();

    private async Task<string> OrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        await using var conn = await Store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SeedUploadedAsync(string module, string version, string createdAt, bool blocked)
    {
        string orgId = await OrgIdAsync();
        string pkgId = await PackageSeeder.InsertAsync(Store, orgId, "golang", module);
        string verId = await PackageSeeder.InsertVersionAsync(
            Store, pkgId, version, $"pkg:golang/{module}@{version}", blobKey: $"hosted/{Guid.NewGuid():N}");
        await using var conn = await Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET created_at = @createdAt, manual_block_state = @state WHERE id = @verId",
            new { createdAt, state = blocked ? "blocked" : null, verId });
    }

    private async Task SeedProxiedAsync(string module, string version, string cachedAt, bool blocked)
    {
        string orgId = await OrgIdAsync();
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, first_cached_at)
            VALUES (@id, 'golang', @module, @version, @filename, @blobKey, 'cafeba', 1, @cachedAt)
            """,
            new { id, module, version, filename = $"{version}.zip", blobKey = $"proxy/sha256/{id}", cachedAt });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state) VALUES (@orgId, @id, @state)",
            new { orgId, id, state = blocked ? "blocked" : null });
    }

    private async Task<string> GetAsync(string path)
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return await resp.Content.ReadAsStringAsync();
    }

    [Fact]
    public async Task VersionList_ProxiedVersionDifferingOnlyInCase_IsListedBesideTheUploadedOne()
    {
        const string module = "example.com/gocase-list";
        await SeedUploadedAsync(module, Upper, "2026-06-01T00:00:00Z", blocked: false);
        await SeedProxiedAsync(module, Lower, "2026-06-01T01:00:00Z", blocked: false);

        string[] lines = (await GetAsync($"/go/{module}/@v/list")).Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.Contains(Upper, lines);
        Assert.Contains(Lower, lines);
    }

    [Fact]
    public async Task VersionList_BlockedVersion_DoesNotWithholdTheCaseDistinctOne()
    {
        const string module = "example.com/gocase-blocked";
        await SeedProxiedAsync(module, Upper, "2026-06-01T00:00:00Z", blocked: true);
        await SeedProxiedAsync(module, Lower, "2026-06-01T01:00:00Z", blocked: false);

        string[] lines = (await GetAsync($"/go/{module}/@v/list")).Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.DoesNotContain(Upper, lines);
        Assert.Contains(Lower, lines);
    }

    [Fact]
    public async Task Latest_NewestVersionBlocked_FallsBackToTheCaseDistinctVersion()
    {
        const string module = "example.com/gocase-latest";
        await SeedUploadedAsync(module, Upper, "2026-06-02T00:00:00Z", blocked: true);
        await SeedProxiedAsync(module, Lower, "2026-06-01T00:00:00Z", blocked: false);

        using var doc = JsonDocument.Parse(await GetAsync($"/go/{module}/@latest"));

        Assert.Equal(Lower, doc.RootElement.GetProperty("Version").GetString());
    }
}
