using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Cargo versions are exact strings, so a proxied <c>1.0.0-rc1</c> is not shadowed by an uploaded
/// <c>1.0.0-RC1</c>, and a block on one never withholds the other, when <c>cargo search</c> resolves
/// <c>max_version</c> across both catalogues.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CargoVersionCaseTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public CargoVersionCaseTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Search_MaxVersion_KeepsAProxiedVersionDifferingOnlyInCaseFromABlockedUploadedOne()
    {
        const string name = "cargo-case-search";
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        _factory.CreateClient().Dispose();
        await using var conn = await store.OpenAsync();
        string orgId = (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;

        string pkgId = await PackageSeeder.InsertAsync(store, orgId, "cargo", name);
        string verId = await PackageSeeder.InsertVersionAsync(
            store, pkgId, "1.0.0-RC1", $"pkg:cargo/{name}@1.0.0-RC1", blobKey: $"hosted/{Guid.NewGuid():N}");
        await conn.ExecuteAsync(
            "UPDATE package_versions SET manual_block_state = 'blocked' WHERE id = @verId", new { verId });

        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
            VALUES (@id, 'cargo', @name, '1.0.0-rc1', 'case-1.0.0-rc1.crate', @blobKey, 'cafeba', 1)
            """,
            new { id, name, blobKey = $"proxy/sha256/{id}" });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @id)",
            new { orgId, id });

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        string body = await (await client.GetAsync($"/cargo/api/v1/crates?q={name}")).Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(body);
        var crate = doc.RootElement.GetProperty("crates").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);
        // The uploaded 1.0.0-RC1 is blocked; the proxied 1.0.0-rc1 is a different version and stays.
        Assert.Equal("1.0.0-rc1", crate.GetProperty("max_version").GetString());
    }

    [Fact]
    public async Task Search_MaxVersion_ProxyOnlyCasePair_KeepsTheCleanVersionWhenTheNewerOneIsBlocked()
    {
        const string name = "cargo-case-proxyonly";
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        _factory.CreateClient().Dispose();
        await using var conn = await store.OpenAsync();
        string orgId = (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
        await PackageSeeder.InsertAsync(store, orgId, "cargo", name, isProxy: true);

        // 1.0.0-RC1 is cached later, so a case-folding group-by over the newest-first rows keeps it
        // and drops 1.0.0-rc1 with it.
        await SeedProxiedAsync(conn, orgId, name, "1.0.0-rc1", "2026-06-01T00:00:00Z", blocked: false);
        await SeedProxiedAsync(conn, orgId, name, "1.0.0-RC1", "2026-06-01T01:00:00Z", blocked: true);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        string body = await (await client.GetAsync($"/cargo/api/v1/crates?q={name}")).Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(body);
        var crate = doc.RootElement.GetProperty("crates").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name);
        Assert.Equal("1.0.0-rc1", crate.GetProperty("max_version").GetString());
    }

    private static async Task SeedProxiedAsync(
        System.Data.Common.DbConnection conn, string orgId, string name, string version, string cachedAt, bool blocked)
    {
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, first_cached_at)
            VALUES (@id, 'cargo', @name, @version, @filename, @blobKey, 'cafeba', 1, @cachedAt)
            """,
            new { id, name, version, filename = $"{name}-{version}.crate", blobKey = $"proxy/sha256/{id}", cachedAt });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state) VALUES (@orgId, @id, @state)",
            new { orgId, id, state = blocked ? "blocked" : null });
    }
}
