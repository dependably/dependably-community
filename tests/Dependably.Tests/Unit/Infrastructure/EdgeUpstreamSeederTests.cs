using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Seeding the edge node's single-upstream rows: the exact per-ecosystem set, idempotency across
/// re-runs, master URL/token change propagation, and encryption-at-rest of the reader token.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeUpstreamSeederTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public EdgeUpstreamSeederTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private async Task<string> NewOrgAsync() =>
        await OrgSeeder.InsertAsync(_fixture.Store, $"edge-{Guid.NewGuid():N}");

    [Fact]
    public async Task Seed_WritesOneRowPerEcosystemPlusOci_AllPointingAtMaster()
    {
        string org = await NewOrgAsync();
        var envelope = TestEnvelope.Configured();

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(
                conn, org, "https://master.example.com", "edge-tok", envelope);
        }

        await using var read = await _fixture.Store.OpenAsync();
        var rows = (await read.QueryAsync<(string Ecosystem, string Url, string AuthType)>(
            "SELECT ecosystem AS Ecosystem, url AS Url, auth_type AS AuthType FROM upstream_registry WHERE org_id = @org ORDER BY ecosystem",
            new { org })).ToList();

        var byEco = rows.ToDictionary(r => r.Ecosystem, r => r.Url);
        Assert.Equal("https://master.example.com", byEco["pypi"]);
        Assert.Equal("https://master.example.com/npm", byEco["npm"]);
        Assert.Equal("https://master.example.com/nuget", byEco["nuget"]);
        Assert.Equal("https://master.example.com/maven", byEco["maven"]);
        Assert.Equal("https://master.example.com/rpm", byEco["rpm"]);
        Assert.Equal("https://master.example.com/go", byEco["golang"]);
        Assert.Equal("https://master.example.com/cargo", byEco["cargo"]);
        Assert.Equal("https://master.example.com/apk", byEco["apk"]);
        Assert.Equal("master.example.com", byEco["oci"]);

        // Non-OCI ecosystems authenticate with Bearer; OCI uses Basic (user:token).
        Assert.Equal("bearer", rows.Single(r => r.Ecosystem == "npm").AuthType);
        Assert.Equal("basic", rows.Single(r => r.Ecosystem == "oci").AuthType);

        // No public-registry rows leaked in — the edge set replaces the standard defaults.
        Assert.DoesNotContain(rows, r => r.Url.Contains("registry.npmjs.org"));
        Assert.DoesNotContain(rows, r => r.Url.Contains("pypi.org"));
    }

    [Fact]
    public async Task Seed_TwiceWithSameMaster_IsIdempotent()
    {
        string org = await NewOrgAsync();
        var envelope = TestEnvelope.Configured();

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(conn, org, "https://m.example", "tok", envelope);
        }

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(conn, org, "https://m.example", "tok", envelope);
        }

        await using var read = await _fixture.Store.OpenAsync();
        int count = await read.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM upstream_registry WHERE org_id = @org", new { org });
        // 8 non-OCI ecosystems + 1 OCI row, no duplication after a second run.
        Assert.Equal(9, count);
    }

    [Fact]
    public async Task Seed_ChangedMasterUrl_UpdatesRowsAndLeavesNoStale()
    {
        string org = await NewOrgAsync();
        var envelope = TestEnvelope.Configured();

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(conn, org, "https://old.example", "tok", envelope);
        }

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(conn, org, "https://new.example", "tok", envelope);
        }

        await using var read = await _fixture.Store.OpenAsync();
        var urls = (await read.QueryAsync<string>(
            "SELECT url FROM upstream_registry WHERE org_id = @org", new { org })).ToList();

        Assert.All(urls, u => Assert.DoesNotContain("old.example", u));
        Assert.Contains("https://new.example/npm", urls);
        Assert.Equal(9, urls.Count);
    }

    [Fact]
    public async Task Seed_TokenEncryptedAtRest_NeverPlaintext()
    {
        string org = await NewOrgAsync();
        var envelope = TestEnvelope.Configured();

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(conn, org, "https://m.example", "s3cr3t-token", envelope);
        }

        await using var read = await _fixture.Store.OpenAsync();
        var secrets = (await read.QueryAsync<string?>(
            "SELECT secret FROM upstream_registry WHERE org_id = @org AND secret IS NOT NULL",
            new { org })).ToList();

        Assert.NotEmpty(secrets);
        foreach (string? s in secrets)
        {
            Assert.NotNull(s);
            Assert.StartsWith("enc:v1:", s);
            Assert.DoesNotContain("s3cr3t-token", s);
        }
    }

    [Fact]
    public async Task Seed_ResolvedSource_CarriesDecryptedAuthHeader()
    {
        string org = await NewOrgAsync();
        var envelope = TestEnvelope.Configured();

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(conn, org, "https://m.example", "edge-tok", envelope);
        }

        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, envelope);
        var npmSources = await repo.ListSourcesForEcosystemAsync(org, "npm");
        var source = Assert.Single(npmSources);
        Assert.Equal("https://m.example/npm", source.Url);
        Assert.Equal("Bearer edge-tok", source.AuthorizationHeader);
    }
}
