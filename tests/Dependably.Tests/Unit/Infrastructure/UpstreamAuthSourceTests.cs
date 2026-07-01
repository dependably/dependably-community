using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Per-upstream auth: the header-builder matrix and the resolver bridge
/// (<see cref="UpstreamRegistryRepository.ListSourcesForEcosystemAsync"/>), including secret-at-rest
/// encryption round-trip and legacy-plaintext pass-through.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamAuthSourceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public UpstreamAuthSourceTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Theory]
    [InlineData("bearer", null, "tok", "Bearer tok")]
    [InlineData("anonymous", null, null, null)]
    [InlineData(null, null, null, null)]
    [InlineData("unknown-scheme", "u", "p", null)]
    [InlineData("bearer", null, null, null)] // bearer with no secret degrades to anonymous
    public void BuildUpstreamAuthHeader_Matrix(string? authType, string? username, string? secret, string? expected)
    {
        Assert.Equal(expected, UpstreamRegistryRepository.BuildUpstreamAuthHeader(authType, username, secret));
    }

    [Fact]
    public void BuildUpstreamAuthHeader_Basic_IsBase64UserColonSecret()
    {
        string? header = UpstreamRegistryRepository.BuildUpstreamAuthHeader("basic", "robot", "s3cr3t");
        string expected = "Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("robot:s3cr3t"));
        Assert.Equal(expected, header);
    }

    [Fact]
    public async Task ListSources_BearerSecret_RoundTripsThroughEncryption()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, TestEnvelope.Configured());

        await repo.AddAsync(org, new NewUpstreamRegistry("npm", "https://cache.example/npm", "cache", AuthType: "bearer", Secret: "tok-abc"));

        var sources = await repo.ListSourcesForEcosystemAsync(org, "npm");
        var source = Assert.Single(sources);
        Assert.Equal("https://cache.example/npm", source.Url);
        Assert.Equal("Bearer tok-abc", source.AuthorizationHeader);
    }

    [Fact]
    public async Task AddAsync_BearerSecret_PersistsEncryptedAtRest()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, TestEnvelope.Configured());

        await repo.AddAsync(org, new NewUpstreamRegistry("npm", "https://cache.example/npm", null, AuthType: "bearer", Secret: "tok-abc"));

        await using var conn = await _fixture.Store.OpenAsync();
        string? stored = await conn.QuerySingleAsync<string?>(
            "SELECT secret FROM upstream_registry WHERE org_id = @org AND ecosystem = 'npm'",
            new { org });
        Assert.NotNull(stored);
        Assert.StartsWith("enc:v1:", stored);          // encrypted, never plaintext
        Assert.DoesNotContain("tok-abc", stored);
    }

    [Fact]
    public async Task ListSources_LegacyPlaintextSecret_PassesThrough()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        // Simulate a pre-encryption row: plaintext secret, no enc:v1: prefix.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, secret)
                VALUES (@id, @org, 'npm', 'https://legacy.example/npm', 0, 'bearer', 'legacy-plain')
                """,
                new { id = Guid.NewGuid().ToString("N"), org });
        }

        // An unconfigured protector still reads legacy plaintext (pass-through on the enc:v1: discriminator).
        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, TestEnvelope.Unconfigured());
        var source = Assert.Single(await repo.ListSourcesForEcosystemAsync(org, "npm"));
        Assert.Equal("Bearer legacy-plain", source.AuthorizationHeader);
    }

    [Fact]
    public async Task ListSources_Anonymous_HasNullHeader()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, TestEnvelope.Unconfigured());
        await repo.AddAsync(org, new NewUpstreamRegistry("npm", "https://registry.npmjs.org"));

        var source = Assert.Single(await repo.ListSourcesForEcosystemAsync(org, "npm"));
        Assert.Null(source.AuthorizationHeader);
    }
}
