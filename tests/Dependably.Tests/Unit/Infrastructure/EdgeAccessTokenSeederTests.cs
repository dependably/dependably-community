using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Seeding the edge node's inbound client-auth state from <c>EDGE_ACCESS_TOKEN</c>: a reader
/// service token row (SHA-256 hash, reader caps) when the token is set with anonymous_pull OFF,
/// anonymous_pull ON with no row when absent, and deterministic rotation (old row gone, new hash
/// works) across re-seeds. Mirrors the upstream reseed's idempotency contract.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeAccessTokenSeederTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public EdgeAccessTokenSeederTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private async Task<string> NewOrgAsync() =>
        await OrgSeeder.InsertAsync(_fixture.Store, $"edge-{Guid.NewGuid():N}");

    private async Task<(int Count, string? Hash, string? Caps, int AnonPull)> ReadStateAsync(string org)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM service_tokens WHERE org_id = @org AND description = @desc",
            new { org, desc = EdgeAccessTokenSeeder.TokenDescription });
        var (Hash, Caps) = await conn.QuerySingleOrDefaultAsync<(string? Hash, string? Caps)>(
            "SELECT token_hash AS Hash, capabilities AS Caps FROM service_tokens WHERE org_id = @org AND description = @desc",
            new { org, desc = EdgeAccessTokenSeeder.TokenDescription });
        int anon = await conn.ExecuteScalarAsync<int>(
            "SELECT anonymous_pull FROM org_settings WHERE org_id = @org", new { org });
        return (count, Hash, Caps, anon);
    }

    [Fact]
    public async Task Token_Set_SeedsReaderServiceToken_AnonymousPullOff()
    {
        string org = await NewOrgAsync();

        EdgeAccessTokenSeeder.SeedOutcome outcome;
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            outcome = await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, "shared-edge-token");
        }

        Assert.Equal(EdgeAccessTokenSeeder.SeedOutcome.Tokened, outcome);

        var (Count, Hash, Caps, AnonPull) = await ReadStateAsync(org);
        Assert.Equal(1, Count);
        Assert.Equal(TokenRepository.HashToken("shared-edge-token"), Hash);
        Assert.Equal(Capabilities.ReaderCapsCanonicalJson, Caps);
        Assert.Equal(0, AnonPull);

        // The seeded token resolves through the normal auth machinery with reader caps.
        var tokens = new TokenRepository(_fixture.Store, TimeProvider.System);
        var record = await tokens.ResolveAsync("shared-edge-token");
        Assert.NotNull(record);
        Assert.True(record!.HasCapability(Capabilities.ReadArtifact));
        Assert.True(record.HasCapability(Capabilities.ReadMetadata));
        Assert.False(record.HasCapability(Capabilities.PublishNpm));
    }

    [Fact]
    public async Task Token_Absent_EnablesAnonymousPull_NoTokenRow()
    {
        string org = await NewOrgAsync();

        EdgeAccessTokenSeeder.SeedOutcome outcome;
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            outcome = await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, accessToken: null);
        }

        Assert.Equal(EdgeAccessTokenSeeder.SeedOutcome.Anonymous, outcome);
        var (Count, _, _, AnonPull) = await ReadStateAsync(org);
        Assert.Equal(0, Count);
        Assert.Equal(1, AnonPull);
    }

    [Fact]
    public async Task WhitespaceToken_IsTreatedAsAnonymous()
    {
        string org = await NewOrgAsync();

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            var outcome = await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, "   ");
            Assert.Equal(EdgeAccessTokenSeeder.SeedOutcome.Anonymous, outcome);
        }

        var (Count, _, _, AnonPull) = await ReadStateAsync(org);
        Assert.Equal(0, Count);
        Assert.Equal(1, AnonPull);
    }

    [Fact]
    public async Task ReSeed_SameToken_IsIdempotent_OneRow()
    {
        string org = await NewOrgAsync();

        for (int i = 0; i < 2; i++)
        {
            await using var conn = await _fixture.Store.OpenAsync();
            await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, "steady-token");
        }

        var (Count, Hash, _, _) = await ReadStateAsync(org);
        Assert.Equal(1, Count);
        Assert.Equal(TokenRepository.HashToken("steady-token"), Hash);
    }

    [Fact]
    public async Task Rotation_ReplacesRow_OldTokenStopsWorking_NewTokenWorks()
    {
        string org = await NewOrgAsync();
        var tokens = new TokenRepository(_fixture.Store, TimeProvider.System);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, "old-token");
        }
        Assert.NotNull(await tokens.ResolveAsync("old-token"));

        // Rotate: re-seed with a new token value.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, "new-token");
        }

        var (Count, _, _, _) = await ReadStateAsync(org);
        Assert.Equal(1, Count);
        Assert.Null(await tokens.ResolveAsync("old-token"));
        Assert.NotNull(await tokens.ResolveAsync("new-token"));
    }

    [Fact]
    public async Task TokenThenAnonymous_RemovesRow_EnablesAnonymousPull()
    {
        string org = await NewOrgAsync();
        var tokens = new TokenRepository(_fixture.Store, TimeProvider.System);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, "some-token");
        }

        // Operator unsets EDGE_ACCESS_TOKEN — the reseed drops the row and opens anonymous pull.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            var outcome = await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, org, accessToken: null);
            Assert.Equal(EdgeAccessTokenSeeder.SeedOutcome.Anonymous, outcome);
        }

        var (Count, _, _, AnonPull) = await ReadStateAsync(org);
        Assert.Equal(0, Count);
        Assert.Equal(1, AnonPull);
        Assert.Null(await tokens.ResolveAsync("some-token"));
    }
}
