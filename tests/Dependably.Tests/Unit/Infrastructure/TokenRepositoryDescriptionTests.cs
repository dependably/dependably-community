using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers the description + last_used_at additions to the user_tokens / service_tokens tables:
/// round-trip persistence of the optional description, the in-SQL throttle on TouchLastUsedAsync,
/// and that the touch dispatches to the correct table per <see cref="TokenSource"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TokenRepositoryDescriptionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private TokenRepository _tokens = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _tokens = new TokenRepository(_db);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES
                ('u1','o1','u1@example.com','','admin')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task UserToken_RoundTripsDescription()
    {
        var (_, rec) = await _tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null, description: "laptop");

        Assert.Equal("laptop", rec.Description);
        var fetched = await _tokens.GetTokenByIdAsync(rec.Id, rec.OrgId);
        Assert.Equal("laptop", fetched!.Description);
        var list = await _tokens.ListUserTokensAsync("o1", "u1");
        Assert.Equal("laptop", list.Single().Description);
    }

    [Fact]
    public async Task UserToken_DescriptionOptional()
    {
        var (_, rec) = await _tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null);
        Assert.Null(rec.Description);
        var fetched = await _tokens.GetTokenByIdAsync(rec.Id, rec.OrgId);
        Assert.Null(fetched!.Description);
    }

    [Fact]
    public async Task ServiceToken_RoundTripsDescription()
    {
        var (_, rec) = await _tokens.CreateServiceTokenAsync(
            "o1", "ci", "[\"read:metadata\"]", expiresAt: null, description: "ci-runner-1");

        Assert.Equal("ci-runner-1", rec.Description);
        var list = await _tokens.ListServiceTokensAsync("o1");
        Assert.Equal("ci-runner-1", list.Single().Description);
    }

    [Fact]
    public async Task ResolveAsync_PopulatesLastUsedAndSource_ForUserTokens()
    {
        var (raw, rec) = await _tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null);
        Assert.Null(rec.LastUsedAt);

        var resolved = await _tokens.ResolveAsync(raw);
        Assert.NotNull(resolved);
        Assert.Equal(TokenSource.User, resolved!.Source);
        Assert.Null(resolved.LastUsedAt); // not touched yet — resolution only reads
    }

    [Fact]
    public async Task ResolveAsync_PopulatesSource_ForServiceTokens()
    {
        var (raw, _) = await _tokens.CreateServiceTokenAsync(
            "o1", "ci", "[\"read:metadata\"]", expiresAt: null);

        var resolved = await _tokens.ResolveAsync(raw);
        Assert.NotNull(resolved);
        Assert.Equal(TokenSource.Service, resolved!.Source);
    }

    [Fact]
    public async Task TouchLastUsedAsync_StampsUserTokenWhenUnset()
    {
        var (_, rec) = await _tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null);

        await _tokens.TouchLastUsedAsync(rec.Id, TokenSource.User);

        var fetched = await _tokens.GetTokenByIdAsync(rec.Id, rec.OrgId);
        Assert.NotNull(fetched!.LastUsedAt);
        Assert.True((DateTimeOffset.UtcNow - fetched.LastUsedAt!.Value).Duration() < TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task TouchLastUsedAsync_ThrottlesWithinWindow()
    {
        var (_, rec) = await _tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null);

        await _tokens.TouchLastUsedAsync(rec.Id, TokenSource.User);
        var first = (await _tokens.GetTokenByIdAsync(rec.Id, rec.OrgId))!.LastUsedAt;

        // Second call inside the throttle window must be a no-op — the timestamp stays put.
        await Task.Delay(50);
        await _tokens.TouchLastUsedAsync(rec.Id, TokenSource.User, minIntervalSeconds: 60);
        var second = (await _tokens.GetTokenByIdAsync(rec.Id, rec.OrgId))!.LastUsedAt;

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task TouchLastUsedAsync_UpdatesAfterThresholdElapses()
    {
        var (_, rec) = await _tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null);

        // Seed last_used_at to a known timestamp in the past so we can verify the threshold
        // logic without sleeping. minIntervalSeconds=0 forces an unconditional update.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE user_tokens SET last_used_at = @ts WHERE id = @id",
                new { id = rec.Id, ts = DateTimeOffset.UtcNow.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ssZ") });
        }

        var before = (await _tokens.GetTokenByIdAsync(rec.Id, rec.OrgId))!.LastUsedAt;
        await _tokens.TouchLastUsedAsync(rec.Id, TokenSource.User, minIntervalSeconds: 60);
        var after = (await _tokens.GetTokenByIdAsync(rec.Id, rec.OrgId))!.LastUsedAt;

        Assert.True(after > before);
    }

    [Fact]
    public async Task TouchLastUsedAsync_TargetsServiceTableForServiceSource()
    {
        var (_, userRec) = await _tokens.CreateUserTokenAsync(
            "o1", "u1", "[\"read:metadata\"]", expiresAt: null);
        var (_, serviceRec) = await _tokens.CreateServiceTokenAsync(
            "o1", "ci", "[\"read:metadata\"]", expiresAt: null);

        await _tokens.TouchLastUsedAsync(serviceRec.Id, TokenSource.Service);

        // The service-token touch must not leak into the user table.
        var userAfter = await _tokens.GetTokenByIdAsync(userRec.Id, userRec.OrgId);
        Assert.Null(userAfter!.LastUsedAt);

        // And it must land in the service row.
        var serviceAfter = (await _tokens.ListServiceTokensAsync("o1")).Single(t => t.Id == serviceRec.Id);
        Assert.NotNull(serviceAfter.LastUsedAt);
    }

    [Fact]
    public async Task DeleteTokenAsync_WrongOrg_DeletesNothingAndKeepsToken()
    {
        var (_, rec) = await _tokens.CreateUserTokenAsync("o1", "u1", "[\"read:metadata\"]", expiresAt: null);

        // A caller in another tenant cannot revoke o1's token.
        var crossOrg = await _tokens.DeleteTokenAsync(rec.Id, "o2");
        Assert.Equal(0, crossOrg);
        Assert.NotNull(await _tokens.GetTokenByIdAsync(rec.Id, "o1"));

        // The owning tenant can.
        var sameOrg = await _tokens.DeleteTokenAsync(rec.Id, "o1");
        Assert.Equal(1, sameOrg);
        Assert.Null(await _tokens.GetTokenByIdAsync(rec.Id, "o1"));
    }

    [Fact]
    public async Task DeleteServiceTokenAsync_WrongOrg_DeletesNothingAndKeepsToken()
    {
        var (_, rec) = await _tokens.CreateServiceTokenAsync("o1", "ci", "[\"read:metadata\"]", expiresAt: null);

        var crossOrg = await _tokens.DeleteServiceTokenAsync(rec.Id, "o2");
        Assert.Equal(0, crossOrg);
        Assert.Contains(await _tokens.ListServiceTokensAsync("o1"), t => t.Id == rec.Id);

        var sameOrg = await _tokens.DeleteServiceTokenAsync(rec.Id, "o1");
        Assert.Equal(1, sameOrg);
        Assert.DoesNotContain(await _tokens.ListServiceTokensAsync("o1"), t => t.Id == rec.Id);
    }
}
