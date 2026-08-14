using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The per-tenant active-token ceiling is enforced where the row is written, not merely checked
/// before it. A count in one statement and an insert in another is a check-then-act: concurrent
/// creates all read the same under-cap total and all insert, so the overshoot is bounded by how
/// many requests a caller can run in parallel rather than by one row.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TokenCapEnforcementTests : IAsyncLifetime
{
    private const string OrgId = "org-token-cap";
    private const string UserId = "user-token-cap";
    private const string Capabilities = """["read:tenant"]""";

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@OrgId, @OrgId)", new { OrgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role)
            VALUES (@UserId, @OrgId, 'cap@example.test', 'x', 'member')
            """,
            new { UserId, OrgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private TokenRepository Repo() => new(_db, TestTime.Frozen());

    private async Task SetCapAsync(int cap)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO instance_settings (key, value) VALUES ('max_active_tokens_per_tenant', @value)
            ON CONFLICT(key) DO UPDATE SET value = @value
            """,
            new { value = cap.ToString() });
    }

    private async Task<int> CountTokensAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            """
            SELECT (SELECT COUNT(*) FROM user_tokens WHERE org_id = @OrgId)
                 + (SELECT COUNT(*) FROM service_tokens WHERE org_id = @OrgId)
            """,
            new { OrgId });
    }

    [Fact]
    public async Task CreateUserToken_AtTheCap_IsRefusedByTheRepository()
    {
        await SetCapAsync(2);
        var repo = Repo();

        await repo.CreateUserTokenAsync(OrgId, UserId, Capabilities, expiresAt: null);
        await repo.CreateUserTokenAsync(OrgId, UserId, Capabilities, expiresAt: null);

        var ex = await Assert.ThrowsAsync<TokenCapExceededException>(
            () => repo.CreateUserTokenAsync(OrgId, UserId, Capabilities, expiresAt: null));

        Assert.Equal(2, ex.Cap);
        Assert.Equal(2, await CountTokensAsync());
    }

    [Fact]
    public async Task ServiceTokens_CountAgainstTheSameCeiling()
    {
        await SetCapAsync(2);
        var repo = Repo();

        await repo.CreateUserTokenAsync(OrgId, UserId, Capabilities, expiresAt: null);
        await repo.CreateServiceTokenAsync(OrgId, "ci", Capabilities, expiresAt: null);

        await Assert.ThrowsAsync<TokenCapExceededException>(
            () => repo.CreateServiceTokenAsync(OrgId, "ci-2", Capabilities, expiresAt: null));

        Assert.Equal(2, await CountTokensAsync());
    }

    [Fact]
    public async Task ExpiredTokens_DoNotConsumeTheCap()
    {
        await SetCapAsync(1);
        var repo = Repo();

        await repo.CreateUserTokenAsync(
            OrgId, UserId, Capabilities, expiresAt: TestTime.KnownNow.AddHours(-1));

        // The expired row is not active, so the ceiling still has its one slot.
        await repo.CreateUserTokenAsync(OrgId, UserId, Capabilities, expiresAt: null);

        Assert.Equal(2, await CountTokensAsync());
    }

    /// <summary>
    /// The mixed partial-failure case, and the one the non-transactional check could not survive:
    /// a burst of concurrent creates against a tenant with two slots left must land exactly two
    /// rows and refuse the rest — not "at most one" past the cap, and not one per racing request.
    /// Each call opens its own connection, matching real concurrent API requests.
    /// </summary>
    [Fact]
    public async Task ConcurrentCreates_FillTheRemainingSlotsExactly_AndRefuseTheRest()
    {
        const int cap = 5;
        const int seeded = 3;
        const int attempts = 8;

        await SetCapAsync(cap);
        var repo = Repo();
        for (int i = 0; i < seeded; i++)
        {
            await repo.CreateUserTokenAsync(OrgId, UserId, Capabilities, expiresAt: null);
        }

        bool[] results = await Task.WhenAll(Enumerable.Range(0, attempts).Select(async _ =>
        {
            try
            {
                await repo.CreateUserTokenAsync(OrgId, UserId, Capabilities, expiresAt: null);
                return true;
            }
            catch (TokenCapExceededException)
            {
                return false;
            }
        }));

        Assert.Equal(cap - seeded, results.Count(ok => ok));
        Assert.Equal(attempts - (cap - seeded), results.Count(ok => !ok));
        // The authoritative count, which is what the cap is actually about.
        Assert.Equal(cap, await CountTokensAsync());
    }
}
