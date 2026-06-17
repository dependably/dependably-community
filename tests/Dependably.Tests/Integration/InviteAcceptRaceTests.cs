using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression guard for the single-use invite race: concurrent POST /api/v1/invites/accept
/// requests carrying the same valid token must produce exactly one account, with all but
/// one request receiving 410. The atomic UPDATE in AcceptAsync ensures the losing requests
/// get rowsAffected==0 even when they reach the statement simultaneously.
///
/// House rule: includes a mixed partial-failure scenario — some requests succeed, the
/// rest fail, in the same concurrent call.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InviteAcceptRaceTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public InviteAcceptRaceTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string OrgId, string RawToken)> SeedInviteAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        string adminId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");

            adminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found.");
        }

        var invites = _factory.Services.GetRequiredService<InviteRepository>();
        string email = $"race-{Guid.NewGuid():N}@x.test";
        var (raw, _) = await invites.CreateAsync(orgId, email, adminId, "member");
        return (orgId, raw);
    }

    private async Task<int> CountUsersWithEmail(string email)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM users WHERE email = @email", new { email });
    }

    // ── Concurrent double-accept: exactly one 200, rest 410 ─────────────────

    /// <summary>
    /// Fires N concurrent POST /api/v1/invites/accept requests with the same token.
    /// Asserts exactly one 200 ("Account created") and the rest 410, and that the
    /// users table gained exactly one row — the mixed partial-failure regression guard
    /// for the atomic acceptance fix.
    /// </summary>
    [Fact]
    public async Task ConcurrentAccept_ExactlyOneWins_RestGet410()
    {
        var (_, rawToken) = await SeedInviteAsync();
        string email = await GetInviteEmail(rawToken);
        // deepcode ignore NoHardcodedCredentials/test: in-memory test fixture password for the invite-accept race test; not a real credential.
        string uniquePassword = "Xm9#kLp2$vRq8nTs!";

        const int Concurrency = 6;

        // POST /api/v1/invites/accept with the same token from N concurrent clients.
        var tasks = Enumerable.Range(0, Concurrency).Select(_ =>
        {
            var client = _factory.CreateClient();
            return client.PostAsJsonAsync("/api/v1/invites/accept", new
            {
                token = rawToken,
                password = uniquePassword
            });
        }).ToList();

        var responses = await Task.WhenAll(tasks);

        int successCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        int goneCount = responses.Count(r => r.StatusCode == HttpStatusCode.Gone);

        // Exactly one request must win. The rest must fail as already-used/expired.
        Assert.Equal(1, successCount);
        Assert.Equal(Concurrency - 1, goneCount);

        // Exactly one user row must exist — duplicate account creation is the bug being fixed.
        int userRowCount = await CountUsersWithEmail(email);
        Assert.Equal(1, userRowCount);
    }

    /// <summary>
    /// Sequential double-accept: second call returns 410 without any concurrent racing.
    /// Validates the basic single-use property.
    /// </summary>
    [Fact]
    public async Task SequentialDoubleAccept_SecondIs410()
    {
        var (_, rawToken) = await SeedInviteAsync();

        var first = await _factory.CreateClient().PostAsJsonAsync("/api/v1/invites/accept", new
        {
            token = rawToken,
            password = "Xm9#kLp2$vRq8nTs!"
        });
        var second = await _factory.CreateClient().PostAsJsonAsync("/api/v1/invites/accept", new
        {
            token = rawToken,
            password = "Xm9#kLp2$vRq8nTs!"
        });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Gone, second.StatusCode);
    }

    /// <summary>
    /// Expired token: returns 410 without creating any user.
    /// </summary>
    [Fact]
    public async Task ExpiredToken_Returns410_NoUserCreated()
    {
        // Seed an invite that is already expired by inserting directly with a past expiry.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        string adminId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
            adminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
                new { orgId })
                ?? throw new InvalidOperationException("Bootstrap owner not found.");
        }

        // Create a valid invite via the repo, then back-date its expires_at in the DB.
        var invites = _factory.Services.GetRequiredService<InviteRepository>();
        string email = $"expired-{Guid.NewGuid():N}@x.test";
        var (raw, record) = await invites.CreateAsync(orgId, email, adminId, "member");

        await using (var conn = await store.OpenAsync())
        {
            // now-ok: back-dating an invite row in the DB for test purposes; no frozen clock
            // is available here because InviteRepository.CreateAsync uses the real system
            // clock in the integration host (DependablyFactory does not freeze by default).
            string pastExpiry = DateTimeOffset.UtcNow.AddHours(-48).ToString("yyyy-MM-ddTHH:mm:ssZ");
            await conn.ExecuteAsync(
                "UPDATE invites SET expires_at = @expiry WHERE id = @id",
                new { expiry = pastExpiry, id = record.Id });
        }

        var response = await _factory.CreateClient().PostAsJsonAsync("/api/v1/invites/accept", new
        {
            token = raw,
            password = "Xm9#kLp2$vRq8nTs!"
        });

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
        Assert.Equal(0, await CountUsersWithEmail(email));
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private async Task<string> GetInviteEmail(string rawToken)
    {
        byte[] hashBytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(rawToken));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        // xtenant: lookup by globally-unique token_hash for test assertion only
        return await conn.ExecuteScalarAsync<string>(
            "SELECT email FROM invites WHERE token_hash = @hash", new { hash })
            ?? throw new InvalidOperationException("Invite not found.");
    }
}
