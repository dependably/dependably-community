using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the system API-token surface (multi mode, apex only): minting via
/// <c>POST /api/v1/system/tokens</c>, the eight-action reach on <c>SystemController</c>, cascade
/// revocation on owner disable/delete/password-reset, and the reach's cross-realm/cross-scheme
/// twins. Every positive case has an adversarial twin that must NOT succeed.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemTokenTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;

    public SystemTokenTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private static async Task<(string Token, JsonElement Record)> MintTokenAsync(
        HttpClient sysAdminClient, string name, DateTimeOffset? expiresAt = null, string? description = null)
    {
        var resp = await sysAdminClient.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name,
            // now-ok: expiresAt is validated against the host's real clock (server-side
            // TimeProvider.System in this fixture), so the request body must be relative to it.
            expiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddDays(30),
            description,
        });
        resp.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return (doc.RootElement.GetProperty("token").GetString()!, doc.RootElement.GetProperty("record").Clone());
    }

    private HttpClient ClientWithSystemToken(string host, string token)
    {
        var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// <summary>Creates a second system_admin (bypassing HTTP) and returns its id + a session JWT client.</summary>
    private async Task<(string AdminId, HttpClient Client)> CreateSecondAdminAsync()
    {
        var admins = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string email = $"second-{Guid.NewGuid():N}@example.com";
        string id = await admins.CreateAsync(email, BCrypt.Net.BCrypt.HashPassword("Irrelevant1!", workFactor: 4), mustChangePassword: false);
        string jwt = await _factory.CreateSystemAdminJwtForUser(id);
        var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return (id, client);
    }

    private static async Task<string> CreateTenantSlugAsync(HttpClient sysAdminClient)
    {
        string slug = "stok-" + Guid.NewGuid().ToString("N")[..8];
        var resp = await sysAdminClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"owner-{Guid.NewGuid():N}@example.com",
        });
        resp.EnsureSuccessStatusCode();
        return slug;
    }

    // ── Positive: mint + reach ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task MintedToken_CreatesTenant_AndAuditsAsServiceActor()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, record) = await MintTokenAsync(sysAdmin, "provisioning-token-" + Guid.NewGuid().ToString("N")[..6]);
        string tokenName = record.GetProperty("name").GetString()!;

        string slug = "mint-" + Guid.NewGuid().ToString("N")[..8];
        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var resp = await tokenClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        string orgId = doc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        var org = await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync(slug);
        Assert.NotNull(org);

        await using var conn = await Db.OpenAsync();
        var (actorKind, actorLabel, detail) = await conn.QuerySingleAsync<(string ActorKind, string? ActorLabel, string? Detail)>(
            """
            SELECT actor_kind as ActorKind, actor_label as ActorLabel, detail as Detail
            FROM audit_log WHERE action = 'tenant.created' AND org_id = @orgId
            ORDER BY created_at DESC LIMIT 1
            """,
            new { orgId });
        Assert.Equal(ActorKinds.Service, actorKind);
        Assert.Equal(tokenName, actorLabel);
        Assert.Contains("via_token_owner", detail);
    }

    /// <summary>Adversarial twin: the equivalent JWT-session write is NOT attributed as a service actor.</summary>
    [Fact]
    public async Task JwtMintedTenant_AuditsAsNullActorKind_NotService()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        string slug = "jwt-" + Guid.NewGuid().ToString("N")[..8];
        var resp = await sysAdmin.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        resp.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        string orgId = doc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        await using var conn = await Db.OpenAsync();
        var (actorKind, _) = await conn.QuerySingleAsync<(string? ActorKind, string? ActorLabel)>(
            """
            SELECT actor_kind as ActorKind, actor_label as ActorLabel
            FROM audit_log WHERE action = 'tenant.created' AND org_id = @orgId
            ORDER BY created_at DESC LIMIT 1
            """,
            new { orgId });
        Assert.NotEqual(ActorKinds.Service, actorKind);
    }

    [Fact]
    public async Task Token_AtTenantSubdomain_Returns404()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, _) = await MintTokenAsync(sysAdmin, "subdomain-check-" + Guid.NewGuid().ToString("N")[..6]);
        string slug = await CreateTenantSlugAsync(sysAdmin);

        using var tokenClient = ClientWithSystemToken($"{slug}.localhost", token);
        var resp = await tokenClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Theory]
    [InlineData("GET", "/api/v1/system/admins")]
    [InlineData("POST", "/api/v1/system/jwt-secret/rotate")]
    [InlineData("GET", "/api/v1/system/me")]
    public async Task Token_OnNonAllowlistedAction_Returns401(string method, string path)
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, _) = await MintTokenAsync(sysAdmin, "reach-check-" + Guid.NewGuid().ToString("N")[..6]);

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var req = new HttpRequestMessage(new HttpMethod(method), path);
        var resp = await tokenClient.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Revocation / cascade ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ExpiredToken_Returns401()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, record) = await MintTokenAsync(sysAdmin, "expiry-check-" + Guid.NewGuid().ToString("N")[..6]);
        string id = record.GetProperty("id").GetString()!;

        await using (var conn = await Db.OpenAsync())
        {
            // now-ok: seeds relative to the host's real clock so the resolver's expires_at > now
            // filter rejects it, matching the established backdate pattern (NpmPingWhoamiTests).
            await conn.ExecuteAsync(
                "UPDATE system_tokens SET expires_at = @past WHERE id = @id",
                new { past = DateTimeOffset.UtcNow.AddHours(-1).ToUtcIso(), id });
        }

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var resp = await tokenClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task RevokedToken_Returns401()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, record) = await MintTokenAsync(sysAdmin, "revoke-check-" + Guid.NewGuid().ToString("N")[..6]);
        string id = record.GetProperty("id").GetString()!;

        var deleteResp = await sysAdmin.DeleteAsync($"/api/v1/system/tokens/{id}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResp.StatusCode);

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var resp = await tokenClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    /// <summary>
    /// Adversarial twin: DELETE targets exactly the revoked row's id — a sibling token minted by
    /// the same owner is untouched and keeps authenticating. Pins <c>DeleteAsync</c>'s
    /// <c>WHERE id = @id</c> against a broader delete (e.g. one that drops every token for the
    /// owner) that would pass <see cref="RevokedToken_Returns401"/> just as easily.
    /// </summary>
    [Fact]
    public async Task RevokedToken_SiblingTokenBySameOwner_StillAuthenticates()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (keptToken, _) = await MintTokenAsync(sysAdmin, "kept-" + Guid.NewGuid().ToString("N")[..6]);
        var (revokedToken, revokedRecord) = await MintTokenAsync(sysAdmin, "revoked-" + Guid.NewGuid().ToString("N")[..6]);
        string revokedId = revokedRecord.GetProperty("id").GetString()!;

        var deleteResp = await sysAdmin.DeleteAsync($"/api/v1/system/tokens/{revokedId}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResp.StatusCode);

        using var revokedClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, revokedToken);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await revokedClient.GetAsync("/api/v1/system/tenants")).StatusCode);

        using var keptClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, keptToken);
        Assert.Equal(HttpStatusCode.OK,
            (await keptClient.GetAsync("/api/v1/system/tenants")).StatusCode);
    }

    [Fact]
    public async Task OwnerDisabled_TokenStopsResolving()
    {
        var (adminId, adminClient) = await CreateSecondAdminAsync();
        var (token, _) = await MintTokenAsync(adminClient, "owner-disabled-" + Guid.NewGuid().ToString("N")[..6]);

        var admins = _factory.Services.GetRequiredService<SystemAdminRepository>();
        await admins.SetAccountStatusAsync(adminId, "disabled");

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var resp = await tokenClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task OwnerDeleted_TokenGoneViaForeignKeyCascade()
    {
        var (adminId, adminClient) = await CreateSecondAdminAsync();
        var (token, record) = await MintTokenAsync(adminClient, "owner-deleted-" + Guid.NewGuid().ToString("N")[..6]);
        string tokenId = record.GetProperty("id").GetString()!;

        var admins = _factory.Services.GetRequiredService<SystemAdminRepository>();
        await admins.SetAccountStatusAsync(adminId, "disabled");
        int affected = await admins.DeleteIfDisabledAsync(adminId);
        Assert.Equal(1, affected);

        await using (var conn = await Db.OpenAsync())
        {
            long remaining = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM system_tokens WHERE id = @tokenId", new { tokenId });
            Assert.Equal(0, remaining);
        }

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var resp = await tokenClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task OwnerPasswordReset_ByAnotherAdmin_RevokesTokens()
    {
        var (adminId, adminClient) = await CreateSecondAdminAsync();
        var (token, _) = await MintTokenAsync(adminClient, "owner-reset-" + Guid.NewGuid().ToString("N")[..6]);

        using var bootstrapAdmin = await _factory.CreateSystemAdminClient();
        var resetResp = await bootstrapAdmin.PostAsync($"/api/v1/system/admins/{adminId}/password-reset", content: null);
        Assert.Equal(HttpStatusCode.OK, resetResp.StatusCode);

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var resp = await tokenClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    /// <summary>
    /// Adversarial twin: DeleteByOwnerAsync is scoped to the reset target's own id — a different
    /// admin's token is untouched. Pins the <c>WHERE created_by = @adminId</c> against a broader
    /// delete (e.g. one that clears every system token instance-wide) that would pass
    /// <see cref="OwnerPasswordReset_ByAnotherAdmin_RevokesTokens"/> just as easily.
    /// </summary>
    [Fact]
    public async Task OwnerPasswordReset_UnrelatedAdminToken_StillAuthenticates()
    {
        var (resetTargetId, resetTargetClient) = await CreateSecondAdminAsync();
        var (_, bystanderClient) = await CreateSecondAdminAsync();

        var (targetToken, _) = await MintTokenAsync(resetTargetClient, "reset-target-" + Guid.NewGuid().ToString("N")[..6]);
        var (bystanderToken, _) = await MintTokenAsync(bystanderClient, "bystander-" + Guid.NewGuid().ToString("N")[..6]);

        using var bootstrapAdmin = await _factory.CreateSystemAdminClient();
        var resetResp = await bootstrapAdmin.PostAsync($"/api/v1/system/admins/{resetTargetId}/password-reset", content: null);
        Assert.Equal(HttpStatusCode.OK, resetResp.StatusCode);

        using var targetClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, targetToken);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await targetClient.GetAsync("/api/v1/system/tenants")).StatusCode);

        using var bystanderTokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, bystanderToken);
        Assert.Equal(HttpStatusCode.OK,
            (await bystanderTokenClient.GetAsync("/api/v1/system/tenants")).StatusCode);
    }

    /// <summary>Adversarial twin: the owner's own self-service password change does NOT revoke their tokens.</summary>
    [Fact]
    public async Task OwnerSelfPasswordChange_DoesNotRevokeTokens()
    {
        var (_, adminClient) = await CreateSecondAdminAsync();
        var (token, _) = await MintTokenAsync(adminClient, "owner-self-change-" + Guid.NewGuid().ToString("N")[..6]);

        var changeResp = await adminClient.PostAsJsonAsync("/api/v1/system/me/password", new
        {
            currentPassword = "Irrelevant1!",
            newPassword = "Irrelevant2!ReallyStrong",
        });
        Assert.Equal(HttpStatusCode.OK, changeResp.StatusCode);

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        var resp = await tokenClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Cross-scheme rejection ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task TenantServiceToken_OnSystemTenantsRoute_Returns401()
    {
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var org = await orgRepo.CreateOrgAsync($"xrealm-{Guid.NewGuid():N}"[..16]);
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            org.Id, $"svc-{Guid.NewGuid():N}"[..16],
            """["publish:*","read:artifact","read:metadata","yank:*"]""",
            expiresAt: null);

        using var client = ClientWithSystemToken(DependablyMultiFactory.ApexHost, raw);
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug = "should-not-" + Guid.NewGuid().ToString("N")[..8],
            ownerEmail = $"nope-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task SystemToken_OnTenantTokensRoute_Rejected()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, _) = await MintTokenAsync(sysAdmin, "tenant-route-check-" + Guid.NewGuid().ToString("N")[..6]);
        string slug = await CreateTenantSlugAsync(sysAdmin);

        using var tokenClient = ClientWithSystemToken($"{slug}.localhost", token);
        var resp = await tokenClient.GetAsync("/api/v1/tokens");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task SystemToken_CannotMintAnotherToken()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, _) = await MintTokenAsync(sysAdmin, "no-self-mint-" + Guid.NewGuid().ToString("N")[..6]);

        using var tokenClient = ClientWithSystemToken(DependablyMultiFactory.ApexHost, token);
        // now-ok: request body validated against the host's real clock.
        var resp = await tokenClient.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "should-not-mint",
            expiresAt = DateTimeOffset.UtcNow.AddDays(1),
        });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Mint validation ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Mint_MissingExpiry_Returns422()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var resp = await sysAdmin.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "no-expiry-" + Guid.NewGuid().ToString("N")[..6],
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("expiresAt", doc.RootElement.GetProperty("field").GetString());
    }

    [Fact]
    public async Task Mint_ExpiryInPast_Returns422()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        // now-ok: request body validated against the host's real clock.
        var resp = await sysAdmin.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "past-expiry-" + Guid.NewGuid().ToString("N")[..6],
            expiresAt = DateTimeOffset.UtcNow.AddDays(-1),
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Mint_ExpiryOver365Days_Returns422()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        // now-ok: request body validated against the host's real clock.
        var resp = await sysAdmin.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "far-expiry-" + Guid.NewGuid().ToString("N")[..6],
            expiresAt = DateTimeOffset.UtcNow.AddDays(366),
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("expiresAt", doc.RootElement.GetProperty("field").GetString());
    }

    /// <summary>Adversarial twin: an expiry inside the window mints successfully.</summary>
    [Fact]
    public async Task Mint_ExpiryWithinWindow_Succeeds()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        // now-ok: request body validated against the host's real clock.
        var resp = await sysAdmin.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "ok-expiry-" + Guid.NewGuid().ToString("N")[..6],
            expiresAt = DateTimeOffset.UtcNow.AddDays(365),
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    /// <summary>
    /// The mint response's record names its owner, so a client that renders it directly (the
    /// system console prepends it to the table) shows the same owner the list endpoint does.
    /// </summary>
    [Fact]
    public async Task Mint_ResponseRecord_CarriesOwnerEmail_MatchingList()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (_, record) = await MintTokenAsync(sysAdmin, "owner-shown-" + Guid.NewGuid().ToString("N")[..6]);
        string id = record.GetProperty("id").GetString()!;

        Assert.Equal(DependablyMultiFactory.SystemAdminEmail, record.GetProperty("ownerEmail").GetString());

        var list = await sysAdmin.GetFromJsonAsync<JsonElement>("/api/v1/system/tokens");
        var listed = list.EnumerateArray().Single(t => t.GetProperty("id").GetString() == id);
        Assert.Equal(DependablyMultiFactory.SystemAdminEmail, listed.GetProperty("ownerEmail").GetString());
    }

    // ── Instance cap ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Seeds exactly the instance-wide cap (50 active rows), confirms the next mint is refused
    /// with the dedicated <c>error.systemToken.limitReached</c> field, then expires one seeded
    /// row (the same SQL-backdate pattern <see cref="ExpiredToken_Returns401"/> uses) and confirms
    /// the mint that was refused a moment ago now succeeds — proving the cap counts active rows,
    /// not a static high-water mark.
    /// </summary>
    [Fact]
    public async Task InstanceCap_AtFiftyActiveTokens_RefusesMint_ThenExpiringOneAllowsIt()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();

        string bootstrapAdminId;
        await using (var conn = await Db.OpenAsync())
        {
            bootstrapAdminId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM system_admins WHERE email = @email LIMIT 1",
                new { email = DependablyMultiFactory.SystemAdminEmail })
                ?? throw new InvalidOperationException("bootstrap admin missing");
        }

        // Isolate this test's count from any tokens other tests in the shared class fixture
        // minted — tests in one class run sequentially, so no other test is mid-flight — then
        // seed exactly the cap directly (bypassing the repository, whose own cap check would
        // refuse the 50th seed row).
        string firstSeededId = Guid.NewGuid().ToString("N");
        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM system_tokens");

            // now-ok: seeds relative to the host's real clock so the resolver's expires_at > now
            // filter (and the repository's own active-count check) treat every row as active.
            string farFuture = DateTimeOffset.UtcNow.AddDays(30).ToUtcIso();
            for (int i = 0; i < 50; i++)
            {
                string id = i == 0 ? firstSeededId : Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO system_tokens (id, name, token_hash, created_by, expires_at)
                    VALUES (@id, @name, @hash, @createdBy, @expires)
                    """,
                    new
                    {
                        id,
                        name = $"cap-seed-{i}",
                        hash = Guid.NewGuid().ToString("N"),
                        createdBy = bootstrapAdminId,
                        expires = farFuture,
                    });
            }
        }

        // now-ok: request body validated against the host's real clock.
        var atCapResp = await sysAdmin.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "over-cap-" + Guid.NewGuid().ToString("N")[..6],
            expiresAt = DateTimeOffset.UtcNow.AddDays(1),
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, atCapResp.StatusCode);
        var doc = JsonDocument.Parse(await atCapResp.Content.ReadAsStringAsync());
        Assert.Equal("tokens", doc.RootElement.GetProperty("field").GetString());

        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_tokens SET expires_at = @past WHERE id = @id",
                // now-ok: seeds relative to the host's real clock so the resolver's expires_at >
                // now filter (and the cap count) treat this row as inactive again.
                new { past = DateTimeOffset.UtcNow.AddHours(-1).ToUtcIso(), id = firstSeededId });
        }

        // now-ok: request body validated against the host's real clock.
        var underCapResp = await sysAdmin.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "under-cap-" + Guid.NewGuid().ToString("N")[..6],
            expiresAt = DateTimeOffset.UtcNow.AddDays(1),
        });
        Assert.Equal(HttpStatusCode.OK, underCapResp.StatusCode);

        // Tests in this class run sequentially against one shared factory (IClassFixture), so
        // the 48 still-active seeded rows this test leaves behind would push every later test's
        // own mint against the same cap. Clear the table rather than leaving global state for a
        // sibling test to trip over.
        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM system_tokens");
        }
    }

    // ── Session-version race ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// The outer JwtBearer/<c>SystemAdminTokenVersionStore</c> check is cache-backed (up to 60s
    /// TTL on this single-replica test host) and runs once, before the controller action
    /// executes. A <c>token_version</c> bump landing in the DB after that check but before
    /// <c>CreateAsync</c>'s own transactional re-check would otherwise still mint a durable
    /// credential under a session that is, at that instant, already invalidated everywhere
    /// else — the race <c>CreateAsync</c>'s <c>WHERE token_version = @callerTokenVersion</c>
    /// closes. Reproduced by warming the cache with one authenticated call, then bumping
    /// <c>token_version</c> directly (bypassing <c>SystemAdminTokenVersionStore.Invalidate</c>,
    /// the shape a concurrent request such as another admin's password-reset produces), which
    /// leaves the outer gate still admitting the stale session for its cache window.
    /// </summary>
    [Fact]
    public async Task ConcurrentTokenVersionBump_BeforeMint_MintRefuses()
    {
        var (adminId, adminClient) = await CreateSecondAdminAsync();

        var warm = await adminClient.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);

        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE system_admins SET token_version = token_version + 1 WHERE id = @adminId",
                new { adminId });
        }

        // now-ok: request body validated against the host's real clock.
        var mintResp = await adminClient.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "race-check-" + Guid.NewGuid().ToString("N")[..6],
            expiresAt = DateTimeOffset.UtcNow.AddDays(1),
        });
        Assert.Equal(HttpStatusCode.Unauthorized, mintResp.StatusCode);
    }

    // ── Mixed principal ──────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A request presenting both the session cookie (a valid system_admin JWT) and a
    /// <c>dpsys_…</c> Bearer header authenticates under both schemes at once — the exact shape
    /// <c>SystemTokenMixedPrincipalGuard</c> exists to refuse rather than let ASP.NET Core merge
    /// into one two-identity principal.
    /// </summary>
    [Fact]
    public async Task SessionCookiePlusSystemToken_Returns401()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, _) = await MintTokenAsync(sysAdmin, "mixed-principal-" + Guid.NewGuid().ToString("N")[..6]);
        string jwt = await _factory.CreateSystemAdminJwt();

        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/tenants");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    /// <summary>Adversarial twin: the same token with no cookie on the request authenticates normally.</summary>
    [Fact]
    public async Task SystemTokenAlone_NoCookie_Returns200()
    {
        using var sysAdmin = await _factory.CreateSystemAdminClient();
        var (token, _) = await MintTokenAsync(sysAdmin, "token-alone-" + Guid.NewGuid().ToString("N")[..6]);

        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/tenants");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── REQUIRE_MFA exemption ────────────────────────────────────────────────────────────────

    /// <summary>
    /// With the instance-level REQUIRE_MFA=true and the token's owner unenrolled, the token
    /// still authenticates its allowlisted actions — MfaEnrollmentGuard exempts the SystemToken
    /// scheme the same way it exempts ApiToken, because minting already required a session in
    /// good standing. Uses its own host (REQUIRE_MFA is read once at startup) and mints the
    /// token directly through the repository, since the mint endpoint itself is JWT-only and
    /// would otherwise be blocked by the guard for the same unenrolled admin.
    /// </summary>
    [Fact]
    public async Task Token_WithRequireMfaTrue_AndUnenrolledOwner_StillAuthenticates()
    {
        await using var factory = new RequireMfaSystemFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        var admins = factory.Services.GetRequiredService<SystemAdminRepository>();
        int adminCount = await admins.CountAsync();
        Assert.True(adminCount >= 1);

        var systemTokens = factory.Services.GetRequiredService<SystemTokenRepository>();
        await using var conn = await factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string adminId = await conn.ExecuteScalarAsync<string>("SELECT id FROM system_admins LIMIT 1")
            ?? throw new InvalidOperationException("bootstrap admin missing");

        long tokenVersion = await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM system_admins WHERE id = @adminId", new { adminId });

        // now-ok: seeded relative to the host's real clock — this fixture runs no FakeTimeProvider.
        var (raw, _) = await systemTokens.CreateAsync(
            adminId, "mfa-exempt-check", DateTimeOffset.UtcNow.AddDays(1), tokenVersion);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Host = RequireMfaSystemFactory.ApexHost;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);

        var resp = await client.GetAsync("/api/v1/system/tenants");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    /// <summary>Minimal REQUIRE_MFA=true multi-mode host, mirroring LoginEnrollmentRequiredTests' fixture shape.</summary>
    private sealed class RequireMfaSystemFactory : WebApplicationFactory<Program>, IAsyncLifetime
    {
        public const string ApexHost = "localhost";
        private readonly InMemoryBlobStore _blob = new();
        private readonly IntegrationDatabase _db = new();

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            builder.Configuration["DEPLOYMENT_MODE"] = "multi";
            builder.Configuration["BASE_URL"] = $"http://{ApexHost}";
            builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] = "mfa-check@example.com";
            builder.Configuration["FIRST_BOOT_SYSTEM_ADMIN_PASSWORD"] = "MfaCheck12345!";

            _db.ConfigureBefore(builder);

            Program.ConfigureBuilder(builder);

            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blob);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blob, _blob));
            _db.ConfigureServices(builder.Services);

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting(
                "DISABLE_BACKGROUND_JOBS",
                "vuln-scan,vuln-rescan,sbom-scan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep");
            builder.WebHost.UseSetting("REQUIRE_MFA", "true");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);
            _db.Start(app);
            return app;
        }

        public Task InitializeAsync()
        {
            _ = CreateClient();
            return Task.CompletedTask;
        }

        public new async Task DisposeAsync()
        {
            await base.DisposeAsync();
            await _db.DisposeAsync();
        }
    }
}
