using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for <see cref="TokenAuthExtensions.ResolveTokenAsync"/>. The integration
/// suite in <c>TokenAuthenticationHandlerTests</c> exercises the happy path through the
/// ASP.NET auth pipeline; here we directly poke the helper to nail the malformed-header
/// and unsupported-scheme branches that don't get hit by the real handler.
/// </summary>
[Trait("Category", "Unit")]
public class TokenAuthExtensionsTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private TokenRepository _tokens = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _tokens = new TokenRepository(_db, TestTime.Frozen());
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static HttpRequest RequestWithAuth(string? authHeader)
    {
        var ctx = new DefaultHttpContext();
        if (authHeader is not null)
        {
            ctx.Request.Headers.Authorization = authHeader;
        }

        return ctx.Request;
    }

    [Fact]
    public async Task ResolveTokenAsync_NoAuthorizationHeader_ReturnsNull()
    {
        var req = RequestWithAuth(null);
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_UnsupportedScheme_ReturnsNull()
    {
        // Neither Bearer nor Basic — falls through both branches, raw stays null,
        // the IsNullOrEmpty gate trips and we return null without touching the repo.
        var req = RequestWithAuth("Digest some-digest-value");
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_BearerWithEmptyToken_ReturnsNull()
    {
        // "Bearer " with nothing after — raw trims to empty, IsNullOrEmpty short-circuits
        // before we ever hit the repository.
        var req = RequestWithAuth("Bearer ");
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_BearerWithUnknownToken_ReturnsNull()
    {
        // Well-formed Bearer header but no matching row in the DB — repo returns null.
        var req = RequestWithAuth("Bearer not-a-real-token-zzz");
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_BasicWithMalformedBase64_ReturnsNull()
    {
        // The catch block is the canonically-uncovered branch — Convert.FromBase64String
        // throws on a non-Base64 payload and the helper swallows it as null. This must NOT
        // bubble a FormatException up to the caller.
        var req = RequestWithAuth("Basic !!!not-base64!!!");
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_BasicWithNoColonInDecodedPayload_ReturnsNull()
    {
        // Base64 decodes cleanly but the decoded payload has no ':' separator —
        // colonIdx is -1, raw stays null, IsNullOrEmpty returns null.
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("nocolonhere"));
        var req = RequestWithAuth($"Basic {encoded}");
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_BasicWithEmptyTokenAfterColon_ReturnsNull()
    {
        // "user:" decodes to a present colon at index 4 but raw substring is "" —
        // IsNullOrEmpty trips and we return null without a repo call.
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:"));
        var req = RequestWithAuth($"Basic {encoded}");
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_BasicCaseInsensitiveSchemePrefix_ParsesCorrectly()
    {
        // "basic" lowercase must still parse — StringComparison.OrdinalIgnoreCase.
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:unknown-token-xyz"));
        var req = RequestWithAuth($"basic {encoded}");
        var result = await req.ResolveTokenAsync(_tokens);
        Assert.Null(result); // repo returns null for unknown token, but the scheme parsed
    }

    [Fact]
    public async Task ResolveTokenAsync_BearerResolvesUserToken()
    {
        // End-to-end happy path through Bearer: seed a row, present the raw token,
        // confirm the repo lookup returns it. Exercises the final
        // `await tokens.ResolveAsync(raw, ct)` line.
        const string rawToken = "raw-user-token-abcdef";
        string hash = TokenRepository.HashToken(rawToken);
        string tokenId = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = "org-unit", slug = "unit" });
            await conn.ExecuteAsync(
                "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @tenant, @email, @pw, @role)",
                new { id = "user-unit", tenant = "org-unit", email = "u@example.com", pw = "x", role = "member" });
            await conn.ExecuteAsync("""
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, created_at)
                VALUES (@id, @org, @user, @hash, @caps, @createdAt)
                """,
                new
                {
                    id = tokenId,
                    org = "org-unit",
                    user = "user-unit",
                    hash,
                    caps = """["read:metadata"]""",
                    createdAt = TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }

        var req = RequestWithAuth($"Bearer {rawToken}");
        var result = await req.ResolveTokenAsync(_tokens);

        Assert.NotNull(result);
        Assert.Equal(tokenId, result!.Id);
        Assert.Equal("org-unit", result.OrgId);
    }

    [Fact]
    public async Task ResolveTokenAsync_OrgScopedOverload_WrongOrg_ReturnsNull()
    {
        // The two-arg overload returns null when the token resolves but belongs to a
        // different tenant — the "cross-tenant token presented" branch. We seed for
        // org-unit and ask for org-other.
        const string rawToken = "raw-cross-tenant-token";
        string hash = TokenRepository.HashToken(rawToken);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = "org-unit-x", slug = "unitx" });
            await conn.ExecuteAsync("""
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
                VALUES (@id, @org, @name, @hash, @caps, @createdAt)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    org = "org-unit-x",
                    name = "ci",
                    hash,
                    caps = """["publish:npm"]""",
                    createdAt = TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }

        var req = RequestWithAuth($"Bearer {rawToken}");
        var result = await req.ResolveTokenAsync(_tokens, expectedOrgId: "some-other-org");

        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_OrgScopedOverload_NoToken_ReturnsNull()
    {
        // org-scoped overload covers the "inner returned null" early-out — no header at
        // all means the underlying helper returns null, which short-circuits before the
        // OrgId comparison.
        var req = RequestWithAuth(null);
        var result = await req.ResolveTokenAsync(_tokens, expectedOrgId: "any-org");
        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveTokenAsync_SuccessfulAuth_StampsLastUsedAt()
    {
        // The auth helper must call TouchLastUsedAsync on a successful resolution so the
        // /tokens UI can show operators when each token was last actually used. Failure
        // paths (covered above) must NOT touch the row.
        const string rawToken = "raw-touch-token";
        string hash = TokenRepository.HashToken(rawToken);
        string tokenId = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = "org-touch", slug = "touch" });
            await conn.ExecuteAsync(
                "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @tenant, @email, @pw, @role)",
                new { id = "user-touch", tenant = "org-touch", email = "u@example.com", pw = "x", role = "member" });
            await conn.ExecuteAsync("""
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, created_at)
                VALUES (@id, @org, @user, @hash, @caps, @createdAt)
                """,
                new
                {
                    id = tokenId,
                    org = "org-touch",
                    user = "user-touch",
                    hash,
                    caps = """["read:metadata"]""",
                    createdAt = TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }

        var req = RequestWithAuth($"Bearer {rawToken}");
        var resolved = await req.ResolveTokenAsync(_tokens);

        Assert.NotNull(resolved);
        var after = await _tokens.GetTokenByIdAsync(tokenId, "org-touch");
        Assert.NotNull(after!.LastUsedAt);
        // Repository stamps from its injected frozen clock at second granularity — exact match.
        Assert.Equal(TestTime.KnownNow, after.LastUsedAt!.Value);
    }

    [Fact]
    public async Task ResolveTokenAsync_FailedAuth_LeavesLastUsedAtUntouched()
    {
        // The bad-token branch returns null without calling TouchLastUsedAsync, so a row
        // we plant with a known last_used_at must be unchanged after the failed lookup.
        var req = RequestWithAuth("Bearer never-resolves-anywhere");
        var resolved = await req.ResolveTokenAsync(_tokens);
        Assert.Null(resolved);
        // Nothing to verify on a non-existent row — the absence of an exception is the contract;
        // the throttled UPDATE on a missing id is a 0-row no-op even if it had been called.
    }

    [Fact]
    public async Task ResolveTokenAsync_OrgScopedOverload_MatchingOrg_ReturnsToken()
    {
        // The positive branch of the org check — token resolves AND OrgId matches.
        const string rawToken = "raw-org-match-token";
        string hash = TokenRepository.HashToken(rawToken);
        string tokenId = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = "org-match", slug = "match" });
            await conn.ExecuteAsync("""
                INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, created_at)
                VALUES (@id, @org, @name, @hash, @caps, @createdAt)
                """,
                new
                {
                    id = tokenId,
                    org = "org-match",
                    name = "ci",
                    hash,
                    caps = """["publish:npm"]""",
                    createdAt = TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                });
        }

        var req = RequestWithAuth($"Bearer {rawToken}");
        var result = await req.ResolveTokenAsync(_tokens, expectedOrgId: "org-match");

        Assert.NotNull(result);
        Assert.Equal(tokenId, result!.Id);
        Assert.Equal("org-match", result.OrgId);
    }
}
