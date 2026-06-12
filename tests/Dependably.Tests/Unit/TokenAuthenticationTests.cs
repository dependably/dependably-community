using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Encodings.Web;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage of <see cref="TokenAuthenticationHandler"/> branches that aren't reached by
/// the integration tests: header-shape extraction (Basic without colon, malformed base64,
/// no header at all), capability JSON edge cases (null, empty, whitespace, malformed,
/// whitespace entries), and the CI vs. user role lookup. Hits the handler directly via
/// <see cref="AuthenticationHandler{T}.InitializeAsync"/> so we don't need a full TestServer.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TokenAuthenticationTests : IAsyncLifetime
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
                ('u-admin', 'o1', 'a@example.com', '', 'admin')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task<TokenAuthenticationHandler> CreateHandlerAsync(HttpContext context)
    {
        var options = Substitute.For<IOptionsMonitor<TokenAuthenticationOptions>>();
        options.Get(Arg.Any<string>()).Returns(new TokenAuthenticationOptions());
        var handler = new TokenAuthenticationHandler(
            options, NullLoggerFactory.Instance, UrlEncoder.Default, _tokens, _db);
        var scheme = new AuthenticationScheme(
            TokenAuthenticationDefaults.Scheme,
            TokenAuthenticationDefaults.Scheme,
            typeof(TokenAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);
        return handler;
    }

    private static DefaultHttpContext ContextWithHeader(string name, string value)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers[name] = value;
        return ctx;
    }

    private async Task<string> SeedUserTokenAsync(string capabilitiesJson, string userId = "u-admin")
    {
        string raw = TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(raw);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities)
            VALUES (@id, 'o1', @userId, @hash, @caps)
            """,
            new { id = Guid.NewGuid().ToString("N"), userId, hash, caps = capabilitiesJson });
        return raw;
    }

    private async Task<string> SeedServiceTokenAsync(string? capabilitiesJson)
    {
        string raw = TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(raw);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities)
            VALUES (@id, 'o1', @name, @hash, @caps)
            """,
            new { id = Guid.NewGuid().ToString("N"), name = $"ci-{Guid.NewGuid():N}", hash, caps = capabilitiesJson });
        return raw;
    }

    // ── ExtractRawToken branches ─────────────────────────────────────────────────

    [Fact]
    public async Task NoAuthHeaderAndNoApiKey_ReturnsNoResult()
    {
        var ctx = new DefaultHttpContext();
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.Equal(AuthenticateResult.NoResult().Succeeded, result.Succeeded);
        Assert.False(result.Failure is not null);
        Assert.True(result.None);
    }

    [Fact]
    public async Task EmptyApiKeyHeader_ReturnsNoResult()
    {
        // X-NuGet-ApiKey present-but-empty must be treated the same as missing — the handler
        // returns NoResult, not Fail, so other schemes (e.g. JWT) can still try.
        var ctx = ContextWithHeader("X-NuGet-ApiKey", "");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
    }

    [Fact]
    public async Task BasicAuthMissingColon_ReturnsNoResult()
    {
        // Base64 of "tokenwithoutcolon" decodes successfully but has no ':' separator. The
        // extractor returns null, so the handler reports NoResult.
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("tokenwithoutcolon"));
        var ctx = ContextWithHeader("Authorization", $"Basic {encoded}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
    }

    [Fact]
    public async Task BasicAuthMalformedBase64_ReturnsNoResult()
    {
        // FormatException catch path — '!!!' is not valid base64.
        var ctx = ContextWithHeader("Authorization", "Basic !!!not-base64!!!");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
    }

    [Fact]
    public async Task BearerWithUnknownToken_Fails()
    {
        var ctx = ContextWithHeader("Authorization", "Bearer not-a-real-token");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
        Assert.Equal("Invalid or expired API token.", result.Failure!.Message);
    }

    [Fact]
    public async Task XNuGetApiKey_WithKnownToken_Authenticates()
    {
        // The handler must fall through Authorization absence and check X-NuGet-ApiKey.
        string token = await SeedServiceTokenAsync("""["publish:nuget"]""");
        var ctx = ContextWithHeader("X-NuGet-ApiKey", token);
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Contains(result.Principal!.Claims, c => c.Type == "cap" && c.Value == "publish:nuget");
        Assert.Equal("ci", result.Principal!.FindFirst("role")!.Value);
    }

    [Fact]
    public async Task BasicAuth_StripsUsername_ResolvesToken()
    {
        // Username segment is ignored; everything after ':' is the token.
        string token = await SeedUserTokenAsync("""["read:metadata"]""");
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"someuser:{token}"));
        var ctx = ContextWithHeader("Authorization", $"Basic {encoded}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Equal("admin", result.Principal!.FindFirst("role")!.Value);
    }

    // ── LookupUserRoleAsync branches ────────────────────────────────────────────

    [Fact]
    public async Task UserToken_EmitsRoleFromDb_AndSubIsUserId()
    {
        string token = await SeedUserTokenAsync("""["read:metadata","read:artifact"]""");
        var ctx = ContextWithHeader("Authorization", $"Bearer {token}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        var principal = result.Principal!;
        Assert.Equal("admin", principal.FindFirst("role")!.Value);
        Assert.Equal("u-admin", principal.FindFirst(JwtRegisteredClaimNames.Sub)!.Value);
        Assert.Equal("o1", principal.FindFirst("org_id")!.Value);
        Assert.Equal("o1", principal.FindFirst("tid")!.Value);
        var caps = principal.FindAll("cap").Select(c => c.Value).ToHashSet();
        Assert.Contains("read:metadata", caps);
        Assert.Contains("read:artifact", caps);
    }

    [Fact]
    public async Task UserToken_MissingUserRow_FailsAuthentication()
    {
        // Token row references a user_id with no matching users row — resolution requires
        // a live, active owner in the token's tenant, so an orphaned token is rejected
        // outright (a removed user's credentials must not keep authenticating).
        // Microsoft.Data.Sqlite enables foreign_keys by default; toggle off just for the
        // orphan insert so we can craft this shape without re-enabling globally.
        string raw = TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(raw);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("PRAGMA foreign_keys = OFF");
            await conn.ExecuteAsync("""
                INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities)
                VALUES (@id, 'o1', 'u-does-not-exist', @hash, @caps)
                """,
                new { id = Guid.NewGuid().ToString("N"), hash, caps = """["read:metadata"]""" });
        }

        var ctx = ContextWithHeader("Authorization", $"Bearer {raw}");
        var handler = await CreateHandlerAsync(ctx);
        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Null(result.Principal);
    }

    [Fact]
    public async Task ServiceToken_GetsCiRole_AndSubIsTokenId()
    {
        // Service tokens carry no user_id; the handler emits role=ci and uses the token id as sub.
        string token = await SeedServiceTokenAsync("""["publish:npm"]""");
        var ctx = ContextWithHeader("Authorization", $"Bearer {token}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        var principal = result.Principal!;
        Assert.Equal("ci", principal.FindFirst("role")!.Value);
        // sub is the token row id (32-char Guid N format) — definitely not "u-admin".
        string sub = principal.FindFirst(JwtRegisteredClaimNames.Sub)!.Value;
        Assert.NotEqual("u-admin", sub);
        Assert.Equal(32, sub.Length);
    }

    // ── ResolveTokenCapabilities branches ───────────────────────────────────────

    [Fact]
    public async Task NullCapabilitiesColumn_EmitsNoCapClaims()
    {
        string token = await SeedServiceTokenAsync(capabilitiesJson: null);
        var ctx = ContextWithHeader("Authorization", $"Bearer {token}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Empty(result.Principal!.FindAll("cap"));
    }

    [Fact]
    public async Task WhitespaceCapabilitiesColumn_EmitsNoCapClaims()
    {
        string token = await SeedServiceTokenAsync(capabilitiesJson: "   ");
        var ctx = ContextWithHeader("Authorization", $"Bearer {token}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Empty(result.Principal!.FindAll("cap"));
    }

    [Fact]
    public async Task MalformedCapabilitiesJson_EmitsNoCapClaims()
    {
        // JsonException catch path — not a JSON array.
        string token = await SeedServiceTokenAsync(capabilitiesJson: "{not valid json}");
        var ctx = ContextWithHeader("Authorization", $"Bearer {token}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Empty(result.Principal!.FindAll("cap"));
    }

    [Fact]
    public async Task NullJsonLiteralCapabilities_EmitsNoCapClaims()
    {
        // JSON literal "null" deserializes to a null string[] reference — the handler must
        // treat that the same as an empty set rather than NRE.
        string token = await SeedServiceTokenAsync(capabilitiesJson: "null");
        var ctx = ContextWithHeader("Authorization", $"Bearer {token}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Empty(result.Principal!.FindAll("cap"));
    }

    [Fact]
    public async Task CapabilitiesArray_FiltersWhitespaceEntries()
    {
        // Defensive filter on the deserialized array — blank/whitespace entries are dropped.
        string token = await SeedServiceTokenAsync(capabilitiesJson: """["publish:npm","   ","","read:metadata"]""");
        var ctx = ContextWithHeader("Authorization", $"Bearer {token}");
        var handler = await CreateHandlerAsync(ctx);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        var caps = result.Principal!.FindAll("cap").Select(c => c.Value).ToList();
        Assert.Equal(2, caps.Count);
        Assert.Contains("publish:npm", caps);
        Assert.Contains("read:metadata", caps);
    }
}
