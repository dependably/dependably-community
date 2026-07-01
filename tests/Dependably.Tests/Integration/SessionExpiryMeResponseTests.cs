using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that GET /api/v1/auth/me surfaces a sessionExpiresAt field whose value is an
/// ISO-8601 timestamp matching the exp claim of the session JWT. The frontend session-expiry
/// watcher reads this field to arm its proactive timer.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SessionExpiryMeResponseTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public SessionExpiryMeResponseTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Primary assertion ─────────────────────────────────────────────────────

    [Fact]
    public async Task Me_ReturnsSessionExpiresAt_AsIso8601MatchingJwtExp()
    {
        string jwt = await _factory.CreateAdminJwt();

        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("sessionExpiresAt", out var sessionExpiresAtEl),
            "Response must contain 'sessionExpiresAt'.");

        string? sessionExpiresAt = sessionExpiresAtEl.GetString();
        Assert.NotNull(sessionExpiresAt);

        bool parsed = DateTimeOffset.TryParse(sessionExpiresAt, out var expiresAt);
        Assert.True(parsed, $"sessionExpiresAt '{sessionExpiresAt}' must be a valid ISO-8601 timestamp.");

        // Verify the value matches the exp claim carried in the JWT that was sent in the cookie.
        var jwtExp = ExtractJwtExpiry(jwt);
        Assert.Equal(jwtExp, expiresAt);
    }

    // ── Mixed partial-failure: missing cookie returns 401, no crash on exp parse ─

    [Fact]
    public async Task Me_WithMissingCookie_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Me_SessionExpiresAt_AbsentFromUnauthenticatedErrorResponse()
    {
        // RFC 7807 problem responses (401) must not include sessionExpiresAt — the field
        // is only meaningful in authenticated 200 responses.
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/v1/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("sessionExpiresAt", body, StringComparison.OrdinalIgnoreCase);
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private static DateTimeOffset ExtractJwtExpiry(string jwt)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        // JwtSecurityToken.ValidTo is UTC; wrap in a zero-offset DateTimeOffset so the
        // comparison against the ISO-8601 field (which carries +00:00) is exact.
        return new DateTimeOffset(token.ValidTo, TimeSpan.Zero);
    }
}

/// <summary>
/// Verifies that GET /api/v1/system/me surfaces a sessionExpiresAt field whose value is an
/// ISO-8601 timestamp matching the exp claim of the system-scoped session JWT.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemSessionExpiryMeResponseTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;

    public SystemSessionExpiryMeResponseTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task SystemMe_ReturnsSessionExpiresAt_AsIso8601MatchingJwtExp()
    {
        string jwt = await _factory.CreateSystemAdminJwt();

        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/me");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("sessionExpiresAt", out var sessionExpiresAtEl),
            "Response must contain 'sessionExpiresAt'.");

        string? sessionExpiresAt = sessionExpiresAtEl.GetString();
        Assert.NotNull(sessionExpiresAt);

        bool parsed = DateTimeOffset.TryParse(sessionExpiresAt, out var expiresAt);
        Assert.True(parsed, $"sessionExpiresAt '{sessionExpiresAt}' must be a valid ISO-8601 timestamp.");

        var jwtExp = ExtractJwtExpiry(jwt);
        Assert.Equal(jwtExp, expiresAt);
    }

    private static DateTimeOffset ExtractJwtExpiry(string jwt)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
        return new DateTimeOffset(token.ValidTo, TimeSpan.Zero);
    }
}
