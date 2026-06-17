using System.Net;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Exercises the LoginService failure + lockout paths through the public /auth/login endpoint.
/// The success path is already covered by PasswordChangeTests' indirect token flow; this file
/// fills the gap on lockout, account_status rejection, and audit emission on failure.
/// </summary>
[Trait("Category", "Integration")]
public sealed class LoginServiceLockoutTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public LoginServiceLockoutTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    [Fact]
    public async Task Login_MissingEmail_Returns400()
    {
        using var c = _factory.CreateClient();
        var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new { email = "", password = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Login_WrongPassword_Returns401_AndAuditsFailure()
    {
        string email = $"loginfail-{Guid.NewGuid():N}@example.com";
        await _factory.CreateUser(email, "RealPassword12345");

        using var c = _factory.CreateClient();
        var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "wrong-password" });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        // login.failure landed in audit_log.
        await using var conn = await Db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'login.failure'");
        Assert.True(count >= 1);
    }

    [Fact]
    public async Task Login_UnknownEmail_Returns401_AndDoesNotRevealUserExistence()
    {
        using var c = _factory.CreateClient();
        var resp = await c.PostAsJsonAsync("/api/v1/auth/login",
            new { email = $"ghost-{Guid.NewGuid():N}@example.com", password = "anything" });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        // Detail must NOT carry a user-existence oracle.
        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("not found", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unknown", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_DisabledAccount_RejectedAsInvalidCredentials()
    {
        string email = $"disabled-{Guid.NewGuid():N}@example.com";
        string userId = await _factory.CreateUser(email, "RealPassword12345");

        await using (var conn = await Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE users SET account_status = 'disabled' WHERE id = @id",
                new { id = userId });
        }

        using var c = _factory.CreateClient();
        var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "RealPassword12345" });

        // The service deliberately returns 401 with the same generic message — disabled accounts
        // must not be distinguishable from wrong-credentials by external observers.
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Login_TenthFailure_LocksAccount_AndSubsequentLoginReturns429()
    {
        // The lockout threshold is 10 failed attempts within the lockout window.
        // Driving via the endpoint here keeps the full pipeline (audit + emitter) in scope.
        string email = $"lockout-{Guid.NewGuid():N}@example.com";
        await _factory.CreateUser(email, "RealPassword12345");

        using var c = _factory.CreateClient();

        for (int i = 0; i < 10; i++)
        {
            var r = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "wrong" });
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        }

        // Lockout row stamped with locked_until.
        // The key stored in login_attempts is the realm+tenant scoped lockout key, not the
        // bare email hash. Resolve the tenant the same way CreateUser does (default org).
        string tenantId = await ResolveDefaultTenantIdAsync();
        string lockoutKey = LoginService.HashLockoutKey("tenant", tenantId, email);
        await using (var conn = await Db.OpenAsync())
        {
            string? lockedUntil = await conn.ExecuteScalarAsync<string?>(
                "SELECT locked_until FROM login_attempts WHERE email_hash = @key LIMIT 1",
                new { key = lockoutKey });
            Assert.False(string.IsNullOrEmpty(lockedUntil));
        }

        // The next call — whether credentials are right or wrong — is rejected with 429
        // (the service short-circuits before checking the password).
        var locked = await c.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "RealPassword12345" });
        Assert.Equal((HttpStatusCode)429, locked.StatusCode);
        Assert.True(locked.Headers.Contains("Retry-After"));

        // lockout.triggered audited.
        await using var verify = await Db.OpenAsync();
        long lockoutAudit = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'lockout.triggered'");
        Assert.True(lockoutAudit >= 1);
    }

    private async Task<string> ResolveDefaultTenantIdAsync()
    {
        await using var conn = await Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }
}
