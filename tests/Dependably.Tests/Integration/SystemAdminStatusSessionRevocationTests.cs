using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end session revocation when one system admin locks, disables, re-activates or deletes
/// another, through the real JwtBearer pipeline (signature, <c>tver</c> check, token-version
/// cache). Each test first proves the target's session works, which also fills the token-version
/// cache the way a live session does, so a revocation that leaves the cached version in place
/// shows up as a 200 rather than passing by accident.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemAdminStatusSessionRevocationTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    // test-only placeholder password
    private const string TargetPassword = "TargetAdminPass1!";

    private readonly DependablyMultiFactory _factory;

    public SystemAdminStatusSessionRevocationTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string AdminId, string Email, HttpClient Session)> CreateTargetAdminAsync()
    {
        var admins = _factory.Services.GetRequiredService<SystemAdminRepository>();
        string email = $"target-{Guid.NewGuid():N}@example.com";
        string id = await admins.CreateAsync(
            email, BCrypt.Net.BCrypt.HashPassword(TargetPassword, workFactor: 4), mustChangePassword: false);
        var session = SessionClient(await _factory.CreateSystemAdminJwtForUser(id));
        return (id, email, session);
    }

    private HttpClient SessionClient(string jwt)
    {
        var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static Task<HttpResponseMessage> CallSystemApiAsync(HttpClient session) =>
        session.GetAsync("/api/v1/system/admins");

    private static async Task SetStatusAsync(HttpClient operatorClient, string adminId, string status)
    {
        var resp = await operatorClient.PatchAsJsonAsync(
            $"/api/v1/system/admins/{adminId}/account-status", new { accountStatus = status });
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("locked")]
    public async Task StatusChangeToNonActive_RejectsTheTargetsExistingSession(string status)
    {
        using var operatorClient = await _factory.CreateSystemAdminClient();
        var (adminId, _, session) = await CreateTargetAdminAsync();
        using (session)
        {
            Assert.Equal(HttpStatusCode.OK, (await CallSystemApiAsync(session)).StatusCode);

            await SetStatusAsync(operatorClient, adminId, status);

            Assert.Equal(HttpStatusCode.Unauthorized, (await CallSystemApiAsync(session)).StatusCode);
        }
    }

    [Fact]
    public async Task StatusChange_LeavesOtherAdminsSessionsAlone()
    {
        // Mixed scenario: disabling one admin must not touch a bystander's session.
        using var operatorClient = await _factory.CreateSystemAdminClient();
        var (targetId, _, target) = await CreateTargetAdminAsync();
        var (_, _, bystander) = await CreateTargetAdminAsync();
        using (target)
        using (bystander)
        {
            Assert.Equal(HttpStatusCode.OK, (await CallSystemApiAsync(bystander)).StatusCode);

            await SetStatusAsync(operatorClient, targetId, "disabled");

            Assert.Equal(HttpStatusCode.Unauthorized, (await CallSystemApiAsync(target)).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await CallSystemApiAsync(bystander)).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await CallSystemApiAsync(operatorClient)).StatusCode);
        }
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("locked")]
    public async Task Reactivation_DoesNotReviveTheOldSession_ButAFreshLoginWorks(string status)
    {
        using var operatorClient = await _factory.CreateSystemAdminClient();
        var (adminId, email, session) = await CreateTargetAdminAsync();
        using (session)
        {
            Assert.Equal(HttpStatusCode.OK, (await CallSystemApiAsync(session)).StatusCode);

            await SetStatusAsync(operatorClient, adminId, status);
            await SetStatusAsync(operatorClient, adminId, "active");

            Assert.Equal(HttpStatusCode.Unauthorized, (await CallSystemApiAsync(session)).StatusCode);
        }

        using var apex = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
        });
        apex.DefaultRequestHeaders.Host = DependablyMultiFactory.ApexHost;
        var login = await apex.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TargetPassword });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        string sessionCookie = login.Headers.GetValues("Set-Cookie")
            .Select(c => c.Split(';')[0])
            .Single(c => c.StartsWith("dependably_session=", StringComparison.Ordinal));
        using var fresh = new HttpRequestMessage(HttpMethod.Get, "/api/v1/system/admins");
        fresh.Headers.Add("Cookie", sessionCookie);
        Assert.Equal(HttpStatusCode.OK, (await apex.SendAsync(fresh)).StatusCode);
    }

    [Fact]
    public async Task DeleteAfterDisable_RejectsTheSession_EvenWithItsVersionStillCached()
    {
        using var operatorClient = await _factory.CreateSystemAdminClient();
        var (adminId, _, session) = await CreateTargetAdminAsync();
        using (session)
        {
            // Fills the token-version cache for the target.
            Assert.Equal(HttpStatusCode.OK, (await CallSystemApiAsync(session)).StatusCode);

            // Disable through a write that neither bumps nor evicts, so the cached entry from the
            // request above is still live when the delete runs. Only the delete's own eviction
            // can end the session before the cache TTL.
            await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
            {
                await conn.ExecuteAsync(
                    "UPDATE system_admins SET account_status = 'disabled' WHERE id = @adminId", new { adminId });
            }

            var delete = await operatorClient.DeleteAsync($"/api/v1/system/admins/{adminId}");
            Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

            Assert.Equal(HttpStatusCode.Unauthorized, (await CallSystemApiAsync(session)).StatusCode);
        }
    }

    [Fact]
    public async Task DisableThenDelete_ThroughTheApi_RejectsTheSession()
    {
        using var operatorClient = await _factory.CreateSystemAdminClient();
        var (adminId, _, session) = await CreateTargetAdminAsync();
        using (session)
        {
            Assert.Equal(HttpStatusCode.OK, (await CallSystemApiAsync(session)).StatusCode);

            await SetStatusAsync(operatorClient, adminId, "disabled");
            var delete = await operatorClient.DeleteAsync($"/api/v1/system/admins/{adminId}");
            Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

            Assert.Equal(HttpStatusCode.Unauthorized, (await CallSystemApiAsync(session)).StatusCode);
        }
    }
}
