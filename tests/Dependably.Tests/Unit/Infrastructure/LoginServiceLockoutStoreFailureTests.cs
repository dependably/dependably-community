using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using StackExchange.Redis;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the fail-closed contract between <see cref="LoginService"/> and
/// <see cref="ILockoutStore"/>: when the lockout store cannot answer — the HA case is
/// <c>RedisLockoutStore</c>, which deliberately does not catch its Redis errors — the login
/// attempt aborts with that exception (the caller returns 500) rather than proceeding.
///
/// Both directions of the alternative are worse. Swallowing the error on the failure path
/// would return a normal 401 while the counter stayed put, turning a Redis outage into
/// unlimited password guessing with no signal. Swallowing it on the success path would issue a
/// session whose lockout state is unknown. These tests exist so a future refactor that adds a
/// catch has to change them deliberately.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LoginServiceLockoutStoreFailureTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly ILockoutStore _lockout = Substitute.For<ILockoutStore>();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public LoginServiceLockoutStoreFailureTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private static RedisConnectionException Down() =>
        new(ConnectionFailureType.SocketFailure, "lockout store unreachable");

    private LoginService NewSut() =>
        new(new LoginService.Dependencies(
            _fixture.Store,
            new OrgRepository(_fixture.Store),
            new SystemAdminRepository(_fixture.Store),
            _lockout,
            new AuditRepository(_fixture.Store),
            new ExternalIdentityRepository(_fixture.Store, _clock),
            Substitute.For<IAuditEmitter>(),
            _clock,
            Substitute.For<IMfaEnrollmentService>(),
            Substitute.For<ISystemMfaEnrollmentService>()));

    private async Task<(string OrgId, string Email, string UserId)> SeedUserAsync()
    {
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', 'unit-test-secret-min-32-chars-xxxxxx') ON CONFLICT(key) DO NOTHING");
        }

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(
            _fixture.Store, orgId, email, role: "member", password: "RealPass12345");
        return (orgId, email, userId);
    }

    private async Task<bool> HasSessionEvidenceAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        string? lastLogin = await conn.ExecuteScalarAsync<string?>(
            "SELECT last_login_at FROM users WHERE id = @id", new { id = userId });
        long successAudits = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'login.success' AND actor_id = @id",
            new { id = userId });
        return !string.IsNullOrEmpty(lastLogin) || successAudits > 0;
    }

    [Fact]
    public async Task GetAsync_Throws_AbortsBeforeTheCredentialCheck()
    {
        var (orgId, email, userId) = await SeedUserAsync();
        _lockout.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<(int, DateTimeOffset?)>>(_ => throw Down());

        await Assert.ThrowsAsync<RedisConnectionException>(
            () => NewSut().LoginTenantAsync(email, "RealPass12345", orgId));

        Assert.False(await HasSessionEvidenceAsync(userId));
    }

    [Fact]
    public async Task RecordFailureAsync_Throws_SurfacesInsteadOfReturningPlainInvalidCredentials()
    {
        // The dangerous direction: a swallowed failure write returns 401 while the counter
        // stays put, so the lockout budget never advances and guessing is unbounded.
        var (orgId, email, _) = await SeedUserAsync();
        _lockout.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<(int, DateTimeOffset?)>((0, null)));
        _lockout.RecordFailureAsync(
                Arg.Any<string>(), Arg.Any<int>(), Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>())
            .Returns<Task>(_ => throw Down());

        await Assert.ThrowsAsync<RedisConnectionException>(
            () => NewSut().LoginTenantAsync(email, "wrong-password", orgId));
    }

    [Fact]
    public async Task ClearAsync_Throws_IssuesNoSession()
    {
        // Correct password, but the counter reset could not be written: the attempt aborts
        // before CompleteTenantLoginAsync, so no JWT is minted and no login.success is recorded.
        var (orgId, email, userId) = await SeedUserAsync();
        _lockout.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<(int, DateTimeOffset?)>((0, null)));
        _lockout.ClearAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task>(_ => throw Down());

        await Assert.ThrowsAsync<RedisConnectionException>(
            () => NewSut().LoginTenantAsync(email, "RealPass12345", orgId));

        Assert.False(await HasSessionEvidenceAsync(userId));
    }

    [Fact]
    public async Task SystemRealm_GetAsync_Throws_AbortsTheAttempt()
    {
        // The system-admin realm shares the same lockout store and the same posture.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', 'unit-test-secret-min-32-chars-xxxxxx') ON CONFLICT(key) DO NOTHING");
        }

        _lockout.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<(int, DateTimeOffset?)>>(_ => throw Down());

        await Assert.ThrowsAsync<RedisConnectionException>(
            () => NewSut().LoginSystemAsync($"admin-{Guid.NewGuid():N}@x.test", "whatever"));
    }
}
