using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// A rejected second factor is one login failure: one <c>login.failure</c> audit row carrying
/// the reason, one LoginFailure event, and one charge against the lockout budget. Operators count
/// failed sign-ins from the audit log, so a second row for the same attempt — previously a bare
/// row whose action was the event-type name <c>auth.login.failure</c> — double-counts every wrong
/// code. Each test gets its own database so the counts are exact rather than "at least one".
/// </summary>
[Trait("Category", "Unit")]
public sealed class LoginServiceSecondFactorAuditTests : IAsyncLifetime
{
    private const string SourceIp = "203.0.113.7";

    private readonly InMemoryDbFixture _db = new();
    private readonly IAuditEmitter _emitter = Substitute.For<IAuditEmitter>();
    private readonly IMfaEnrollmentService _tenantMfa = Substitute.For<IMfaEnrollmentService>();
    private readonly ISystemMfaEnrollmentService _systemMfa = Substitute.For<ISystemMfaEnrollmentService>();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await _db.InitializeAsync();
        await using var conn = await _db.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', 'unit-test-secret-min-32-chars-xxxxxx') ON CONFLICT(key) DO NOTHING");
    }

    public Task DisposeAsync() => _db.DisposeAsync();

    private LoginService NewSut() =>
        new(new LoginService.Dependencies(
            _db.Store,
            new OrgRepository(_db.Store),
            new SystemAdminRepository(_db.Store),
            new SqliteLockoutStore(_db.Store, _clock),
            new AuditRepository(_db.Store),
            new ExternalIdentityRepository(_db.Store, _clock),
            _emitter,
            _clock,
            _tenantMfa,
            _systemMfa));

    private sealed record AuditRow(string Action, string? OrgId, string Scope, string? Detail);

    private async Task<List<AuditRow>> ReadLoginFailureRowsAsync()
    {
        await using var conn = await _db.Store.OpenAsync();
        var rows = await conn.QueryAsync<AuditRow>(
            """
            SELECT action AS Action, org_id AS OrgId, scope AS Scope, detail AS Detail
            FROM audit_log
            WHERE action IN ('login.failure', 'auth.login.failure')
            ORDER BY created_at, id
            """);
        return rows.ToList();
    }

    private async Task<int> ReadFailedCountAsync(string lockoutKey)
    {
        var (failedCount, _) = await new SqliteLockoutStore(_db.Store, _clock).GetAsync(lockoutKey, CancellationToken.None);
        return failedCount;
    }

    private int LoginFailureEventCount() =>
        _emitter.ReceivedCalls().Count(c =>
            c.GetMethodInfo().Name == nameof(IAuditEmitter.EmitAsync)
            && (string)c.GetArguments()[0]! == AuthEvents.TypeLoginFailure);

    private static void AssertMfaInvalidRow(AuditRow row, string realm)
    {
        Assert.Equal("login.failure", row.Action);
        Assert.NotNull(row.Detail);
        Assert.Contains("\"reason\":\"mfa_invalid\"", row.Detail, StringComparison.Ordinal);
        Assert.Contains($"\"realm\":\"{realm}\"", row.Detail, StringComparison.Ordinal);
    }

    private async Task<(string UserId, string OrgId, string LockoutKey, string EmailHash)> SeedTenantUserAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_db.Store, $"o-{Guid.NewGuid():N}");
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_db.Store, orgId, email, password: "Correct12345");
        return (userId, orgId, LoginService.HashLockoutKey("tenant", orgId, email), LoginService.HashEmail(email));
    }

    private async Task<(string AdminId, string Email, string LockoutKey, string EmailHash)> SeedSystemAdminAsync()
    {
        string email = $"sys-{Guid.NewGuid():N}@example.com";
        string adminId = await SystemAdminSeeder.InsertAsync(_db.Store, email, "SysPass12345");
        return (adminId, email, LoginService.HashLockoutKey("system", null, email), LoginService.HashEmail(email));
    }

    [Fact]
    public async Task TenantWrongCode_WritesExactlyOneLoginFailureRowWithReason_AndOneEvent()
    {
        var (userId, orgId, lockoutKey, emailHash) = await SeedTenantUserAsync();
        _tenantMfa.VerifyTotpAsync(userId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);
        _tenantMfa.RedeemRecoveryCodeAsync(userId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);

        var result = await NewSut().CompleteTenantSecondFactorAsync(
            userId, orgId, "member", tokenVersion: 1,
            new LoginService.SecondFactorContext(lockoutKey, emailHash, "000000", SourceIp));

        Assert.Null(result.Token);
        var rows = await ReadLoginFailureRowsAsync();
        var row = Assert.Single(rows);
        AssertMfaInvalidRow(row, "tenant");
        Assert.Equal(orgId, row.OrgId);
        Assert.Equal("tenant", row.Scope);
        Assert.Equal(1, LoginFailureEventCount());
        Assert.Equal(1, await ReadFailedCountAsync(lockoutKey));
    }

    [Fact]
    public async Task SystemWrongCode_WritesExactlyOneLoginFailureRowWithReason_AndOneEvent()
    {
        var (adminId, email, lockoutKey, emailHash) = await SeedSystemAdminAsync();
        _systemMfa.VerifyTotpAsync(adminId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);
        _systemMfa.RedeemRecoveryCodeAsync(adminId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);

        var result = await NewSut().CompleteSystemSecondFactorAsync(
            adminId, email, tokenVersion: 1,
            new LoginService.SecondFactorContext(lockoutKey, emailHash, "000000", SourceIp));

        Assert.Null(result.Token);
        var rows = await ReadLoginFailureRowsAsync();
        var row = Assert.Single(rows);
        AssertMfaInvalidRow(row, "system");
        Assert.Null(row.OrgId);
        Assert.Equal("system", row.Scope);
        Assert.Equal(1, LoginFailureEventCount());
        Assert.Equal(1, await ReadFailedCountAsync(lockoutKey));
    }

    /// <summary>
    /// Mixed sequence across both realms: a wrong code in each, then a correct code in the
    /// tenant realm. The failures are counted once each, the success writes no failure row, and
    /// no row in either realm is named after the event type.
    /// </summary>
    [Fact]
    public async Task MixedRealms_WrongCodesThenSuccess_OneRowAndOneEventPerFailure()
    {
        var (userId, orgId, tenantKey, tenantHash) = await SeedTenantUserAsync();
        var (adminId, email, systemKey, systemHash) = await SeedSystemAdminAsync();
        _tenantMfa.VerifyTotpAsync(userId, "000000", Arg.Any<CancellationToken>()).Returns(false);
        _tenantMfa.VerifyTotpAsync(userId, "123456", Arg.Any<CancellationToken>()).Returns(true);
        _tenantMfa.RedeemRecoveryCodeAsync(userId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);
        _systemMfa.VerifyTotpAsync(adminId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);
        _systemMfa.RedeemRecoveryCodeAsync(adminId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);
        var sut = NewSut();

        var tenantFail = await sut.CompleteTenantSecondFactorAsync(
            userId, orgId, "member", 1, new LoginService.SecondFactorContext(tenantKey, tenantHash, "000000", SourceIp));
        var systemFail = await sut.CompleteSystemSecondFactorAsync(
            adminId, email, 1, new LoginService.SecondFactorContext(systemKey, systemHash, "000000", SourceIp));
        var tenantOk = await sut.CompleteTenantSecondFactorAsync(
            userId, orgId, "member", 1, new LoginService.SecondFactorContext(tenantKey, tenantHash, "123456", SourceIp));

        Assert.Null(tenantFail.Token);
        Assert.Null(systemFail.Token);
        Assert.NotNull(tenantOk.Token);

        var rows = await ReadLoginFailureRowsAsync();
        Assert.Equal(2, rows.Count);
        Assert.DoesNotContain(rows, r => r.Action == AuthEvents.TypeLoginFailure);
        AssertMfaInvalidRow(Assert.Single(rows, r => r.Scope == "tenant"), "tenant");
        AssertMfaInvalidRow(Assert.Single(rows, r => r.Scope == "system"), "system");
        Assert.Equal(2, LoginFailureEventCount());

        // The tenant success clears its own counter; the system failure stays charged.
        Assert.Equal(0, await ReadFailedCountAsync(tenantKey));
        Assert.Equal(1, await ReadFailedCountAsync(systemKey));
    }
}
