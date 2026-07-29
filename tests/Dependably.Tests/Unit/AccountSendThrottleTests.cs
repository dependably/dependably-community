using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for the per-account send budget that bounds account-targeted transactional mail
/// independently of source IP. The per-IP limiter and this budget are complementary controls: the
/// tests here drive <see cref="AccountSendThrottle"/> directly, with no HTTP in the picture at all,
/// so nothing an IP limiter does can account for the results.
///
/// <para>
/// Each assertion is paired with the twin that would fail if the budget were keyed too broadly:
/// a second account must keep its full budget while the first is exhausted, and a second purpose
/// must keep its own, or the control would be a global mail kill-switch rather than a per-account
/// one.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class AccountSendThrottleTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static AccountSendThrottle Build(
        IMetadataStore db, TimeProvider time, int maxPerWindow = 3, int windowMinutes = 60)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ACCOUNT_SEND_MAX_PER_WINDOW"] = maxPerWindow.ToString(),
                ["ACCOUNT_SEND_WINDOW_MINUTES"] = windowMinutes.ToString(),
            })
            .Build();

        return new AccountSendThrottle(db, time, config, NullLogger<AccountSendThrottle>.Instance);
    }

    private const string Purpose = AccountSendThrottle.PurposePasswordReset;

    [Fact]
    public async Task ConsumingUpToTheCap_IsAllowed_AndTheNextSendIsRefused()
    {
        var clock = TestTime.Frozen();
        var throttle = Build(_db, clock, maxPerWindow: 3);
        string key = LoginService.HashLockoutKey("tenant", "org-1", "victim@example.com");

        for (int i = 1; i <= 3; i++)
        {
            Assert.True(await throttle.TryConsumeAsync(key, Purpose), $"send {i} should be within budget");
        }

        Assert.False(await throttle.TryConsumeAsync(key, Purpose));
        Assert.False(await throttle.TryConsumeAsync(key, Purpose));
    }

    /// <summary>
    /// Adversarial twin: exhausting one account's budget must leave every other account's budget
    /// untouched. A shared bucket would turn this control into an instance-wide mail outage that
    /// any anonymous caller could trigger.
    /// </summary>
    [Fact]
    public async Task ExhaustingOneAccount_DoesNotThrottleAnother()
    {
        var clock = TestTime.Frozen();
        var throttle = Build(_db, clock, maxPerWindow: 2);
        string victim = LoginService.HashLockoutKey("tenant", "org-1", "victim@example.com");
        string bystander = LoginService.HashLockoutKey("tenant", "org-1", "bystander@example.com");

        Assert.True(await throttle.TryConsumeAsync(victim, Purpose));
        Assert.True(await throttle.TryConsumeAsync(victim, Purpose));
        Assert.False(await throttle.TryConsumeAsync(victim, Purpose));

        Assert.True(await throttle.TryConsumeAsync(bystander, Purpose));
        Assert.True(await throttle.TryConsumeAsync(bystander, Purpose));
    }

    /// <summary>
    /// The key folds in the tenant, so the same address in two orgs is two accounts. Without this,
    /// one tenant could throttle an identically-named account in another — a cross-tenant control.
    /// </summary>
    [Fact]
    public async Task SameAddressInTwoTenants_HasIndependentBudgets()
    {
        var clock = TestTime.Frozen();
        var throttle = Build(_db, clock, maxPerWindow: 1);
        string inOrgA = LoginService.HashLockoutKey("tenant", "org-a", "shared@example.com");
        string inOrgB = LoginService.HashLockoutKey("tenant", "org-b", "shared@example.com");

        Assert.True(await throttle.TryConsumeAsync(inOrgA, Purpose));
        Assert.False(await throttle.TryConsumeAsync(inOrgA, Purpose));

        Assert.True(await throttle.TryConsumeAsync(inOrgB, Purpose));
    }

    [Fact]
    public async Task DistinctPurposes_HaveIndependentBudgets()
    {
        var clock = TestTime.Frozen();
        var throttle = Build(_db, clock, maxPerWindow: 1);
        string key = LoginService.HashLockoutKey("tenant", "org-1", "victim@example.com");

        Assert.True(await throttle.TryConsumeAsync(key, Purpose));
        Assert.False(await throttle.TryConsumeAsync(key, Purpose));

        Assert.True(await throttle.TryConsumeAsync(key, "some_other_send"));
    }

    /// <summary>
    /// The budget restores when the window elapses — an attacker can hold an account's reset link
    /// down for at most one window past their last request, never indefinitely.
    /// </summary>
    [Fact]
    public async Task WhenTheWindowElapses_TheBudgetRestarts()
    {
        var clock = TestTime.Frozen();
        var throttle = Build(_db, clock, maxPerWindow: 1, windowMinutes: 60);
        string key = LoginService.HashLockoutKey("tenant", "org-1", "victim@example.com");

        Assert.True(await throttle.TryConsumeAsync(key, Purpose));
        Assert.False(await throttle.TryConsumeAsync(key, Purpose));

        // Still inside the window one minute short of its end.
        clock.Advance(TimeSpan.FromMinutes(59));
        Assert.False(await throttle.TryConsumeAsync(key, Purpose));

        // Past the window: the stored window_start is now at or before now - 60m, so it restarts.
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.True(await throttle.TryConsumeAsync(key, Purpose));
    }

    /// <summary>
    /// The persisted row carries only the pseudonym, the purpose, the window, and a count — no
    /// plaintext address. The whole point of keying on <c>HashLockoutKey</c> is that an operator
    /// reading this table learns nothing about who was targeted that they did not already know.
    /// </summary>
    [Fact]
    public async Task PersistedRow_CarriesOnlyThePseudonym_NeverThePlaintextAddress()
    {
        var clock = TestTime.Frozen();
        var throttle = Build(_db, clock);
        const string email = "victim@example.com";
        string key = LoginService.HashLockoutKey("tenant", "org-1", email);

        Assert.True(await throttle.TryConsumeAsync(key, Purpose));

        await using var conn = await _db.OpenAsync();
        var row = await conn.QuerySingleAsync<(string EmailHash, string Purpose, string WindowStart, long SendCount)>(
            "SELECT email_hash AS EmailHash, purpose AS Purpose, window_start AS WindowStart, send_count AS SendCount FROM account_send_throttle");

        Assert.Equal(key, row.EmailHash);
        Assert.Equal(Purpose, row.Purpose);
        Assert.Equal(1L, row.SendCount);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), row.WindowStart);
        Assert.DoesNotContain(email, row.EmailHash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Concurrent requests for one account must not all read "nothing sent yet". The increment is a
    /// single upsert precisely so the count is decided by the database, not by a read-then-write
    /// window that a burst can slip through.
    /// </summary>
    [Fact]
    public async Task ConcurrentConsumes_AllowNoMoreThanTheCap()
    {
        var clock = TestTime.Frozen();
        var throttle = Build(_db, clock, maxPerWindow: 3);
        string key = LoginService.HashLockoutKey("tenant", "org-1", "victim@example.com");

        bool[] results = await Task.WhenAll(
            Enumerable.Range(0, 12).Select(_ => throttle.TryConsumeAsync(key, Purpose)));

        Assert.Equal(3, results.Count(allowed => allowed));
    }
}
