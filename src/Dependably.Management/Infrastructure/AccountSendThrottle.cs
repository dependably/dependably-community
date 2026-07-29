using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Fixed-window send budget for account-targeted transactional mail, keyed on the TARGET account
/// rather than on the caller's source IP.
///
/// <para>
/// The per-IP limiter on <c>forgot-password</c> collapses an IPv6 client to its /64, so one routed
/// prefix is one budget. That bounds the batch case but not the distributed one: an attacker with
/// addresses in many /64s can still mail-bomb a single mailbox, because nothing in the per-IP path
/// is keyed on who the mail is being sent TO. This throttle closes that: every request for a given
/// account shares one bucket regardless of where it came from. It is defense-in-depth alongside the
/// /64 limiter, not a replacement for it.
/// </para>
///
/// <para>
/// The key is <see cref="LoginService.HashLockoutKey"/> over (realm, tenant, email) — the same
/// pseudonym <c>login_attempts</c> uses — so the bucket is tenant-scoped and the plaintext address
/// is never stored. Callers consume the budget for every requested address, matched or not, so the
/// work done per request does not vary with whether the address resolves to an account; the flow
/// is enumeration-sensitive and its uniform 202 must stay uniform underneath as well.
/// </para>
///
/// <para>
/// Consequence worth stating plainly: saturating an account's bucket also stops that account's
/// legitimate owner from requesting a reset until the window rolls. That is inherent to any
/// per-account budget, and is why the window is short and the cap is well above real human use.
/// The counter keeps climbing past the cap within a window (nothing clamps it) so the increment
/// stays a single atomic statement; it resets the moment the window elapses, so an attacker can
/// never hold an account down for longer than one window past their last request.
/// </para>
/// </summary>
public sealed class AccountSendThrottle
{
    /// <summary>Purpose discriminator for the self-serve password-reset send.</summary>
    public const string PurposePasswordReset = "password_reset";

    private const int DefaultMaxPerWindow = 5;
    private const int DefaultWindowMinutes = 60;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly IConfiguration _config;
    private readonly ILogger<AccountSendThrottle> _logger;

    public AccountSendThrottle(
        IMetadataStore db, TimeProvider time, IConfiguration config, ILogger<AccountSendThrottle> logger)
    {
        _db = db;
        _time = time;
        _config = config;
        _logger = logger;
    }

    /// <summary>Sends permitted per account per window. <c>ACCOUNT_SEND_MAX_PER_WINDOW</c>, default 5.</summary>
    public int MaxPerWindow =>
        int.TryParse(_config["ACCOUNT_SEND_MAX_PER_WINDOW"], out int m) && m > 0 ? m : DefaultMaxPerWindow;

    /// <summary>Window length in minutes. <c>ACCOUNT_SEND_WINDOW_MINUTES</c>, default 60.</summary>
    public int WindowMinutes =>
        int.TryParse(_config["ACCOUNT_SEND_WINDOW_MINUTES"], out int w) && w > 0 ? w : DefaultWindowMinutes;

    /// <summary>
    /// Records one send attempt against <paramref name="accountKey"/> and reports whether it is
    /// within budget. The upsert is a single statement so concurrent requests for the same account
    /// serialize on the row rather than racing a read-then-write: each one observes a distinct
    /// post-increment count, so N concurrent requests can never all read "0 sent so far".
    /// </summary>
    /// <param name="accountKey">
    /// <see cref="LoginService.HashLockoutKey"/> over the target account — never a plaintext address.
    /// </param>
    /// <param name="purpose">Which send this budget bounds, e.g. <see cref="PurposePasswordReset"/>.</param>
    public async Task<bool> TryConsumeAsync(string accountKey, string purpose, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        string nowStr = now.ToUtcIso();
        // A window whose start is at or before this instant has fully elapsed and restarts at 1.
        string cutoff = now.AddMinutes(-WindowMinutes).ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);

        // account_send_throttle has no org/tenant column — the tenant is folded into the key by
        // HashLockoutKey, exactly as it is for login_attempts.
        // xtenant: keyed by a (realm, tenant, email) pseudonym that already encodes the tenant.
        long count = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            """
            INSERT INTO account_send_throttle (email_hash, purpose, window_start, send_count)
            VALUES (@accountKey, @purpose, @now, 1)
            ON CONFLICT(email_hash, purpose) DO UPDATE SET
                window_start = CASE WHEN account_send_throttle.window_start <= @cutoff
                                    THEN @now ELSE account_send_throttle.window_start END,
                send_count   = CASE WHEN account_send_throttle.window_start <= @cutoff
                                    THEN 1 ELSE account_send_throttle.send_count + 1 END
            RETURNING send_count
            """,
            new { accountKey, purpose, now = nowStr, cutoff },
            cancellationToken: ct));

        bool allowed = count <= MaxPerWindow;
        if (!allowed)
        {
            // Logged without the address or its pseudonym: the operator needs to know the control
            // fired, and a per-account identifier in an unbounded log stream is the thing this
            // whole path exists to avoid persisting.
            _logger.LogWarning(
                "Per-account send throttle rejected a {Purpose} send: {Count} attempts in the last {Window} minutes exceeds {Max}.",
                purpose, count, WindowMinutes, MaxPerWindow);
        }

        return allowed;
    }
}
