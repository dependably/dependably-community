using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolves the live HS256 session-signing key from <c>instance_settings.jwt_secret</c> for the
/// JwtBearer scheme. Minting already reads the secret per login (<see cref="LoginService"/> via
/// <see cref="OrgRepository.GetInstanceSettingAsync"/>); this is the validation-side counterpart,
/// so a rotated secret takes effect without a process restart.
///
/// <para><b>Why a provider rather than a fixed key.</b> JwtBearer captures
/// <c>TokenValidationParameters</c> once when the options are built. A key copied in at startup
/// makes the validation side blind to any later change: rotating <c>jwt_secret</c> would mint
/// tokens under the new secret that the running process cannot validate. The scheme instead
/// points <c>IssuerSigningKeyResolver</c> at <see cref="CurrentKeys"/>, which reads this
/// provider's cache on every validation.</para>
///
/// <para><b>Exactly one key is ever trusted.</b> <see cref="CurrentKeys"/> returns the current
/// secret and nothing else — there is no old-key grace period. Rotation is an incident-response
/// action (the dominant trigger is a suspected leak, and a leaked <c>jwt_secret</c> forges any
/// session on the instance), so continuing to honour the previous key would keep the attacker's
/// forged tokens alive for the width of the window and defeat the rotation. The cost is
/// deliberate: rotation signs every session out, including the operator who triggered it. This
/// matches the immediate-invalidation posture ADR-auth-identity-hybrid sets for <c>tver</c>, which rejects
/// SecurityStampValidator precisely because of its poll lag.</para>
///
/// <para><b>Cache staleness is the one bounded window.</b> The replica that performs the rotation
/// reloads synchronously, so its own trust of the old key ends before the response is written.
/// Other replicas (HA: Postgres + Redis, multi-process) converge on the next
/// <see cref="RefreshIfStaleAsync"/> — at most <see cref="RefreshInterval"/> behind, defaulting to
/// one second and configurable via <c>Auth:JwtSigningKeyRefreshSeconds</c>. Set it to <c>0</c> to
/// re-read on every validation and close the window entirely at the cost of a DB round trip per
/// authenticated request.</para>
/// </summary>
public sealed class JwtSigningKeyProvider
{
    // Cross-replica convergence window after a rotation. Matches the OrgRepository settings-cache
    // TTL: at one refresh per second per replica the read is immaterial next to the login path's
    // own uncached read, while a rotation on one replica is honoured by every other within a
    // second.
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromSeconds(1);

    private readonly OrgRepository _orgs;
    private readonly TimeProvider _time;
    private readonly ILogger<JwtSigningKeyProvider> _logger;

    // Held across the DB read so a burst of requests arriving on an expired cache produces one
    // read, not one per request. Refreshers that find it taken skip and use the current key.
    private readonly SemaphoreSlim _reloadLock = new(1, 1);

    // Replaced wholesale on reload; readers get either the old array or the new one, never a torn
    // one. Empty until the first successful load, which fails validation closed.
    private volatile SecurityKey[] _keys = [];

    private long _loadedAtTicks;

    public JwtSigningKeyProvider(
        OrgRepository orgs,
        TimeProvider time,
        IConfiguration config,
        ILogger<JwtSigningKeyProvider> logger)
    {
        _orgs = orgs;
        _time = time;
        _logger = logger;
        RefreshInterval =
            double.TryParse(
                config["Auth:JwtSigningKeyRefreshSeconds"],
                System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture,
                out double seconds) && seconds >= 0
                ? TimeSpan.FromSeconds(seconds)
                : DefaultRefreshInterval;
    }

    /// <summary>
    /// How far behind a rotation performed on another replica this one may be. Zero re-reads the
    /// secret on every validation.
    /// </summary>
    public TimeSpan RefreshInterval { get; }

    /// <summary>
    /// The keys the JwtBearer resolver trusts right now — the current secret alone, or empty
    /// before the first successful load (validation then fails closed rather than falling back to
    /// a guessable placeholder).
    /// </summary>
    public IReadOnlyList<SecurityKey> CurrentKeys => _keys;

    /// <summary>
    /// Re-reads <c>jwt_secret</c> and replaces the cache. Returns false when no <c>jwt_secret</c>
    /// row exists (first boot has not completed) — the caller decides whether that is fatal.
    /// Callers that have just written a new secret use this to make it effective immediately on
    /// this replica.
    /// </summary>
    public async Task<bool> TryReloadAsync(CancellationToken ct = default)
    {
        await _reloadLock.WaitAsync(ct);
        try
        {
            return await LoadAsync(ct);
        }
        finally
        {
            _reloadLock.Release();
        }
    }

    /// <summary>
    /// Re-reads the secret when the cache has outlived <see cref="RefreshInterval"/>. Called on the
    /// JwtBearer message-received hook so a rotation on another replica converges without a
    /// restart. A failed read keeps the last known-good key and retries on the next request: the
    /// alternative — dropping the key — would sign every session out on a transient DB blip, and
    /// a DB this replica cannot read is also one no rotation could have been recorded through.
    /// </summary>
    public async Task RefreshIfStaleAsync(CancellationToken ct = default)
    {
        if (!IsStale())
        {
            return;
        }

        // Non-blocking: whoever holds the lock is already doing this read.
        if (!await _reloadLock.WaitAsync(0, ct))
        {
            return;
        }

        try
        {
            if (IsStale())
            {
                await LoadAsync(ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "JWT signing key refresh failed ({ExceptionType}: {Message}); continuing with the "
                + "previously loaded key. A rotation performed on another replica will not be "
                + "honoured here until a refresh succeeds.",
                ex.GetType().Name, ex.Message);
        }
        finally
        {
            _reloadLock.Release();
        }
    }

    private bool IsStale() =>
        _time.GetUtcNow().UtcTicks - Interlocked.Read(ref _loadedAtTicks) >= RefreshInterval.Ticks;

    // Caller holds _reloadLock.
    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        string? secret = await _orgs.GetInstanceSettingAsync("jwt_secret", ct);
        if (secret is null)
        {
            return false;
        }

        _keys = [new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))];
        Interlocked.Exchange(ref _loadedAtTicks, _time.GetUtcNow().UtcTicks);
        return true;
    }
}
