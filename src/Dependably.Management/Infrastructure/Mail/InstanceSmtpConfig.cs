namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Resolves the instance-level SMTP transport from <c>instance_settings</c> (the
/// <c>smtp_*</c> keys), modeled on <see cref="Dependably.Security.MetricsAccessConfig"/>: a
/// 5-second TTL cache over the DB read so the hot invite/alert send path never round-trips per
/// message, with an explicit <see cref="Invalidate"/> the PUT endpoints call so a save takes
/// effect immediately rather than waiting out the TTL.
///
/// DB-only — there is no env-var fallback or seed. An unconfigured instance resolves to
/// <c>Configured = false</c> and every send caller treats that as a no-op / 400, never a
/// silent fallback to some other transport.
/// </summary>
public sealed class InstanceSmtpConfig
{
    private const int CacheTtlSeconds = 5;

    private readonly Func<string, CancellationToken, Task<string?>> _instanceSettingReader;
    private readonly TimeProvider _time;

    private readonly SemaphoreSlim _lock = new(1, 1);
    private ResolvedSmtpConfig? _cached;
    private DateTimeOffset _expiry;

    // Generation counter guarding against a fill that raced an Invalidate. A fill snapshots this
    // before reading instance_settings; Invalidate increments it. A fill whose snapshot no longer
    // matches when it goes to publish drops its (potentially stale) transport instead of
    // overwriting the invalidation — mirroring UserTokenVersionStore's generation-token guard.
    private long _generation;

    /// <summary>
    /// Constructs the resolver against an instance-setting reader (the production wiring passes
    /// <c>OrgRepository.GetInstanceSettingAsync</c>, which already decrypts envelope-protected
    /// values; unit tests pass a stub dictionary reader so no real DB is needed).
    /// </summary>
    public InstanceSmtpConfig(
        Func<string, CancellationToken, Task<string?>> instanceSettingReader,
        TimeProvider time)
    {
        _instanceSettingReader = instanceSettingReader;
        _time = time;
    }

    public sealed record ResolvedSmtpConfig(bool Enabled, SmtpTransportSettings Transport, bool Configured);

    public async Task<ResolvedSmtpConfig> ResolveAsync(CancellationToken ct = default)
    {
        if (_cached is not null && _time.GetUtcNow() < _expiry)
        {
            return _cached;
        }

        await _lock.WaitAsync(ct);
        try
        {
            if (_cached is not null && _time.GetUtcNow() < _expiry)
            {
                return _cached;
            }

            // Snapshot the generation BEFORE reading the DB. A concurrent Invalidate (which does
            // not take _lock) increments it, so a fill that read pre-update credentials cannot
            // publish them over the invalidation the operator just issued.
            long generation = Interlocked.Read(ref _generation);
            var resolved = await ResolveFromDbAsync(ct);

            // Publish only if no Invalidate fired during the read; the second check closes the
            // narrow window where an Invalidate lands between the publish and this return.
            if (Interlocked.Read(ref _generation) == generation)
            {
                _cached = resolved;
                _expiry = _time.GetUtcNow().AddSeconds(CacheTtlSeconds);
                if (Interlocked.Read(ref _generation) != generation)
                {
                    _cached = null;
                }
            }

            return resolved;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Invalidates the cache so the next <see cref="ResolveAsync"/> re-reads from
    /// <c>instance_settings</c>. Called by the system/instance email-config PUT endpoints
    /// immediately after a successful write. Bumps the generation so a fill racing this call
    /// cannot republish the pre-update transport.
    /// </summary>
    public void Invalidate()
    {
        Interlocked.Increment(ref _generation);
        _cached = null;
    }

    private async Task<ResolvedSmtpConfig> ResolveFromDbAsync(CancellationToken ct)
    {
        string? enabledRaw = await _instanceSettingReader("smtp_enabled", ct);
        bool enabled = enabledRaw is "1" or "true";

        string? host = await _instanceSettingReader("smtp_host", ct);
        string? portRaw = await _instanceSettingReader("smtp_port", ct);
        int port = int.TryParse(portRaw, out int p) ? p : SmtpTransportSettings.DefaultPort;
        string? security = await _instanceSettingReader("smtp_security", ct);
        string? username = await _instanceSettingReader("smtp_username", ct);
        string? password = await _instanceSettingReader("smtp_password", ct);
        string? fromAddress = await _instanceSettingReader("smtp_from_address", ct);

        var transport = new SmtpTransportSettings(
            Host: host,
            Port: port,
            Security: string.IsNullOrWhiteSpace(security) ? SmtpTransportSettings.DefaultSecurity : security,
            Username: username,
            Password: password,
            FromAddress: fromAddress);

        return new ResolvedSmtpConfig(enabled, transport, transport.IsConfigured);
    }
}
