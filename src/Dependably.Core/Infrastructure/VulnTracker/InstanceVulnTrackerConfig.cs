namespace Dependably.Infrastructure.VulnTracker;

/// <summary>
/// Resolves the one instance-level vulnerability-tracker connection from
/// <c>instance_settings</c> (the <c>vuln_tracker_*</c> keys), modeled on
/// <see cref="Dependably.Infrastructure.Mail.InstanceSmtpConfig"/>: a short TTL cache over the DB
/// read so the scan pass never round-trips per batch, with an explicit <see cref="Invalidate"/>
/// the apex write surfaces call so a save takes effect immediately rather than waiting out the
/// TTL.
///
/// <para>
/// DB-only — no env-var fallback and no seed. An unconfigured instance resolves to
/// <c>Enabled = false</c> / <c>Configured = false</c>, and every caller treats that as "the
/// feature does not exist" rather than as a degraded connection: no client is constructed, no
/// request is made, and the scan pass is byte-identical to its pre-overlay behaviour.
/// </para>
/// </summary>
public sealed class InstanceVulnTrackerConfig
{
    private const int CacheTtlSeconds = 5;

    private readonly Func<string, CancellationToken, Task<string?>> _instanceSettingReader;
    private readonly TimeProvider _time;

    private readonly SemaphoreSlim _lock = new(1, 1);
    private ResolvedVulnTrackerConfig? _cached;
    private DateTimeOffset _expiry;

    // Generation counter guarding against a fill that raced an Invalidate. A fill snapshots this
    // before reading instance_settings; Invalidate increments it. A fill whose snapshot no longer
    // matches when it goes to publish drops its (potentially stale) connection instead of
    // overwriting the invalidation — the same guard InstanceSmtpConfig carries.
    private long _generation;

    /// <summary>
    /// Constructs the resolver against an instance-setting reader (production wiring passes
    /// <c>OrgRepository.GetInstanceSettingAsync</c>, which already decrypts envelope-protected
    /// values; unit tests pass a stub dictionary reader so no real DB is needed).
    /// </summary>
    public InstanceVulnTrackerConfig(
        Func<string, CancellationToken, Task<string?>> instanceSettingReader,
        TimeProvider time)
    {
        _instanceSettingReader = instanceSettingReader;
        _time = time;
    }

    /// <summary>
    /// <paramref name="Enabled"/> is the operator's intent and <paramref name="Configured"/> is
    /// whether the stored connection could actually be dialed. They are kept apart so an operator
    /// can pause enrichment without discarding the base URL and credential, and so a half-filled
    /// row never reads as an intentional switch-off.
    /// </summary>
    public sealed record ResolvedVulnTrackerConfig(
        bool Enabled, VulnTrackerSettings Connection, bool Configured)
    {
        /// <summary>
        /// The single question every caller on the scan path asks: may this pass talk to the
        /// tracker at all? Intent and completeness both have to hold.
        /// </summary>
        public bool IsActive => Enabled && Configured;
    }

    public async Task<ResolvedVulnTrackerConfig> ResolveAsync(CancellationToken ct = default)
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
            // not take _lock) increments it, so a fill that read the pre-update connection cannot
            // publish it over the invalidation the operator just issued.
            long generation = Interlocked.Read(ref _generation);
            var resolved = await ResolveFromDbAsync(ct);

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
    /// <c>instance_settings</c>. Called by the apex system/instance vuln-tracker PUT endpoints
    /// immediately after a successful write. Bumps the generation so a fill racing this call
    /// cannot republish the pre-update connection.
    /// </summary>
    public void Invalidate()
    {
        Interlocked.Increment(ref _generation);
        _cached = null;
    }

    private async Task<ResolvedVulnTrackerConfig> ResolveFromDbAsync(CancellationToken ct)
    {
        string? enabledRaw = await _instanceSettingReader("vuln_tracker_enabled", ct);
        bool enabled = enabledRaw is "1" or "true";

        string? baseUrl = await _instanceSettingReader("vuln_tracker_base_url", ct);
        string? token = await _instanceSettingReader("vuln_tracker_token", ct);
        string? stalenessRaw = await _instanceSettingReader("vuln_tracker_max_staleness_hours", ct);
        string? batchRaw = await _instanceSettingReader("vuln_tracker_batch_size", ct);

        var connection = new VulnTrackerSettings(
            BaseUrl: string.IsNullOrWhiteSpace(baseUrl) ? null : baseUrl.Trim(),
            Token: string.IsNullOrEmpty(token) ? null : token,
            MaxStalenessHours: ParseBounded(
                stalenessRaw,
                VulnTrackerSettings.DefaultMaxStalenessHours,
                1,
                VulnTrackerSettings.MaxStalenessHoursCeiling),
            BatchSize: ParseBounded(
                batchRaw,
                VulnTrackerSettings.DefaultBatchSize,
                1,
                VulnTrackerSettings.MaxBatchSize));

        return new ResolvedVulnTrackerConfig(enabled, connection, connection.IsConfigured);
    }

    /// <summary>
    /// Parses a stored numeric setting, falling back to the default when it is absent,
    /// unparseable, or outside its bounds. Clamping rather than trusting matters because these
    /// two values bound a security decision and an outbound request size: a hand-edited row
    /// carrying <c>0</c> or a negative number would otherwise disable the staleness horizon
    /// entirely, or send an empty batch every pass.
    /// </summary>
    private static int ParseBounded(string? raw, int fallback, int min, int max)
        => int.TryParse(raw, out int parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}
