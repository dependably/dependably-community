namespace Dependably.Storage;

/// <summary>
/// Instance-level configuration for presigned blob reads.
///
/// <para>
/// Default off. Handing a client a signed URL moves the bytes off the application tier, which is
/// the point — but it also means the granted read is replayable, by whoever holds the URL, until
/// it expires, and the registry cannot observe it. Deployments that require every artefact byte to
/// leave through an authenticated request the registry can account for keep this off and lose
/// nothing but throughput.
/// </para>
/// </summary>
public sealed class PresignedReadOptions
{
    /// <summary>Environment/configuration key that turns presigned reads on.</summary>
    public const string EnabledKey = "STORAGE_PRESIGNED_READS";

    /// <summary>Environment/configuration key holding the URL lifetime in seconds.</summary>
    public const string TtlSecondsKey = "STORAGE_PRESIGNED_READ_TTL_SECONDS";

    /// <summary>Lifetime used when the operator sets no explicit TTL.</summary>
    public const int DefaultTtlSeconds = 60;

    /// <summary>
    /// Floor on the configured lifetime. A URL shorter than this races the client's own
    /// redirect follow on a slow link and turns a working pull into a 403 from the object store.
    /// </summary>
    public const int MinTtlSeconds = 5;

    /// <summary>
    /// Ceiling on the configured lifetime. The URL is a bearer credential for one blob, so the
    /// window in which a leaked one is useful is capped regardless of what is configured.
    /// </summary>
    public const int MaxTtlSeconds = 900;

    /// <summary>Whether digest-addressed reads may be answered with a redirect.</summary>
    public bool Enabled { get; init; }

    /// <summary>How long a minted URL stays valid. Clamped to [Min,Max]TtlSeconds on binding.</summary>
    public TimeSpan Ttl { get; init; } = TimeSpan.FromSeconds(DefaultTtlSeconds);

    /// <summary>
    /// Binds from configuration. An unset, empty, or unparseable enable flag leaves the feature
    /// off; an unset or unparseable TTL falls back to the default, and any parsed TTL is clamped
    /// rather than rejected so a fat-fingered value degrades to a safe window instead of failing
    /// boot.
    /// </summary>
    public static PresignedReadOptions FromConfiguration(IConfiguration config)
    {
        bool enabled = bool.TryParse(config[EnabledKey], out bool parsed) && parsed;
        int seconds = int.TryParse(config[TtlSecondsKey], out int ttl) ? ttl : DefaultTtlSeconds;
        seconds = Math.Clamp(seconds, MinTtlSeconds, MaxTtlSeconds);
        return new PresignedReadOptions { Enabled = enabled, Ttl = TimeSpan.FromSeconds(seconds) };
    }
}
