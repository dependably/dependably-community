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
///
/// <para>
/// Turning the feature on redirects only the ecosystems named in
/// <see cref="EcosystemsKey"/>, which defaults to <c>oci</c> alone. An operator who enabled
/// presigned reads for container pulls does not start redirecting every npm tarball on upgrade,
/// and the list is also the escape hatch for a client found to mishandle a redirect.
/// </para>
/// </summary>
public sealed class PresignedReadOptions
{
    /// <summary>Environment/configuration key that turns presigned reads on.</summary>
    public const string EnabledKey = "STORAGE_PRESIGNED_READS";

    /// <summary>Environment/configuration key holding the URL lifetime in seconds.</summary>
    public const string TtlSecondsKey = "STORAGE_PRESIGNED_READ_TTL_SECONDS";

    /// <summary>
    /// Environment/configuration key holding the comma-separated list of ecosystems whose
    /// artefact downloads may be answered with a redirect.
    /// </summary>
    public const string EcosystemsKey = "STORAGE_PRESIGNED_READ_ECOSYSTEMS";

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

    /// <summary>
    /// Every ecosystem whose artefact serve path calls the redirect seam, spelled as the metered
    /// <c>source</c> of its downloads. A configured name outside this set is a typo, and a typo
    /// here would silently leave an ecosystem streaming, so binding refuses it.
    /// </summary>
    public static readonly IReadOnlySet<string> RedirectableEcosystems = new HashSet<string>(StringComparer.Ordinal)
    {
        "apk", "cargo", "go", "hex", "maven", "npm", "nuget", "oci", "pypi", "rpm", "terraform",
    };

    /// <summary>The ecosystems that redirect when the operator names none.</summary>
    public static readonly IReadOnlySet<string> DefaultEcosystems = new HashSet<string>(StringComparer.Ordinal) { "oci" };

    /// <summary>Whether artefact reads may be answered with a redirect.</summary>
    public bool Enabled { get; init; }

    /// <summary>How long a minted URL stays valid. Clamped to [Min,Max]TtlSeconds on binding.</summary>
    public TimeSpan Ttl { get; init; } = TimeSpan.FromSeconds(DefaultTtlSeconds);

    /// <summary>The ecosystems whose artefact downloads may redirect.</summary>
    public IReadOnlySet<string> Ecosystems { get; init; } = DefaultEcosystems;

    /// <summary>Which signer mints URLs. Defaults to the object store's own.</summary>
    public PresignedReadSigner Signer { get; init; } = PresignedReadSigner.Store;

    /// <summary>The CloudFront settings; set exactly when <see cref="Signer"/> is <see cref="PresignedReadSigner.CloudFront"/>.</summary>
    public CloudFrontSignerOptions? CloudFront { get; init; }

    /// <summary>True when <paramref name="ecosystem"/> is on the operator's redirect list.</summary>
    public bool RedirectsEcosystem(string ecosystem) => Ecosystems.Contains(ecosystem);

    /// <summary>
    /// Binds from configuration. An unset, empty, or unparseable enable flag leaves the feature
    /// off; an unset or unparseable TTL falls back to the default, and any parsed TTL is clamped
    /// rather than rejected so a fat-fingered value degrades to a safe window instead of failing
    /// boot. An unset ecosystem list means <c>oci</c>; a list naming an ecosystem that has no
    /// redirect seam fails boot, because the alternative is an operator who believes an ecosystem
    /// redirects when it streams. The CloudFront signer is validated whenever it is selected, even
    /// with the feature off, so a misconfiguration surfaces at deploy rather than when someone
    /// later turns the feature on.
    /// </summary>
    public static PresignedReadOptions FromConfiguration(IConfiguration config)
    {
        bool enabled = bool.TryParse(config[EnabledKey], out bool parsed) && parsed;
        int seconds = int.TryParse(config[TtlSecondsKey], out int ttl) ? ttl : DefaultTtlSeconds;
        seconds = Math.Clamp(seconds, MinTtlSeconds, MaxTtlSeconds);
        var signer = CloudFrontSignerOptions.ParseSigner(config[CloudFrontSignerOptions.SignerKey]);
        return new PresignedReadOptions
        {
            Enabled = enabled,
            Ttl = TimeSpan.FromSeconds(seconds),
            Ecosystems = ParseEcosystems(config[EcosystemsKey]),
            Signer = signer,
            CloudFront = signer == PresignedReadSigner.CloudFront ? CloudFrontSignerOptions.FromConfiguration(config) : null,
        };
    }

    /// <summary>
    /// Parses the comma-separated ecosystem list. Whitespace and case are forgiven; an empty
    /// value after trimming means the default; an unknown name throws.
    /// </summary>
    public static IReadOnlySet<string> ParseEcosystems(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return DefaultEcosystems;
        }

        var names = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(n => n.ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);
        var unknown = names.Where(n => !RedirectableEcosystems.Contains(n)).OrderBy(n => n, StringComparer.Ordinal).ToList();
        return unknown.Count > 0
            ? throw new InvalidOperationException(
                $"{EcosystemsKey} names {string.Join(", ", unknown)}, which "
                + $"{(unknown.Count == 1 ? "is" : "are")} not a redirectable ecosystem. "
                + $"Valid values: {string.Join(", ", RedirectableEcosystems.OrderBy(n => n, StringComparer.Ordinal))}.")
            : names.Count == 0 ? DefaultEcosystems : names;
    }
}
