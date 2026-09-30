using System.Globalization;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// The instance-wide default usage caps (<c>DEFAULT_USAGE_CAPS</c>): the cap a tenant inherits on
/// every meter where it has no <c>org_usage_caps</c> row. An explicit cap always wins over the
/// default, higher or lower, so a larger explicit cap exempts a tenant; clearing an explicit cap
/// returns that meter to the default.
///
/// <para>
/// Read in multi-tenant modes only (<c>DEPLOYMENT_MODE=multi</c> or <c>header</c>), the same scope
/// as usage caps. Unset or empty means no defaults, so a tenant with no caps is metered and never
/// enforced. A value that cannot be read fails startup rather than running uncapped: a usage
/// control never degrades to "allow" because its configuration is unreadable.
/// </para>
/// </summary>
public sealed class DefaultUsageCaps
{
    public const string ConfigKey = "DEFAULT_USAGE_CAPS";

    /// <summary>No defaults: every tenant is capped by its explicit rows alone.</summary>
    public static DefaultUsageCaps None { get; } = new(new Dictionary<string, long>(StringComparer.Ordinal));

    private DefaultUsageCaps(IReadOnlyDictionary<string, long> caps) => Caps = caps;

    /// <summary>The default cap for each meter that has one, keyed by meter literal.</summary>
    public IReadOnlyDictionary<string, long> Caps { get; }

    /// <summary>Whether any meter has a default cap.</summary>
    public bool Any => Caps.Count > 0;

    /// <summary>
    /// Reads <see cref="ConfigKey"/> in a multi-tenant deployment mode, and returns
    /// <see cref="None"/> in any other mode, where usage caps do not apply.
    /// </summary>
    public static DefaultUsageCaps FromConfiguration(IConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);
        string mode = (config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        return mode is "multi" or "header" ? Parse(config[ConfigKey]) : None;
    }

    /// <summary>
    /// Parses comma-separated <c>meter=quantity</c> pairs, such as
    /// <c>egress_bytes=500000000000,artifact_count=10000</c>. Whitespace around a token is ignored.
    /// Null, empty or whitespace is <see cref="None"/>. An unknown meter, a quantity that is not a
    /// positive whole number, a duplicate meter, or a token that is not a pair throws
    /// <see cref="InvalidOperationException"/> naming the token and the valid meters.
    /// </summary>
    public static DefaultUsageCaps Parse(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return None;
        }

        var caps = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (string part in raw.Split(','))
        {
            string token = part.Trim();
            int eq = token.IndexOf('=', StringComparison.Ordinal);
            if (eq < 0)
            {
                throw Invalid(token, "is not a meter=quantity pair");
            }

            string meter = token[..eq].Trim();
            string value = token[(eq + 1)..].Trim();
            if (!UsageCapMeters.IsKnown(meter))
            {
                throw Invalid(token, $"names unknown meter '{meter}'");
            }

            if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long quantity) || quantity <= 0)
            {
                throw Invalid(token, "does not set a positive whole-number cap");
            }

            if (!caps.TryAdd(meter, quantity))
            {
                throw Invalid(token, $"repeats meter '{meter}'");
            }
        }

        return new DefaultUsageCaps(caps);
    }

    /// <summary>
    /// The caps that apply to a tenant: its <paramref name="explicitCaps"/>, plus the default for
    /// each meter it has no explicit cap on.
    /// </summary>
    public IReadOnlyDictionary<string, long> Effective(IReadOnlyDictionary<string, long> explicitCaps)
    {
        ArgumentNullException.ThrowIfNull(explicitCaps);
        if (!Any)
        {
            return explicitCaps;
        }

        var effective = new Dictionary<string, long>(explicitCaps, StringComparer.Ordinal);
        foreach (var (meter, cap) in Caps)
        {
            effective.TryAdd(meter, cap);
        }

        return effective;
    }

    private static InvalidOperationException Invalid(string token, string problem) =>
        new($"{ConfigKey} token '{token}' {problem}. Expected comma-separated meter=quantity pairs, "
            + $"each quantity a positive whole number, over the meters {string.Join(", ", UsageCapMeters.All)}.");
}
