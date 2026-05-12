namespace Dependably.Infrastructure;

/// <summary>
/// Reports whether the deployment is configured air-gapped (#46). When true, every upstream
/// fetch path returns a clear error rather than timing out, the proxy cache is never written,
/// and the OSV scanner runs against a local mirror only.
///
/// Configured via the <c>AIR_GAPPED</c> environment variable. Read once at startup; the
/// setting does not change at runtime.
/// </summary>
public interface IAirGapMode
{
    bool IsEnabled { get; }
}

public sealed class AirGapMode : IAirGapMode
{
    public bool IsEnabled { get; }

    public AirGapMode(IConfiguration config)
    {
        var raw = config["AIR_GAPPED"];
        IsEnabled = string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase);
    }
}
