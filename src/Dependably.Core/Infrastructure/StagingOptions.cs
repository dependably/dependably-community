namespace Dependably.Infrastructure;

/// <summary>
/// Resolved staging configuration shared by every component that touches the
/// proxy-fetch hash-and-stage volume. Resolving the path and the disk floor in one
/// place keeps the two from diverging: <see cref="UpstreamClient"/> guards new fetches
/// against <see cref="FloorBytes"/>, <see cref="DriveInfoStagingDiskInfo"/> probes
/// <see cref="Path"/>, and <see cref="StartupService"/> warns when the floor is the
/// deliberate 0 opt-out — all reading the same resolved values.
/// </summary>
public sealed record StagingOptions(string Path, long FloorBytes)
{
    /// <summary>Hard floor applied when <c>STAGING_DISK_FLOOR_BYTES</c> is unset, negative, or unparseable.</summary>
    public const long DefaultFloorBytes = 512L * 1024 * 1024;

    /// <summary>
    /// Resolves staging options from configuration:
    ///   - Path: <c>PROXY_STAGING_PATH</c> if set, else the OS temp directory. Defaults to
    ///     temp because that always exists; operators expecting large artefacts on
    ///     containerised deployments should point this at a disk-backed volume (e.g.
    ///     /data/staging), because /tmp is often tmpfs (RAM-backed), which defeats the
    ///     memory-bounding goal of streaming.
    ///   - FloorBytes: <c>STAGING_DISK_FLOOR_BYTES</c> when it parses to a value &gt;= 0
    ///     (an explicit 0 is a deliberate opt-out that disables disk-full protection);
    ///     a negative or unparseable value falls back to <see cref="DefaultFloorBytes"/>
    ///     rather than silently disabling.
    /// </summary>
    public static StagingOptions Resolve(IConfiguration configuration)
    {
        string? configuredPath = configuration["PROXY_STAGING_PATH"];
        string path = string.IsNullOrWhiteSpace(configuredPath)
            ? System.IO.Path.GetTempPath()
            : configuredPath;

        bool floorConfigured = long.TryParse(configuration["STAGING_DISK_FLOOR_BYTES"], out long floor);
        long floorBytes = floorConfigured && floor >= 0 ? floor : DefaultFloorBytes;

        return new StagingOptions(path, floorBytes);
    }
}
