namespace Dependably.Infrastructure;

/// <summary>
/// Provides disk-space measurements for the staging volume. Abstracted for testability
/// so unit tests inject a mock without touching the file system.
/// </summary>
public interface IStagingDiskInfo
{
    /// <summary>Available free bytes on the staging volume.</summary>
    long GetAvailableBytes();

    /// <summary>Total capacity in bytes of the staging volume.</summary>
    long GetTotalBytes();

    /// <summary>
    /// Sum of file sizes (in bytes) for all files currently present in the
    /// staging directory. Does not recurse into sub-directories.
    /// </summary>
    long GetStagingDirectoryUsedBytes();
}
