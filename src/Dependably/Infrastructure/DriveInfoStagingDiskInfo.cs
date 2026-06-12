namespace Dependably.Infrastructure;

/// <summary>
/// Production implementation of <see cref="IStagingDiskInfo"/>. Reads disk space
/// from <see cref="DriveInfo"/> for the staging volume and sums file sizes in the
/// staging directory.
/// </summary>
public sealed class DriveInfoStagingDiskInfo : IStagingDiskInfo
{
    private readonly string _stagingPath;

    public DriveInfoStagingDiskInfo(string stagingPath)
    {
        _stagingPath = stagingPath;
    }

    /// <inheritdoc/>
    public long GetAvailableBytes()
    {
        var info = new DriveInfo(_stagingPath);
        return info.AvailableFreeSpace;
    }

    /// <inheritdoc/>
    public long GetTotalBytes()
    {
        var info = new DriveInfo(_stagingPath);
        return info.TotalSize;
    }

    /// <inheritdoc/>
    public long GetStagingDirectoryUsedBytes()
    {
        if (!Directory.Exists(_stagingPath))
        {
            return 0;
        }

        long total = 0;
        foreach (string file in Directory.EnumerateFiles(_stagingPath))
        {
            try
            {
                total += new FileInfo(file).Length;
            }
            catch (FileNotFoundException)
            {
                // File may have been deleted between enumeration and stat — skip it.
            }
            catch (IOException)
            {
                // Skip files we can't stat.
            }
        }
        return total;
    }
}
