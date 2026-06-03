namespace Dependably.Infrastructure;

public class EcoCount { public string Ecosystem { get; set; } = ""; public int Count { get; set; } }
public class HourCount { public string Hour { get; set; } = ""; public int Count { get; set; } }
public class EcoSeverityCount { public string Ecosystem { get; set; } = ""; public string Severity { get; set; } = ""; public int Count { get; set; } }
public class EcoDiskBytes { public string Ecosystem { get; set; } = ""; public long TotalBytes { get; set; } }
public class VulnPeriodCounts { public int Day { get; set; } public int Week { get; set; } public int Month { get; set; } }

public sealed record OrgStats(
    IReadOnlyList<EcoCount> PackagesByEcosystem,
    IReadOnlyList<HourCount> DownloadsByHour,
    IReadOnlyList<EcoSeverityCount> VulnsByEcosystemAndSeverity,
    IReadOnlyList<EcoDiskBytes> DiskByEcosystem,
    long TotalDiskBytes,
    VulnPeriodCounts NewVulns,
    int ActiveUsers7d,
    int BlockedPulls30d,
    int TotalDownloads30d);
