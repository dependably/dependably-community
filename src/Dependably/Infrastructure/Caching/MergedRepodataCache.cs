using System.Xml.Linq;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// The cached, gzipped merged-mode RPM repodata documents for one tenant: the combined
/// local+upstream <c>primary.xml.gz</c> and <c>filelists.xml.gz</c>, plus the upstream
/// non-primary repomd <c>&lt;data&gt;</c> entries passed through verbatim. Cached as a value (not
/// <c>byte[]</c>) and weighed by the two gzipped payloads' lengths.
/// </summary>
public sealed record MergedRepodataCache(
    byte[] PrimaryGz,
    byte[] FilelistsGz,
    IReadOnlyList<XElement> UpstreamNonPrimaryEntries);
