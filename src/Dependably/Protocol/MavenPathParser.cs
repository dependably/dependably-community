using System.Text.RegularExpressions;

namespace Dependably.Protocol;

/// <summary>
/// Decomposes a Maven request path into <see cref="MavenCoordinates"/>. Maven repositories
/// have a strict file-tree layout (PURL spec §maven; Maven Central convention):
///
///   <c>/{groupId-as-path}/{artifactId}/{version}/{artifactId}-{version}[-{classifier}].{extension}</c>
///
/// Checksum sidecars (<c>.sha1</c>, <c>.md5</c>, <c>.sha256</c>, <c>.sha512</c>) ride next
/// to every primary file. Group-level and version-level <c>maven-metadata.xml</c> drive
/// version listing and SNAPSHOT resolution.
/// </summary>
public static partial class MavenPathParser
{
    public static readonly string[] ChecksumExtensions = [".sha512", ".sha256", ".sha1", ".md5"];

    [GeneratedRegex(@"^(?<ts>\d{8}\.\d{6})-(?<bn>\d+)$")]
    private static partial Regex SnapshotTimestampRegex();

    /// <summary>
    /// Parses <paramref name="path"/> into Maven coordinates. Returns null when the path
    /// doesn't match either an artifact-layout file (<c>g/a/v/file</c>) or a metadata
    /// file (<c>g/a/maven-metadata.xml</c> / <c>g/a/v/maven-metadata.xml</c>).
    /// </summary>
    public static MavenCoordinates? Parse(string path)
    {
        path = path.Trim('/');
        if (path.Length == 0) return null;
        var segments = path.Split('/');
        if (segments.Length < 3) return null;

        var lastSegment = segments[^1];

        if (IsMetadataFile(lastSegment))
            return ParseMetadataPath(segments, lastSegment);

        return ParseArtifactPath(segments);
    }

    private static MavenCoordinates? ParseMetadataPath(string[] segments, string lastSegment)
    {
        // Two metadata flavours:
        //   version-level:  g/a/v/maven-metadata.xml   (segments.length >= 4)
        //   artifact-level: g/a/maven-metadata.xml     (segments.length >= 3)
        // We detect version-level when the second-to-last segment looks like a Maven version.
        var checksumAlg = ChecksumAlgorithmOf(lastSegment);
        var isChecksum = checksumAlg is not null;

        if (segments.Length >= 4 && LooksLikeVersion(segments[^2]))
        {
            var version = segments[^2];
            var artifactId = segments[^3];
            var groupId = string.Join('.', segments[..^3]);
            if (string.IsNullOrEmpty(groupId)) return null;
            return new MavenCoordinates(
                GroupId: groupId, ArtifactId: artifactId, Version: version,
                Classifier: null, Extension: null, Filename: lastSegment,
                IsMetadata: true,
                IsChecksumSidecar: isChecksum,
                ChecksumAlgorithm: checksumAlg,
                IsSnapshot: version.EndsWith("-SNAPSHOT", StringComparison.OrdinalIgnoreCase),
                SnapshotTimestamp: null, SnapshotBuildNumber: null);
        }

        var artifactIdOnly = segments[^2];
        var groupIdOnly = string.Join('.', segments[..^2]);
        if (string.IsNullOrEmpty(groupIdOnly)) return null;
        return new MavenCoordinates(
            GroupId: groupIdOnly, ArtifactId: artifactIdOnly, Version: null,
            Classifier: null, Extension: null, Filename: lastSegment,
            IsMetadata: true,
            IsChecksumSidecar: isChecksum,
            ChecksumAlgorithm: checksumAlg,
            IsSnapshot: false,
            SnapshotTimestamp: null, SnapshotBuildNumber: null);
    }

    private static MavenCoordinates? ParseArtifactPath(string[] segments)
    {
        if (segments.Length < 4) return null;

        var filename = segments[^1];
        var versionDir = segments[^2];
        var artifactIdSeg = segments[^3];
        var groupIdStr = string.Join('.', segments[..^3]);
        if (string.IsNullOrEmpty(groupIdStr)) return null;

        var (checksumAlg, primaryFilename) = StripChecksumSuffix(filename);

        var parsed = ParsePrimaryFilename(primaryFilename, artifactIdSeg, versionDir);
        if (parsed is null) return null;

        var isSnapshot = versionDir.EndsWith("-SNAPSHOT", StringComparison.OrdinalIgnoreCase);

        return new MavenCoordinates(
            GroupId: groupIdStr,
            ArtifactId: artifactIdSeg,
            Version: versionDir,
            Classifier: parsed.Value.Classifier,
            Extension: parsed.Value.Extension,
            Filename: filename,
            IsMetadata: false,
            IsChecksumSidecar: checksumAlg is not null,
            ChecksumAlgorithm: checksumAlg,
            IsSnapshot: isSnapshot,
            SnapshotTimestamp: parsed.Value.SnapshotTimestamp,
            SnapshotBuildNumber: parsed.Value.SnapshotBuildNumber);
    }

    private static (string? Alg, string Primary) StripChecksumSuffix(string filename)
    {
        var ext = ChecksumExtensions.FirstOrDefault(
            e => filename.EndsWith(e, StringComparison.OrdinalIgnoreCase));
        return ext is null
            ? (null, filename)
            : (ext[1..], filename[..^ext.Length]);
    }

    /// <summary>
    /// Returns the primary-artifact filename when <paramref name="filename"/> is a checksum
    /// sidecar (e.g. <c>lib-1.0.jar.sha1</c> → <c>lib-1.0.jar</c>); otherwise echoes the
    /// input. Used by the controller to locate the primary blob for on-the-fly checksum
    /// computation when the sidecar wasn't uploaded.
    /// </summary>
    public static string PrimaryFilename(string filename)
    {
        var ext = ChecksumExtensions.FirstOrDefault(
            e => filename.EndsWith(e, StringComparison.OrdinalIgnoreCase));
        return ext is null ? filename : filename[..^ext.Length];
    }

    private static (string? Classifier, string Extension, string? SnapshotTimestamp, int? SnapshotBuildNumber)?
        ParsePrimaryFilename(string filename, string artifactId, string version)
    {
        // Every primary artifact starts with "{artifactId}-".
        if (!filename.StartsWith(artifactId + "-", StringComparison.Ordinal))
            return null;

        var afterArtifactId = filename[(artifactId.Length + 1)..];

        var lastDot = afterArtifactId.LastIndexOf('.');
        if (lastDot < 0) return null;

        var extension = afterArtifactId[(lastDot + 1)..];
        var versionAndClassifier = afterArtifactId[..lastDot];

        if (version.EndsWith("-SNAPSHOT", StringComparison.OrdinalIgnoreCase))
        {
            var snap = ParseSnapshotTail(versionAndClassifier, version);
            return snap is null
                ? null
                : (snap.Value.Classifier, extension, snap.Value.Timestamp, snap.Value.BuildNumber);
        }

        var classifier = ParseReleaseClassifier(versionAndClassifier, version);
        if (versionAndClassifier != version && classifier is null) return null;
        return (classifier, extension, null, null);
    }

    private static (string? Classifier, string? Timestamp, int? BuildNumber)?
        ParseSnapshotTail(string versionAndClassifier, string version)
    {
        // SNAPSHOT versions: filename may carry either the literal "-SNAPSHOT" or
        // a timestamp form "{baseVersion}-{yyyyMMdd.HHmmss}-{buildNum}".
        var baseVersion = version[..^"-SNAPSHOT".Length];
        if (!versionAndClassifier.StartsWith(baseVersion + "-", StringComparison.Ordinal))
            return null;

        var afterBaseVersion = versionAndClassifier[(baseVersion.Length + 1)..];

        if (afterBaseVersion.StartsWith("SNAPSHOT", StringComparison.OrdinalIgnoreCase))
        {
            var afterSnapshot = afterBaseVersion["SNAPSHOT".Length..];
            if (afterSnapshot.Length == 0) return (null, null, null);
            if (afterSnapshot[0] == '-') return (afterSnapshot[1..], null, null);
            return null;
        }

        var tsMatch = SnapshotTimestampRegex().Match(afterBaseVersion);
        if (tsMatch.Success)
            return (null, tsMatch.Groups["ts"].Value, int.Parse(tsMatch.Groups["bn"].Value));

        // Timestamp + classifier: "{ts}-{bn}-{classifier}"
        var parts = afterBaseVersion.Split('-');
        if (parts.Length >= 2 && parts[0].Length == 15 && parts[0][8] == '.'
            && int.TryParse(parts[1], out var bn))
        {
            string? classifier = parts.Length > 2 ? string.Join('-', parts[2..]) : null;
            return (classifier, parts[0], bn);
        }
        return null;
    }

    private static string? ParseReleaseClassifier(string versionAndClassifier, string version)
    {
        if (versionAndClassifier == version) return null;
        return versionAndClassifier.StartsWith(version + "-", StringComparison.Ordinal)
            ? versionAndClassifier[(version.Length + 1)..]
            : null;
    }

    private static bool IsMetadataFile(string filename)
    {
        // Either bare maven-metadata.xml or a checksum sidecar on it.
        if (filename.Equals("maven-metadata.xml", StringComparison.OrdinalIgnoreCase)) return true;
        return ChecksumExtensions.Any(
            ext => filename.Equals("maven-metadata.xml" + ext, StringComparison.OrdinalIgnoreCase));
    }

    private static string? ChecksumAlgorithmOf(string filename)
    {
        var ext = ChecksumExtensions.FirstOrDefault(
            e => filename.EndsWith(e, StringComparison.OrdinalIgnoreCase));
        return ext?[1..];
    }

    private static bool LooksLikeVersion(string segment)
        => segment.Any(char.IsDigit) || segment.Contains("SNAPSHOT", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// One Maven coordinate triple plus the file shape inside it. Produced by
/// <see cref="MavenPathParser.Parse"/>. Each request resolves to either an artifact file
/// (one row in <c>maven_version_files</c>) or a metadata document (synthesised at request
/// time from <c>package_versions</c> rows).
/// </summary>
public sealed record MavenCoordinates(
    string GroupId,
    string ArtifactId,
    string? Version,
    string? Classifier,
    string? Extension,
    string Filename,
    bool IsMetadata,
    bool IsChecksumSidecar,
    string? ChecksumAlgorithm,
    bool IsSnapshot,
    string? SnapshotTimestamp,
    int? SnapshotBuildNumber)
{
    /// <summary>Group + artifact in <c>g:a</c> form — used as the package <c>purl_name</c>.</summary>
    public string PackageName => $"{GroupId}:{ArtifactId}";

    /// <summary>Group with dots → slashes (Maven on-disk layout).</summary>
    public string GroupPath => GroupId.Replace('.', '/');

    /// <summary>Relative repository path that callers / blob keys can echo.</summary>
    public string RepositoryPath => Version is not null
        ? $"{GroupPath}/{ArtifactId}/{Version}/{Filename}"
        : $"{GroupPath}/{ArtifactId}/{Filename}";
}
