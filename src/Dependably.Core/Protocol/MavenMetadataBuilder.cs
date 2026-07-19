using System.Globalization;
using System.Xml.Linq;

namespace Dependably.Protocol;

/// <summary>
/// Generates the two <c>maven-metadata.xml</c> flavours mvn/Gradle fetch: artifact-level
/// (<see cref="Build"/>), listing every known version, and SNAPSHOT version-level
/// (<see cref="BuildSnapshotVersion"/>), listing the timestamped builds published under one
/// SNAPSHOT version so a client resolves <c>1.0-SNAPSHOT</c> to the latest build.
///
/// Artifact-level shape (per Maven convention):
/// <code>
///   &lt;metadata&gt;
///     &lt;groupId&gt;...&lt;/groupId&gt;
///     &lt;artifactId&gt;...&lt;/artifactId&gt;
///     &lt;versioning&gt;
///       &lt;latest&gt;...&lt;/latest&gt;
///       &lt;release&gt;...&lt;/release&gt;
///       &lt;versions&gt;&lt;version&gt;...&lt;/version&gt;...&lt;/versions&gt;
///       &lt;lastUpdated&gt;yyyyMMddHHmmss&lt;/lastUpdated&gt;
///     &lt;/versioning&gt;
///   &lt;/metadata&gt;
/// </code>
/// </summary>
public static class MavenMetadataBuilder
{
    /// <summary>
    /// Builds the artifact-level metadata XML for <paramref name="versions"/>. Returns a UTF-8
    /// XML string that <c>mvn</c>/<c>gradle</c> parse directly.
    ///
    /// <paramref name="versions"/> is rendered into <c>&lt;versions&gt;</c> in the order given —
    /// the caller owns that order. <c>&lt;latest&gt;</c> and <c>&lt;release&gt;</c> are
    /// <b>not</b> read off the end of the list: they are selected by comparing the versions
    /// under <see cref="MavenVersionComparer"/>, so the pair a client resolves is a property of
    /// the version set alone and never of the row order behind it. Timestamps do not decide
    /// them — a cache plane populated by one bulk backfill carries a single shared timestamp
    /// across every version of a coordinate, which leaves nothing for a recency rule to order.
    ///
    /// <paramref name="lastUpdated"/> must be derived from the stored data (newest local
    /// publish time), never from the wall clock: the output must be byte-identical for the
    /// same version set so the content-derived ETag is stable across requests and the
    /// generated <c>.sha1</c>/<c>.md5</c> sidecars match the document a client just
    /// downloaded. <c>null</c> (no local provenance, e.g. upstream-only merges) omits the
    /// element — Maven clients treat it as optional.
    /// </summary>
    public static string Build(
        string groupId, string artifactId, IReadOnlyList<string> versions, DateTimeOffset? lastUpdated)
    {
        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement("metadata",
                new XElement("groupId", groupId),
                new XElement("artifactId", artifactId),
                new XElement("versioning",
                    LatestElement(versions, releaseOnly: false),
                    LatestElement(versions, releaseOnly: true),
                    new XElement("versions",
                        versions.Select(v => new XElement("version", v))),
                    lastUpdated is null
                        ? null
                        : new XElement("lastUpdated",
                            lastUpdated.Value.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture)))));

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    /// <summary>
    /// Builds the version-level <c>maven-metadata.xml</c> for a hosted SNAPSHOT version — the
    /// document mvn/Gradle fetch from <c>g/a/{version}/maven-metadata.xml</c> to resolve the
    /// literal <c>1.0-SNAPSHOT</c> coordinate to the latest timestamped build. Shape:
    /// <code>
    ///   &lt;metadata&gt;
    ///     &lt;groupId&gt;...&lt;/groupId&gt;
    ///     &lt;artifactId&gt;...&lt;/artifactId&gt;
    ///     &lt;version&gt;1.0-SNAPSHOT&lt;/version&gt;
    ///     &lt;versioning&gt;
    ///       &lt;snapshot&gt;
    ///         &lt;timestamp&gt;yyyyMMdd.HHmmss&lt;/timestamp&gt;
    ///         &lt;buildNumber&gt;N&lt;/buildNumber&gt;
    ///       &lt;/snapshot&gt;
    ///       &lt;lastUpdated&gt;yyyyMMddHHmmss&lt;/lastUpdated&gt;
    ///       &lt;snapshotVersions&gt;
    ///         &lt;snapshotVersion&gt;
    ///           &lt;classifier&gt;...&lt;/classifier&gt;  (omitted when null)
    ///           &lt;extension&gt;...&lt;/extension&gt;
    ///           &lt;value&gt;1.0-yyyyMMdd.HHmmss-N&lt;/value&gt;
    ///           &lt;updated&gt;yyyyMMddHHmmss&lt;/updated&gt;
    ///         &lt;/snapshotVersion&gt;...
    ///       &lt;/snapshotVersions&gt;
    ///     &lt;/versioning&gt;
    ///   &lt;/metadata&gt;
    /// </code>
    /// <paramref name="files"/> whose filename carries no deploy timestamp (a literal
    /// <c>-SNAPSHOT.jar</c> publish) contribute no <c>snapshotVersion</c> entry and are excluded
    /// from the newest-build selection — clients still resolve them by requesting the literal
    /// filename directly. When no file carries a timestamp, the whole <c>&lt;snapshot&gt;</c>/
    /// <c>&lt;snapshotVersions&gt;</c> pair is omitted. The newest build (highest
    /// <c>buildNumber</c>, ties broken by the lexicographically-greater timestamp — the
    /// <c>yyyyMMdd.HHmmss</c> format sorts chronologically as a string) drives the top-level
    /// <c>&lt;snapshot&gt;</c> element.
    /// </summary>
    public static string BuildSnapshotVersion(
        string groupId, string artifactId, string version,
        IReadOnlyList<MavenSnapshotFile> files, DateTimeOffset? lastUpdated)
    {
        var timestamped = files.Where(f => f.Timestamp is not null && f.BuildNumber is not null).ToList();

        XElement? snapshotElement = null;
        XElement? snapshotVersionsElement = null;

        if (timestamped.Count > 0)
        {
            var newest = timestamped
                .OrderBy(f => f.Timestamp, StringComparer.Ordinal)
                .ThenBy(f => f.BuildNumber)
                .Last();

            string baseVersion = version.EndsWith("-SNAPSHOT", StringComparison.OrdinalIgnoreCase)
                ? version[..^"-SNAPSHOT".Length]
                : version;

            snapshotElement = new XElement("snapshot",
                new XElement("timestamp", newest.Timestamp),
                new XElement("buildNumber", newest.BuildNumber));

            snapshotVersionsElement = new XElement("snapshotVersions",
                timestamped.Select(f => new XElement("snapshotVersion",
                    f.Classifier is null ? null : new XElement("classifier", f.Classifier),
                    new XElement("extension", f.Extension),
                    new XElement("value", $"{baseVersion}-{f.Timestamp}-{f.BuildNumber}"),
                    new XElement("updated",
                        f.Updated.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture)))));
        }

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement("metadata",
                new XElement("groupId", groupId),
                new XElement("artifactId", artifactId),
                new XElement("version", version),
                new XElement("versioning",
                    snapshotElement,
                    lastUpdated is null
                        ? null
                        : new XElement("lastUpdated",
                            lastUpdated.Value.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture)),
                    snapshotVersionsElement)));

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    // XDocument.Save derives the XML declaration's `encoding` from the writer's Encoding
    // property. A plain StringWriter reports UTF-16, so saving to it emits
    // <?xml version="1.0" encoding="utf-16"?> even though the XDeclaration says UTF-8 — which
    // then lies about the UTF-8 bytes MavenController serves, and encoding-sniffing XML readers
    // (plexus/Xerces) either throw or garble the document, breaking LATEST/RELEASE resolution.
    private sealed class Utf8StringWriter : StringWriter
    {
        public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;
    }

    // Picks the newest version under Maven's version ordering — not the last element, whose
    // position only reflects the order the caller's rows happened to arrive in. <latest> ranks
    // every version; <release> ranks only the non-SNAPSHOTs (Maven convention), so a resolver
    // asking for the latest stable build never lands on an in-flight prerelease. Returns null
    // when nothing qualifies: an empty set for <latest>, an all-SNAPSHOT set for <release>.
    private static XElement? LatestElement(IReadOnlyList<string> versions, bool releaseOnly)
    {
        string? newest = null;
        foreach (string version in versions)
        {
            if (releaseOnly && IsSnapshot(version))
            {
                continue;
            }
            if (newest is null || MavenVersionComparer.Instance.Compare(version, newest) > 0)
            {
                newest = version;
            }
        }

        return newest is null ? null : new XElement(releaseOnly ? "release" : "latest", newest);
    }

    // The artifact-level version list carries base versions ("1.0-SNAPSHOT"), not the
    // timestamped builds ("1.0-20240101.120000-3") that only appear in version-level snapshot
    // metadata — so the -SNAPSHOT suffix is the whole snapshot test at this level.
    private static bool IsSnapshot(string version) =>
        version.EndsWith("-SNAPSHOT", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// One file recorded for a SNAPSHOT version, used by <see cref="MavenMetadataBuilder.BuildSnapshotVersion"/>
/// to build the version-level snapshot metadata document. <paramref name="Timestamp"/> /
/// <paramref name="BuildNumber"/> are the Maven-format deploy timestamp (<c>yyyyMMdd.HHmmss</c>)
/// and build counter parsed from a timestamped filename (e.g.
/// <c>lib-1.0-20240101.120000-3.jar</c>); both are <see langword="null"/> when the file was
/// published under the literal <c>-SNAPSHOT</c> filename and carries no deploy timestamp.
/// </summary>
public sealed record MavenSnapshotFile(
    string? Classifier, string Extension, string? Timestamp, int? BuildNumber, DateTimeOffset Updated);
