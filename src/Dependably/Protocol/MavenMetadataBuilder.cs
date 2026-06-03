using System.Text;
using System.Xml.Linq;

namespace Dependably.Protocol;

/// <summary>
/// Generates artifact-level <c>maven-metadata.xml</c> from a list of known versions.
///
/// Shape (per Maven convention):
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
///
/// SNAPSHOT-level metadata (timestamp + buildNumber) is a follow-up — clients can still
/// publish &amp; resolve SNAPSHOTs using the artifact path; only auto-discovery of timestamped
/// filenames degrades without the per-version metadata document.
/// </summary>
public static class MavenMetadataBuilder
{
    /// <summary>
    /// Builds the artifact-level metadata XML for <paramref name="versions"/> (in publish
    /// order — last is the latest). Returns a UTF-8 XML string that <c>mvn</c>/<c>gradle</c>
    /// parse directly.
    /// </summary>
    public static string Build(string groupId, string artifactId, IReadOnlyList<string> versions)
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
                    new XElement("lastUpdated", DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss")))));

        using var sw = new StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    private static XElement? LatestElement(IReadOnlyList<string> versions, bool releaseOnly)
    {
        if (versions.Count == 0) return null;
        if (!releaseOnly) return new XElement("latest", versions[^1]);

        // <release> excludes SNAPSHOT versions (Maven convention).
        for (var i = versions.Count - 1; i >= 0; i--)
        {
            if (!versions[i].EndsWith("-SNAPSHOT", StringComparison.OrdinalIgnoreCase))
                return new XElement("release", versions[i]);
        }
        return null;
    }
}
