using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// <c>g/a/maven-metadata.xml</c> and <c>g/a/{version}/maven-metadata.xml</c> are ambiguous from
/// the path alone: the segment before the filename is either an artifactId or a version, and
/// nothing in the request distinguishes them. The parser decides by shape, and the shape it used
/// — "contains a digit anywhere" — classified a large share of real artifactIds as versions.
///
/// The consequence was not subtle. <c>commons-lang3</c>, <c>log4j-core</c>, <c>slf4j-api</c> and
/// every other artifactId carrying a version-ish suffix had its artifact-level metadata parsed as
/// a version-level request for a different coordinate, and answered 404 — while the versions sat
/// in the catalogue. That document is what Maven resolves version ranges and LATEST/RELEASE
/// through, so the effect is a dependency that cannot be resolved at all.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenArtifactIdWithDigitTests
{
    /// <summary>
    /// Real coordinates, chosen because each one is among the most-depended-on artifacts in the
    /// ecosystem and each has a digit somewhere in its artifactId.
    /// </summary>
    [Theory]
    [InlineData("org/apache/commons/commons-lang3/maven-metadata.xml", "org.apache.commons", "commons-lang3")]
    [InlineData("org/apache/logging/log4j/log4j-core/maven-metadata.xml", "org.apache.logging.log4j", "log4j-core")]
    [InlineData("org/slf4j/slf4j-api/maven-metadata.xml", "org.slf4j", "slf4j-api")]
    [InlineData("com/h2database/h2/maven-metadata.xml", "com.h2database", "h2")]
    [InlineData("org/junit/jupiter/junit-jupiter-api/maven-metadata.xml", "org.junit.jupiter", "junit-jupiter-api")]
    public void ArtifactLevelMetadata_ForAnArtifactIdContainingADigit_ParsesAsArtifactLevel(
        string path, string expectedGroupId, string expectedArtifactId)
    {
        var coords = MavenPathParser.Parse(path);

        Assert.NotNull(coords);
        Assert.True(coords.IsMetadata);
        Assert.Null(coords.Version);
        Assert.Equal(expectedGroupId, coords.GroupId);
        Assert.Equal(expectedArtifactId, coords.ArtifactId);
    }

    /// <summary>
    /// The other half, and the reason the check cannot simply be deleted: a real version-level
    /// request must still be recognised, or SNAPSHOT resolution breaks.
    /// </summary>
    [Theory]
    [InlineData("com/example/mylib/1.0.0/maven-metadata.xml", "1.0.0")]
    [InlineData("com/example/mylib/2.0-SNAPSHOT/maven-metadata.xml", "2.0-SNAPSHOT")]
    [InlineData("org/apache/commons/commons-lang3/3.14.0/maven-metadata.xml", "3.14.0")]
    [InlineData("org/apache/logging/log4j/log4j-core/2.24.1-SNAPSHOT/maven-metadata.xml", "2.24.1-SNAPSHOT")]
    public void VersionLevelMetadata_IsStillRecognised(string path, string expectedVersion)
    {
        var coords = MavenPathParser.Parse(path);

        Assert.NotNull(coords);
        Assert.True(coords.IsMetadata);
        Assert.Equal(expectedVersion, coords.Version);
    }

    /// <summary>
    /// A SNAPSHOT version that does not begin with a digit is why the marker stays a second arm
    /// rather than the first-character test standing alone.
    /// </summary>
    [Fact]
    public void NonNumericSnapshotVersion_IsStillRecognisedAsAVersion()
    {
        var coords = MavenPathParser.Parse("com/example/mylib/trunk-SNAPSHOT/maven-metadata.xml");

        Assert.NotNull(coords);
        Assert.Equal("trunk-SNAPSHOT", coords.Version);
        Assert.Equal("mylib", coords.ArtifactId);
        Assert.True(coords.IsSnapshot);
    }

    /// <summary>
    /// The checksum sidecars resolve to the same coordinate as the document they describe. They
    /// were broken by exactly the same misparse, and a client that cannot verify the metadata it
    /// fetched is in no better position than one that could not fetch it.
    /// </summary>
    [Theory]
    [InlineData("org/apache/commons/commons-lang3/maven-metadata.xml.sha1", "sha1")]
    [InlineData("org/apache/commons/commons-lang3/maven-metadata.xml.md5", "md5")]
    public void ChecksumSidecar_ForAnArtifactIdContainingADigit_ResolvesToTheSameCoordinate(
        string path, string expectedAlgorithm)
    {
        var coords = MavenPathParser.Parse(path);

        Assert.NotNull(coords);
        Assert.True(coords.IsChecksumSidecar);
        Assert.Equal(expectedAlgorithm, coords.ChecksumAlgorithm);
        Assert.Null(coords.Version);
        Assert.Equal("org.apache.commons", coords.GroupId);
        Assert.Equal("commons-lang3", coords.ArtifactId);
    }
}
