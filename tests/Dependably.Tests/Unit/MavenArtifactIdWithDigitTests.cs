using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// <c>g/a/maven-metadata.xml</c> and <c>g/a/{version}/maven-metadata.xml</c> are ambiguous from
/// the path alone: the segment before the filename is either an artifactId or a version, and
/// nothing in the request distinguishes them.
///
/// The consequence of guessing wrong is not subtle. An artifactId read as a version has its
/// artifact-level metadata parsed as a version-level request for a different coordinate and
/// answered 404 — while the versions sit in the catalogue. That document is what Maven resolves
/// version ranges and LATEST/RELEASE through, so the effect is a dependency that cannot be
/// resolved at all.
///
/// Two successive shape heuristics failed in turn. "Contains a digit anywhere" took out
/// <c>commons-lang3</c>, <c>log4j-core</c>, <c>slf4j-api</c> and every other artifactId with a
/// version-ish suffix. Narrowing it to "begins with a digit" left a smaller but real population —
/// WebJars mirrors npm package names into artifactIds, and npm names may start with a digit. The
/// parser now tests the SNAPSHOT marker alone, because the version-level document exists only for
/// a SNAPSHOT version on both the upstream and the hosted plane; the file keeps its original name
/// because the population it guards is still "artifactIds a shape test misreads as versions".
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
    /// Real coordinates whose artifactId BEGINS with a digit, which the first-character shape test
    /// misread as versions. All five serve 200 on Maven Central today. WebJars mirrors npm package
    /// names into artifactIds and npm names may start with a digit, so this is a populated set
    /// rather than a theoretical one — <c>org/webjars/npm/3d-view/maven-metadata.xml</c> resolved
    /// as version-level metadata for groupId <c>org.webjars</c>, artifactId <c>npm</c>.
    /// </summary>
    [Theory]
    [InlineData("org/webjars/npm/3d-view/maven-metadata.xml", "org.webjars.npm", "3d-view")]
    [InlineData("org/webjars/npm/3dmol/maven-metadata.xml", "org.webjars.npm", "3dmol")]
    [InlineData("org/webjars/npm/7.css/maven-metadata.xml", "org.webjars.npm", "7.css")]
    [InlineData("org/webjars/npm/98.css/maven-metadata.xml", "org.webjars.npm", "98.css")]
    [InlineData("org/webjars/3rdwavemedia-themes-developer/maven-metadata.xml", "org.webjars", "3rdwavemedia-themes-developer")]
    public void ArtifactLevelMetadata_ForAnArtifactIdBeginningWithADigit_ParsesAsArtifactLevel(
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
    /// request must still be recognised, or SNAPSHOT resolution breaks. SNAPSHOT is the whole
    /// population — a release coordinate has no version-level document to recognise.
    /// </summary>
    [Theory]
    [InlineData("com/example/mylib/2.0-SNAPSHOT/maven-metadata.xml", "2.0-SNAPSHOT")]
    [InlineData("org/apache/logging/log4j/log4j-core/2.24.1-SNAPSHOT/maven-metadata.xml", "2.24.1-SNAPSHOT")]
    [InlineData("org/webjars/npm/3d-view/1.0.0-SNAPSHOT/maven-metadata.xml", "1.0.0-SNAPSHOT")]
    public void VersionLevelSnapshotMetadata_IsStillRecognised(string path, string expectedVersion)
    {
        var coords = MavenPathParser.Parse(path);

        Assert.NotNull(coords);
        Assert.True(coords.IsMetadata);
        Assert.Equal(expectedVersion, coords.Version);
    }

    /// <summary>
    /// A SNAPSHOT version that does not begin with a digit is why the marker, and not a numeric
    /// shape test, is the arm that survived.
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
    /// The false-negative direction the shape test also got wrong, recorded so a future
    /// reintroduction has to argue with it. Guava published <c>r03</c>–<c>r09</c>: version strings
    /// that begin with a letter. They were the entire false-negative population measured across
    /// 4,509 real Maven Central version strings, and they are unreachable — Central 404s the
    /// version-level document for a release version, so nothing ever requests this path.
    /// </summary>
    [Fact]
    public void ReleaseVersionLevelMetadata_ParsesAsArtifactLevel_BecauseNoSuchDocumentExists()
    {
        var coords = MavenPathParser.Parse("com/google/guava/guava/r09/maven-metadata.xml");

        Assert.NotNull(coords);
        Assert.True(coords.IsMetadata);
        Assert.Null(coords.Version);
        Assert.Equal("com.google.guava.guava", coords.GroupId);
        Assert.Equal("r09", coords.ArtifactId);
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
