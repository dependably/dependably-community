using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Supplementary <see cref="MavenPathParser"/> cases covering the reject branches and the
/// <see cref="MavenCoordinates"/> path-projection properties not hit by the happy-path suite.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenPathParserCoverageTests
{
    [Theory]
    // Filename doesn't start with "{artifactId}-".
    [InlineData("com/example/mylib/1.0/wrong-1.0.jar")]
    // SNAPSHOT version, but the filename version base mismatches the directory version.
    [InlineData("com/example/mylib/1.0-SNAPSHOT/mylib-2.0.jar")]
    // SNAPSHOT literal followed by a non-dash tail.
    [InlineData("com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOTx.jar")]
    // SNAPSHOT directory with a non-SNAPSHOT, non-timestamp tail.
    [InlineData("com/example/mylib/1.0-SNAPSHOT/mylib-1.0-garbage.jar")]
    public void Parse_RejectsMalformedArtifactFilenames(string path)
    {
        Assert.Null(MavenPathParser.Parse(path));
    }

    [Fact]
    public void Parse_SnapshotLiteralWithClassifier()
    {
        var coords = MavenPathParser.Parse(
            "com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT-sources.jar");
        Assert.NotNull(coords);
        Assert.True(coords!.IsSnapshot);
        Assert.Equal("sources", coords.Classifier);
        Assert.Null(coords.SnapshotTimestamp);
    }

    [Fact]
    public void RepositoryPath_VersionedArtifact_IncludesVersionSegment()
    {
        var coords = MavenPathParser.Parse("com/example/mylib/1.0/mylib-1.0.jar");
        Assert.NotNull(coords);
        Assert.Equal("com/example/mylib/1.0/mylib-1.0.jar", coords!.RepositoryPath);
        Assert.Equal("com.example:mylib", coords.PackageName);
        Assert.Equal("com/example", coords.GroupPath);
    }

    [Fact]
    public void RepositoryPath_ArtifactLevelMetadata_OmitsVersionSegment()
    {
        // Artifact-level maven-metadata.xml has a null Version, exercising the no-version path.
        var coords = MavenPathParser.Parse("com/example/mylib/maven-metadata.xml");
        Assert.NotNull(coords);
        Assert.Null(coords!.Version);
        Assert.True(coords.IsMetadata);
        Assert.Equal("com/example/mylib/maven-metadata.xml", coords.RepositoryPath);
    }
}
