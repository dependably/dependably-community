using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class MavenPathParserTests
{
    [Theory]
    [InlineData("com/example/mylib/1.0/mylib-1.0.jar",
        "com.example", "mylib", "1.0", null, "jar")]
    [InlineData("com/example/mylib/1.0/mylib-1.0.pom",
        "com.example", "mylib", "1.0", null, "pom")]
    [InlineData("com/example/mylib/1.0/mylib-1.0-sources.jar",
        "com.example", "mylib", "1.0", "sources", "jar")]
    [InlineData("com/example/mylib/1.0/mylib-1.0-javadoc.jar",
        "com.example", "mylib", "1.0", "javadoc", "jar")]
    [InlineData("org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
        "org.apache.commons", "commons-lang3", "3.14.0", null, "jar")]
    public void Parse_SimpleArtifactPaths(string path, string g, string a, string v, string? c, string ext)
    {
        var coords = MavenPathParser.Parse(path);
        Assert.NotNull(coords);
        Assert.Equal(g, coords!.GroupId);
        Assert.Equal(a, coords.ArtifactId);
        Assert.Equal(v, coords.Version);
        Assert.Equal(c, coords.Classifier);
        Assert.Equal(ext, coords.Extension);
        Assert.False(coords.IsMetadata);
        Assert.False(coords.IsChecksumSidecar);
    }

    [Theory]
    [InlineData("com/example/mylib/1.0/mylib-1.0.jar.sha1", "sha1")]
    [InlineData("com/example/mylib/1.0/mylib-1.0.jar.md5", "md5")]
    [InlineData("com/example/mylib/1.0/mylib-1.0.jar.sha256", "sha256")]
    [InlineData("com/example/mylib/1.0/mylib-1.0.jar.sha512", "sha512")]
    public void Parse_ChecksumSidecars_DetectAlgorithm(string path, string algo)
    {
        var coords = MavenPathParser.Parse(path);
        Assert.NotNull(coords);
        Assert.True(coords!.IsChecksumSidecar);
        Assert.Equal(algo, coords.ChecksumAlgorithm);
        Assert.Equal("jar", coords.Extension);
        Assert.EndsWith(".jar", MavenPathParser.PrimaryFilename(coords.Filename));
    }

    [Fact]
    public void Parse_SnapshotLiteral()
    {
        var coords = MavenPathParser.Parse("com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar");
        Assert.NotNull(coords);
        Assert.True(coords!.IsSnapshot);
        Assert.Equal("1.0-SNAPSHOT", coords.Version);
        Assert.Null(coords.SnapshotTimestamp);
        Assert.Null(coords.SnapshotBuildNumber);
    }

    [Fact]
    public void Parse_SnapshotTimestamped()
    {
        var coords = MavenPathParser.Parse(
            "com/example/mylib/1.0-SNAPSHOT/mylib-1.0-20240115.143022-3.jar");
        Assert.NotNull(coords);
        Assert.True(coords!.IsSnapshot);
        Assert.Equal("20240115.143022", coords.SnapshotTimestamp);
        Assert.Equal(3, coords.SnapshotBuildNumber);
    }

    [Fact]
    public void Parse_SnapshotTimestamped_WithClassifier()
    {
        var coords = MavenPathParser.Parse(
            "com/example/mylib/1.0-SNAPSHOT/mylib-1.0-20240115.143022-3-sources.jar");
        Assert.NotNull(coords);
        Assert.Equal("sources", coords!.Classifier);
        Assert.Equal("20240115.143022", coords.SnapshotTimestamp);
    }

    [Fact]
    public void Parse_ArtifactLevelMetadata()
    {
        var coords = MavenPathParser.Parse("com/example/mylib/maven-metadata.xml");
        Assert.NotNull(coords);
        Assert.True(coords!.IsMetadata);
        Assert.Null(coords.Version);
        Assert.Equal("com.example", coords.GroupId);
        Assert.Equal("mylib", coords.ArtifactId);
    }

    [Fact]
    public void Parse_VersionLevelMetadata()
    {
        var coords = MavenPathParser.Parse("com/example/mylib/1.0-SNAPSHOT/maven-metadata.xml");
        Assert.NotNull(coords);
        Assert.True(coords!.IsMetadata);
        Assert.Equal("1.0-SNAPSHOT", coords.Version);
        Assert.True(coords.IsSnapshot);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("not-enough-segments.jar")]
    [InlineData("group/artifact.jar")]
    public void Parse_InvalidPaths_ReturnNull(string path)
    {
        Assert.Null(MavenPathParser.Parse(path));
    }

    [Fact]
    public void PackageName_ReturnsColonForm()
    {
        var coords = MavenPathParser.Parse("com/example/mylib/1.0/mylib-1.0.jar")!;
        Assert.Equal("com.example:mylib", coords.PackageName);
    }

    [Fact]
    public void GroupPath_ReplacesDotsWithSlashes()
    {
        var coords = MavenPathParser.Parse("com/example/mylib/1.0/mylib-1.0.jar")!;
        Assert.Equal("com/example", coords.GroupPath);
    }
}
