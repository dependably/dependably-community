using System.Xml.Linq;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class MavenMetadataBuilderTests
{
    [Fact]
    public void Build_SingleVersion_EmitsLatestReleaseAndVersions()
    {
        var xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" });
        var doc = XDocument.Parse(xml);

        Assert.Equal("com.example", doc.Root!.Element("groupId")!.Value);
        Assert.Equal("mylib", doc.Root.Element("artifactId")!.Value);

        var versioning = doc.Root.Element("versioning")!;
        Assert.Equal("1.0", versioning.Element("latest")!.Value);
        Assert.Equal("1.0", versioning.Element("release")!.Value);
        Assert.Single(versioning.Element("versions")!.Elements("version"));
    }

    [Fact]
    public void Build_MultipleVersions_LatestIsTheLast()
    {
        var xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0", "2.0", "3.0" });
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Equal("3.0", versioning.Element("latest")!.Value);
        Assert.Equal("3.0", versioning.Element("release")!.Value);
        Assert.Equal(3, versioning.Element("versions")!.Elements("version").Count());
    }

    [Fact]
    public void Build_LatestSnapshot_ReleaseSkipsToPriorNonSnapshot()
    {
        // "latest" tracks the most recent publish (including SNAPSHOTs); "release" must
        // skip SNAPSHOTs so dependency resolvers asking for the latest stable build don't
        // accidentally land on an in-flight prerelease.
        var xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.0", "2.0", "2.1-SNAPSHOT" });
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Equal("2.1-SNAPSHOT", versioning.Element("latest")!.Value);
        Assert.Equal("2.0", versioning.Element("release")!.Value);
    }

    [Fact]
    public void Build_AllSnapshots_NoReleaseElement()
    {
        var xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.0-SNAPSHOT", "1.1-SNAPSHOT" });
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.NotNull(versioning.Element("latest"));
        Assert.Null(versioning.Element("release"));
    }

    [Fact]
    public void Build_EmitsLastUpdatedAsTimestamp()
    {
        var xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" });
        var doc = XDocument.Parse(xml);
        var lu = doc.Root!.Element("versioning")!.Element("lastUpdated")!.Value;
        // yyyyMMddHHmmss → 14 digits.
        Assert.Equal(14, lu.Length);
        Assert.True(lu.All(char.IsDigit));
    }
}
