using System.Xml.Linq;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class MavenMetadataBuilderTests
{
    private static readonly DateTimeOffset Stamp =
        new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Fact]
    public void Build_SingleVersion_EmitsLatestReleaseAndVersions()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" }, Stamp);
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
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0", "2.0", "3.0" }, Stamp);
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
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.0", "2.0", "2.1-SNAPSHOT" }, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Equal("2.1-SNAPSHOT", versioning.Element("latest")!.Value);
        Assert.Equal("2.0", versioning.Element("release")!.Value);
    }

    [Fact]
    public void Build_AllSnapshots_NoReleaseElement()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.0-SNAPSHOT", "1.1-SNAPSHOT" }, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.NotNull(versioning.Element("latest"));
        Assert.Null(versioning.Element("release"));
    }

    [Fact]
    public void Build_EmitsLastUpdatedFromProvidedTimestamp()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" }, Stamp);
        var doc = XDocument.Parse(xml);
        string lu = doc.Root!.Element("versioning")!.Element("lastUpdated")!.Value;
        Assert.Equal("20260102030405", lu);
    }

    [Fact]
    public void Build_IsDeterministic_ForSameInputs()
    {
        // The body feeds a content-derived ETag and generated checksum sidecars; two builds
        // of the same version set must be byte-identical.
        string a = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0", "2.0" }, Stamp);
        string b = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0", "2.0" }, Stamp);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Build_NullLastUpdated_OmitsElement()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" }, lastUpdated: null);
        var doc = XDocument.Parse(xml);
        Assert.Null(doc.Root!.Element("versioning")!.Element("lastUpdated"));
    }
}
