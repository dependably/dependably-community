using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Manifest parsing on the push path: a registry MUST know which blobs a manifest references
/// (to verify they exist) and distinguish an image manifest from an index. Malformed or
/// structureless JSON must surface as null so the controller returns MANIFEST_INVALID rather
/// than accepting an unverifiable blob.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciManifestParserTests
{
    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void ParseReferences_ImageManifest_CollectsConfigAndLayers()
    {
        string json = """
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
          "config": { "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111" },
          "layers": [
            { "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222" },
            { "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333" }
          ]
        }
        """;

        var refs = OciManifestParser.ParseReferences(Bytes(json));

        Assert.NotNull(refs);
        Assert.False(refs!.IsIndex);
        Assert.Equal(3, refs.Digests.Count);
        Assert.Contains("sha256:1111111111111111111111111111111111111111111111111111111111111111", refs.Digests);
        Assert.Contains("sha256:2222222222222222222222222222222222222222222222222222222222222222", refs.Digests);
    }

    [Fact]
    public void ParseReferences_ImageIndex_CollectsChildManifests()
    {
        string json = """
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.index.v1+json",
          "manifests": [
            { "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            { "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
          ]
        }
        """;

        var refs = OciManifestParser.ParseReferences(Bytes(json));

        Assert.NotNull(refs);
        Assert.True(refs!.IsIndex);
        Assert.Equal(2, refs.Digests.Count);
    }

    [Fact]
    public void ParseReferences_MalformedJson_ReturnsNull()
        => Assert.Null(OciManifestParser.ParseReferences(Bytes("{ not valid json")));

    [Fact]
    public void ParseReferences_NoConfigOrLayersOrManifests_ReturnsNull()
        => Assert.Null(OciManifestParser.ParseReferences(Bytes("""{ "schemaVersion": 2 }""")));

    [Fact]
    public void ParseReferences_NonObjectRoot_ReturnsNull()
        => Assert.Null(OciManifestParser.ParseReferences(Bytes("[]")));

    [Theory]
    [InlineData("application/vnd.oci.image.manifest.v1+json", true)]
    [InlineData("application/vnd.docker.distribution.manifest.v2+json", true)]
    [InlineData("application/vnd.oci.image.index.v1+json", true)]
    [InlineData("application/octet-stream", false)]
    [InlineData(null, false)]
    public void IsAcceptedMediaType_GatesOnKnownManifestTypes(string? mediaType, bool expected)
        => Assert.Equal(expected, OciManifestParser.IsAcceptedMediaType(mediaType));
}
