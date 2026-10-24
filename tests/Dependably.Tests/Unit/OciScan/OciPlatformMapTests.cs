using System.Text;
using Dependably.Infrastructure.OciScan;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The platform → manifest map the result writer records on each coverage row, derived from the
/// stored manifest: an index maps each listed platform (with and without its variant) to its
/// child, a single-platform manifest maps every platform to itself, and a platform the index does
/// not list maps to nothing.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciPlatformMapTests
{
    private const string Index = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000";
    private const string Amd64 = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111";
    private const string Arm64 = "sha256:" + "2222222222222222222222222222222222222222222222222222222222222222";

    [Fact]
    public void AnIndex_MapsEachListedPlatformToItsChild()
    {
        byte[] bytes = Encoding.UTF8.GetBytes($$$"""
            {"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
              {"digest":"{{{Amd64}}}","platform":{"os":"linux","architecture":"amd64"}},
              {"digest":"{{{Arm64}}}","platform":{"os":"linux","architecture":"arm64","variant":"v8"}}
            ]}
            """);

        var map = OciPlatformMap.Parse(Index, bytes)!;

        Assert.Equal(Amd64, map.ManifestDigestFor("linux/amd64"));
        Assert.Equal(Arm64, map.ManifestDigestFor("linux/arm64"));
        Assert.Equal(Arm64, map.ManifestDigestFor("linux/arm64/v8"));
        Assert.Null(map.ManifestDigestFor("linux/s390x"));
    }

    [Fact]
    public void ASinglePlatformManifest_MapsEveryPlatformToItself()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(
            """{"schemaVersion":2,"config":{"digest":"sha256:aa"},"layers":[]}""");

        var map = OciPlatformMap.Parse(Amd64, bytes)!;

        Assert.Equal(Amd64, map.ManifestDigestFor("linux/amd64"));
    }

    [Fact]
    public void BytesThatAreNotJson_HaveNoMap()
    {
        Assert.Null(OciPlatformMap.Parse(Amd64, Encoding.UTF8.GetBytes("not json")));
    }
}
