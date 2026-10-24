using System.Text;
using Dependably.Infrastructure.OciScan;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// Manifest bytes the platform map is parsed from are stored upstream content: a root that is not
/// an object has no map, index entries that omit a digest, platform, os or architecture are
/// skipped without losing the entries that are well formed, and the first entry for a platform
/// wins so a later duplicate cannot redirect it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciPlatformMapParseEdgeTests
{
    private const string Owner = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    private const string Amd64 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string Arm64 = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    private const string Forged = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    private static OciPlatformMap? Parse(string json) => OciPlatformMap.Parse(Owner, Encoding.UTF8.GetBytes(json));

    [Theory]
    [InlineData("[]")]
    [InlineData("\"a string\"")]
    [InlineData("42")]
    public void ARootThatIsNotAnObject_HasNoMap(string json) => Assert.Null(Parse(json));

    [Fact]
    public void ManifestsThatIsNotAnArray_IsASinglePlatformManifest()
    {
        var map = Parse("""{"schemaVersion":2,"manifests":"nope"}""")!;

        Assert.Null(map.IndexChildren);
        Assert.Equal(Owner, map.ManifestDigestFor("linux/amd64"));
    }

    [Fact]
    public void MalformedIndexEntries_AreSkipped_AndTheWellFormedOnesStillMap()
    {
        var map = Parse($$$"""
            {"manifests":[
              "not an object",
              {"platform":{"os":"linux","architecture":"amd64"}},
              {"digest":42,"platform":{"os":"linux","architecture":"amd64"}},
              {"digest":"{{{Amd64}}}"},
              {"digest":"{{{Amd64}}}","platform":"linux/amd64"},
              {"digest":"{{{Amd64}}}","platform":{"architecture":"amd64"}},
              {"digest":"{{{Amd64}}}","platform":{"os":"linux"}},
              {"digest":"{{{Amd64}}}","platform":{"os":1,"architecture":"amd64"}},
              {"digest":"{{{Arm64}}}","platform":{"os":"linux","architecture":"arm64","variant":"v8"}}
            ]}
            """)!;

        Assert.Null(map.ManifestDigestFor("linux/amd64"));
        Assert.Equal(Arm64, map.ManifestDigestFor("linux/arm64"));
        Assert.Equal(Arm64, map.ManifestDigestFor("linux/arm64/v8"));
    }

    [Fact]
    public void ADuplicatePlatform_KeepsTheFirstEntry()
    {
        var map = Parse($$$"""
            {"manifests":[
              {"digest":"{{{Amd64}}}","platform":{"os":"linux","architecture":"amd64"}},
              {"digest":"{{{Forged}}}","platform":{"os":"linux","architecture":"amd64"}}
            ]}
            """)!;

        Assert.Equal(Amd64, map.ManifestDigestFor("linux/amd64"));
    }

    [Fact]
    public void AnEmptyIndex_MapsNoPlatformToAnything_NotToTheOwner()
    {
        var map = Parse("""{"manifests":[]}""")!;

        Assert.NotNull(map.IndexChildren);
        Assert.Null(map.ManifestDigestFor("linux/amd64"));
    }
}
