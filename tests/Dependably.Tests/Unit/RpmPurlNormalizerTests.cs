using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class RpmPurlNormalizerTests
{
    [Fact]
    public void Rpm_Basic_FormatsCorrectly()
    {
        Assert.Equal("pkg:rpm/zlib@1.2.11-39.el9?arch=x86_64",
            PurlNormalizer.Rpm("zlib", "1.2.11", "39.el9", "x86_64"));
    }

    [Fact]
    public void Rpm_WithEpoch_AppendsQualifier()
    {
        Assert.Equal("pkg:rpm/python@3.9.18-1.el9?arch=noarch&epoch=2",
            PurlNormalizer.Rpm("python", "3.9.18", "1.el9", "noarch", epoch: 2));
    }

    [Fact]
    public void Rpm_MixedCaseName_Lowercases()
    {
        Assert.StartsWith("pkg:rpm/myrpm@",
            PurlNormalizer.Rpm("MyRPM", "1.0", "1", "x86_64"));
    }

    // ── distroNamespace (OSV.dev remote-path fix) ──────────────────────────────

    [Fact]
    public void Rpm_NoDistroNamespace_RegressionPinsBareForm()
    {
        // Every existing caller that does not pass a distro must keep producing exactly today's
        // bare form — the default parameter value is what makes that true without touching any
        // existing call site.
        Assert.Equal("pkg:rpm/zlib@1.2.11-39.el9?arch=x86_64",
            PurlNormalizer.Rpm("zlib", "1.2.11", "39.el9", "x86_64"));
    }

    [Fact]
    public void Rpm_NullDistroNamespace_ProducesBareForm()
    {
        Assert.Equal("pkg:rpm/zlib@1.2.11-39.el9?arch=x86_64",
            PurlNormalizer.Rpm("zlib", "1.2.11", "39.el9", "x86_64", distroNamespace: null));
    }

    [Fact]
    public void Rpm_KnownDistroNamespace_InsertsNamespaceSegment()
    {
        Assert.Equal("pkg:rpm/rocky-linux/tree@1.8.0-3.el9?arch=x86_64",
            PurlNormalizer.Rpm("tree", "1.8.0", "3.el9", "x86_64", distroNamespace: "rocky-linux"));
    }

    [Fact]
    public void Rpm_KnownDistroNamespaceWithEpoch_PlacesNamespaceBeforeNameAndEpochInQualifiers()
    {
        Assert.Equal("pkg:rpm/redhat/python@3.9.18-1.el9?arch=noarch&epoch=2",
            PurlNormalizer.Rpm("python", "3.9.18", "1.el9", "noarch", epoch: 2, distroNamespace: "redhat"));
    }

    [Fact]
    public void Rpm_KnownDistroNamespace_NameStillLowercased()
    {
        Assert.Equal("pkg:rpm/almalinux/myrpm@1.0-1?arch=x86_64",
            PurlNormalizer.Rpm("MyRPM", "1.0", "1", "x86_64", distroNamespace: "almalinux"));
    }

    // ── RpmHasKnownDistro ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("pkg:rpm/almalinux/tree@1.8.0-3.el9?arch=x86_64")]
    [InlineData("pkg:rpm/azure-linux/tree@1.8.0-3.el9?arch=x86_64")]
    [InlineData("pkg:rpm/mageia/tree@1.8.0-3.el9?arch=x86_64")]
    [InlineData("pkg:rpm/openeuler/tree@1.8.0-3.el9?arch=x86_64")]
    [InlineData("pkg:rpm/opensuse/tree@1.8.0-3.el9?arch=x86_64")]
    [InlineData("pkg:rpm/redhat/tree@1.8.0-3.el9?arch=x86_64")]
    [InlineData("pkg:rpm/rocky-linux/tree@1.8.0-3.el9?arch=x86_64")]
    [InlineData("pkg:rpm/suse/tree@1.8.0-3.el9?arch=x86_64")]
    public void RpmHasKnownDistro_NamespacedPurl_ReturnsTrue(string purl)
    {
        Assert.True(PurlNormalizer.RpmHasKnownDistro(purl));
    }

    [Fact]
    public void RpmHasKnownDistro_BarePurl_ReturnsFalse()
    {
        Assert.False(PurlNormalizer.RpmHasKnownDistro("pkg:rpm/tree@1.8.0-3.el9?arch=x86_64"));
    }

    [Fact]
    public void RpmHasKnownDistro_NamespaceNotInKnownSet_ReturnsFalse()
    {
        // A namespace segment is present, but it is not one OSV.dev registers — e.g. a name that
        // happens to contain a slash-shaped qualifier, or a fabricated/unrecognised distro key.
        Assert.False(PurlNormalizer.RpmHasKnownDistro("pkg:rpm/fedora/tree@1.8.0-3.fc40?arch=x86_64"));
    }

    [Fact]
    public void RpmHasKnownDistro_EmptyPurl_ReturnsFalse()
    {
        Assert.False(PurlNormalizer.RpmHasKnownDistro(""));
    }

    [Fact]
    public void RpmHasKnownDistro_NonRpmPurl_ReturnsFalse()
    {
        Assert.False(PurlNormalizer.RpmHasKnownDistro("pkg:npm/rocky-linux@1.0.0"));
    }

    [Fact]
    public void RpmHasKnownDistro_RoundTripsWithRpmNamespaceConstruction()
    {
        // Every namespace Rpm() can emit is one RpmHasKnownDistro recognises, and the bare form it
        // emits by default is one RpmHasKnownDistro rejects — the two members cannot drift apart
        // through this pin.
        foreach (string ns in RpmVendorDistroResolver.KnownNamespaces)
        {
            string namespaced = PurlNormalizer.Rpm("tree", "1.8.0", "3.el9", "x86_64", distroNamespace: ns);
            Assert.True(PurlNormalizer.RpmHasKnownDistro(namespaced));
        }

        string bare = PurlNormalizer.Rpm("tree", "1.8.0", "3.el9", "x86_64");
        Assert.False(PurlNormalizer.RpmHasKnownDistro(bare));
    }
}
