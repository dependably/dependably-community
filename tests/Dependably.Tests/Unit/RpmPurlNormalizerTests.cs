using Dependably.Protocol;
using Xunit;

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
}
