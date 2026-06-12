using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class MavenPurlNormalizerTests
{
    [Fact]
    public void Maven_BasicCoordinate_FormatsCorrectly()
    {
        Assert.Equal("pkg:maven/com.example/mylib@1.0",
            PurlNormalizer.Maven("com.example", "mylib", "1.0"));
    }

    [Fact]
    public void Maven_DeepGroup_PreservesDots()
    {
        Assert.Equal("pkg:maven/org.apache.commons/commons-lang3@3.14.0",
            PurlNormalizer.Maven("org.apache.commons", "commons-lang3", "3.14.0"));
    }

    [Fact]
    public void Maven_Snapshot_PreservesSuffix()
    {
        Assert.Equal("pkg:maven/com.example/lib@1.0-SNAPSHOT",
            PurlNormalizer.Maven("com.example", "lib", "1.0-SNAPSHOT"));
    }
}
