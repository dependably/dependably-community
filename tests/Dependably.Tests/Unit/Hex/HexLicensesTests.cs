using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Hex;

[Trait("Category", "Unit")]
public sealed class HexLicensesTests
{
    [Fact]
    public void RealDecimalTarball_YieldsApache2()
    {
        using var stream = File.OpenRead(Path.Combine(FixtureManifest.FixturesRoot, "hex", "decimal-2.3.0.tar"));
        var extracted = HexLicenses.FromTarball(stream);
        Assert.Equal(new[] { "Apache-2.0" }, extracted.Spdx);
    }

    [Fact]
    public void MultiLineLicenseList_IsRead()
    {
        var extracted = HexLicenses.FromMetadataText("{<<\"name\">>,<<\"x\">>}.\n{<<\"licenses\">>,\n [<<\"MIT\">>,\n  <<\"Apache-2.0\">>]}.\n");
        Assert.Equal(new[] { "MIT", "Apache-2.0" }, extracted.Spdx);
    }

    [Fact]
    public void NoLicensesKey_OrEmptyList_YieldsEmpty()
    {
        Assert.Empty(HexLicenses.FromMetadataText("{<<\"name\">>,<<\"x\">>}.\n").Spdx);
        Assert.Empty(HexLicenses.FromMetadataText("{<<\"licenses\">>,[]}.\n").Spdx);
    }

    [Fact]
    public void ImplausibleSpdxEntries_AreDropped()
    {
        var extracted = HexLicenses.FromMetadataText("{<<\"licenses\">>,[<<\"MIT\">>,<<\"custom/licence\">>]}.\n");
        Assert.Equal(new[] { "MIT" }, extracted.Spdx);
    }

    [Fact]
    public void NotATarball_YieldsEmpty_AndDisposesTheStream()
    {
        var stream = new MemoryStream("garbage"u8.ToArray());
        Assert.Empty(HexLicenses.FromTarball(stream).Spdx);
        Assert.False(stream.CanRead);
    }
}
