using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Unit coverage for <see cref="RpmLicenseMapper"/>: the Fedora/RHEL short-tag → SPDX
/// mapping table, case-insensitivity, whitespace trimming, and the pass-through
/// (verbatim) behavior for compound/ambiguous/already-SPDX tags.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmLicenseMapperTests
{
    [Theory]
    [InlineData("GPLv2", "GPL-2.0-only")]
    [InlineData("GPLv2+", "GPL-2.0-or-later")]
    [InlineData("GPLv3", "GPL-3.0-only")]
    [InlineData("GPLv3+", "GPL-3.0-or-later")]
    [InlineData("LGPLv2", "LGPL-2.1-only")]
    [InlineData("LGPLv2+", "LGPL-2.1-or-later")]
    [InlineData("LGPLv3", "LGPL-3.0-only")]
    [InlineData("LGPLv3+", "LGPL-3.0-or-later")]
    [InlineData("ASL 2.0", "Apache-2.0")]
    [InlineData("ASL 1.1", "Apache-1.1")]
    [InlineData("MIT", "MIT")]
    [InlineData("ISC", "ISC")]
    [InlineData("MPLv2.0", "MPL-2.0")]
    [InlineData("MPLv1.1", "MPL-1.1")]
    [InlineData("zlib", "Zlib")]
    public void ToSpdx_MapsKnownFedoraShortTags(string rawTag, string expectedSpdx)
    {
        Assert.Equal(expectedSpdx, RpmLicenseMapper.ToSpdx(rawTag));
    }

    [Theory]
    [InlineData("gplv2+")]
    [InlineData("GPLV2+")]
    [InlineData("GplV2+")]
    public void ToSpdx_IsCaseInsensitive(string rawTag)
    {
        Assert.Equal("GPL-2.0-or-later", RpmLicenseMapper.ToSpdx(rawTag));
    }

    [Theory]
    [InlineData("  GPLv2+  ", "GPL-2.0-or-later")]
    [InlineData("\tMIT\t", "MIT")]
    public void ToSpdx_TrimsWhitespaceBeforeMapping(string rawTag, string expected)
    {
        Assert.Equal(expected, RpmLicenseMapper.ToSpdx(rawTag));
    }

    [Theory]
    [InlineData("GPLv2+ and BSD")]
    [InlineData("MIT or Apache-2.0")]
    [InlineData("(MIT AND BSD)")]
    [InlineData("GPLv2+ and (LGPLv2+ or BSD)")]
    public void ToSpdx_CompoundBooleanExpressions_PassThroughVerbatim(string compound)
    {
        Assert.Equal(compound, RpmLicenseMapper.ToSpdx(compound));
    }

    [Fact]
    public void ToSpdx_PublicDomain_IsAmbiguous_PassesThroughVerbatim()
    {
        Assert.Equal("Public Domain", RpmLicenseMapper.ToSpdx("Public Domain"));
    }

    [Fact]
    public void ToSpdx_UnrecognizedTag_PassesThroughVerbatimTrimmed()
    {
        Assert.Equal("Some Weird License", RpmLicenseMapper.ToSpdx("  Some Weird License  "));
    }

    [Fact]
    public void ToSpdx_AlreadySpdxExpression_NotInMapperTable_PassesThroughVerbatim()
    {
        // Modern (post-2023) Fedora packages carry a real SPDX expression already —
        // the mapper doesn't parse it, it just isn't a recognized legacy short tag,
        // so it passes through unchanged.
        Assert.Equal("BSD-3-Clause", RpmLicenseMapper.ToSpdx("BSD-3-Clause"));
    }

    [Fact]
    public void ToSpdx_Empty_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, RpmLicenseMapper.ToSpdx(""));
    }

    [Fact]
    public void ToSpdx_WhitespaceOnly_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, RpmLicenseMapper.ToSpdx("   "));
    }
}
