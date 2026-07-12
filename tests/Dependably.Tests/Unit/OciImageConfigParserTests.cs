using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Parses the SPDX license expression from an OCI image config blob's
/// <c>config.Labels["org.opencontainers.image.licenses"]</c> label. Property names are
/// case-sensitive per the OCI image spec; malformed, absent, or implausible values yield null so
/// the recorder stamps a label-less image without a bogus license.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciImageConfigParserTests
{
    private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void ParseLicensesLabel_LabelPresent_ReturnsValue()
    {
        string json = """
        { "config": { "Labels": { "org.opencontainers.image.licenses": "MIT" } } }
        """;

        Assert.Equal("MIT", OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }

    [Fact]
    public void ParseLicensesLabel_CompoundExpression_ReturnedVerbatim()
    {
        string json = """
        { "config": { "Labels": { "org.opencontainers.image.licenses": "GPL-3.0-only AND MIT" } } }
        """;

        Assert.Equal("GPL-3.0-only AND MIT", OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }

    [Fact]
    public void ParseLicensesLabel_ValueTrimmed()
    {
        string json = """
        { "config": { "Labels": { "org.opencontainers.image.licenses": "  Apache-2.0  " } } }
        """;

        Assert.Equal("Apache-2.0", OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }

    [Fact]
    public void ParseLicensesLabel_MissingLabel_ReturnsNull()
    {
        string json = """
        { "config": { "Labels": { "org.opencontainers.image.title": "demo" } } }
        """;

        Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }

    [Fact]
    public void ParseLicensesLabel_MissingLabels_ReturnsNull()
        => Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes("""{ "config": { } }""")));

    [Fact]
    public void ParseLicensesLabel_MissingConfig_ReturnsNull()
        => Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes("""{ "architecture": "amd64" }""")));

    [Fact]
    public void ParseLicensesLabel_MalformedJson_ReturnsNull()
        => Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes("{ not json")));

    [Fact]
    public void ParseLicensesLabel_NonObjectRoot_ReturnsNull()
        => Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes("[]")));

    [Fact]
    public void ParseLicensesLabel_CaseSensitiveLabelsProperty_ReturnsNull()
    {
        // Lowercase "labels" is not the OCI spec key — must not match.
        string json = """
        { "config": { "labels": { "org.opencontainers.image.licenses": "MIT" } } }
        """;

        Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }

    [Fact]
    public void ParseLicensesLabel_ValueWithNewlines_ReturnsNull()
    {
        string json = """
        { "config": { "Labels": { "org.opencontainers.image.licenses": "MIT\nrogue" } } }
        """;

        Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }

    [Fact]
    public void ParseLicensesLabel_OverlongJunkValue_ReturnsNull()
    {
        string junk = new('x', 500);
        string json = $$"""
        { "config": { "Labels": { "org.opencontainers.image.licenses": "{{junk}}" } } }
        """;

        Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }

    [Fact]
    public void ParseLicensesLabel_NonStringValue_ReturnsNull()
    {
        string json = """
        { "config": { "Labels": { "org.opencontainers.image.licenses": 123 } } }
        """;

        Assert.Null(OciImageConfigParser.ParseLicensesLabel(Bytes(json)));
    }
}
