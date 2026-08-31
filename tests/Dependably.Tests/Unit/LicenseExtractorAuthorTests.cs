using System.Text.Json.Nodes;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// The author half of the manifest parse, per ecosystem.
///
/// <para>Author is captured from the same manifest read that already yields homepage,
/// repository and description — on the hosted publish path and on the proxy first-fetch path
/// alike, since both call the same extractor. Each ecosystem spells it differently, and a shape
/// this parser does not know produces null rather than an exception, so a miss is silent: these
/// facts are what make it loud.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseExtractorAuthorTests
{
    [Fact]
    public void NpmReadsTheAuthorObjectsNameHalf()
    {
        var version = JsonNode.Parse("""
            { "name": "left-pad", "author": { "name": "Ada", "email": "ada@example.com" } }
            """);

        // Only the name is displayed: the email and url halves of the object are contact details
        // nothing in the UI renders, and storing them would put an address at rest for no reader.
        Assert.Equal("Ada", LicenseExtractor.FromNpmPackumentVersion(version).Author);
    }

    [Fact]
    public void NpmReadsTheAuthorStringForm()
    {
        var version = JsonNode.Parse("""{ "name": "x", "author": "Ada <ada@example.com>" }""");
        Assert.Equal("Ada <ada@example.com>", LicenseExtractor.FromNpmPackumentVersion(version).Author);
    }

    [Fact]
    public void NpmLeavesAuthorNullWhenTheManifestOmitsIt()
    {
        var version = JsonNode.Parse("""{ "name": "x", "description": "no author here" }""");
        var extracted = LicenseExtractor.FromNpmPackumentVersion(version);

        // The negative twin: description still lands, so a null author means "the manifest said
        // nothing", not "the parse fell over and dropped everything".
        Assert.Null(extracted.Author);
        Assert.Equal("no author here", extracted.Description);
    }

    [Fact]
    public void NuspecReadsTheAuthorsElement()
    {
        string nuspec = """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Serilog</id>
                <authors>Serilog Contributors</authors>
                <description>Simple .NET logging.</description>
              </metadata>
            </package>
            """;

        var extracted = LicenseExtractor.FromNuspecXml(nuspec);
        Assert.Equal("Serilog Contributors", extracted.Author);
        Assert.Equal("Simple .NET logging.", extracted.Description);
    }

    [Fact]
    public void PresentationOnlyCarriesAnAuthorAndStillDefaultsToNull()
    {
        Assert.Equal("Ada", LicenseExtractor.PresentationOnly(null, null, null, "Ada").Author);
        // The default keeps every existing three-argument call site meaning what it always did.
        Assert.Null(LicenseExtractor.PresentationOnly("https://example.com", null, null).Author);
    }
}
