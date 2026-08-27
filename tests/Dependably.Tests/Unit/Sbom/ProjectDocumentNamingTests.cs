using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The derived download filename. Shared by the documents list and the original-download response,
/// so a change here moves both at once — which is the whole reason it is one helper.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProjectDocumentNamingTests
{
    [Fact]
    public void FileName_IsProjectVersionAndDocType()
    {
        Assert.Equal("storefront-1.4.0-sbom.json", ProjectDocumentNaming.FileName("storefront", "1.4.0", "sbom"));
    }

    [Theory]
    // Path separators are the whole point: neither may survive into a Content-Disposition name.
    [InlineData("acme/storefront", "1.0.0", "vex", "acme-storefront-1.0.0-vex.json")]
    [InlineData("acme\\storefront", "1.0.0", "vex", "acme-storefront-1.0.0-vex.json")]
    [InlineData("../../etc/passwd", "1.0.0", "sbom", "etc-passwd-1.0.0-sbom.json")]
    // Quotes and control characters would break the header itself.
    [InlineData("say \"hi\"", "1.0.0", "sarif", "say-hi-1.0.0-sarif.json")]
    [InlineData("line\r\nbreak", "1.0.0", "sarif", "line-break-1.0.0-sarif.json")]
    // Non-ASCII folds rather than travelling raw.
    [InlineData("café", "1.0.0", "sbom", "caf-1.0.0-sbom.json")]
    // Spaces and repeated separators collapse.
    [InlineData("  spaced   out  ", "v 2", "sbom", "spaced-out-v-2-sbom.json")]
    public void FileName_SanitizesEveryComponent(string project, string version, string docType, string expected)
    {
        Assert.Equal(expected, ProjectDocumentNaming.FileName(project, version, docType));
    }

    [Theory]
    [InlineData(null, null, null, "document.json")]
    [InlineData("", "", "", "document.json")]
    [InlineData("///", "***", "!!!", "document.json")]
    public void FileName_NeverProducesADotfileOrABareExtension(string? project, string? version, string? docType, string expected)
    {
        Assert.Equal(expected, ProjectDocumentNaming.FileName(project, version, docType));
    }

    [Fact]
    public void FileName_KeepsWhicheverComponentsSurvive()
    {
        Assert.Equal("storefront-sbom.json", ProjectDocumentNaming.FileName("storefront", "  ", "sbom"));
    }

    [Fact]
    public void FileName_IsDeterministic()
    {
        // The name is derived on every read rather than stored, so two independent calls have to
        // agree — that agreement is what keeps the list and the download from disagreeing.
        Assert.Equal(
            ProjectDocumentNaming.FileName("acme/storefront", "1.4.0", "sbom"),
            ProjectDocumentNaming.FileName("acme/storefront", "1.4.0", "sbom"));
    }
}
