using Dependably.Api;
using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Precedence between the two things that describe a component: this tenant's own registry row —
/// written from the artifact manifest the instance fetched and hashed, on the hosted publish path
/// and the proxy first-fetch path alike — and the uploaded SBOM's component entry.
///
/// <para>The registry wins. An SBOM is a third party's account of a component, and it can be
/// stale or describe a different build of the same coordinate; the registry's copy came from the
/// bytes this instance actually holds. These facts pin that direction, and — just as importantly
/// — pin that the preference is per field, so a partial registry row cannot blank out what the
/// document did carry.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ComponentMetadataPrecedenceTests
{
    private static AnalysisComponentRow SbomRow(
        string? description = null, string? author = null, string? website = null, string? vcs = null) =>
        new()
        {
            Id = "c1",
            Name = "left-pad",
            Description = description,
            ComponentAuthor = author,
            WebsiteUrl = website,
            VcsUrl = vcs,
        };

    private static ComponentRegistryFacts Facts(
        string? description = null, string? author = null, string? homepage = null, string? repository = null) =>
        new(
            Hosted: true, Cached: false, UpstreamLatestVersion: null,
            BlockedThisVersion: false, BlockedAnyVersion: false,
            DeprecatedThisVersion: false, DeprecatedAnyVersion: false,
            HasInstallScriptThisVersion: false,
            Description: description, Author: author, Homepage: homepage, RepositoryUrl: repository);

    [Fact]
    public void RegistryValuesWinOverTheSbomsOwnClaims()
    {
        var resolved = ComponentMetadataResolver.Resolve(
            SbomRow(
                description: "stale description from the document",
                author: "Document Author",
                website: "https://sbom.example/home",
                vcs: "https://sbom.example/repo"),
            Facts(
                description: "what the manifest says",
                author: "Manifest Author",
                homepage: "https://registry.example/home",
                repository: "https://registry.example/repo"));

        Assert.Equal("what the manifest says", resolved.Description);
        Assert.Equal("Manifest Author", resolved.Author);
        Assert.Equal("https://registry.example/home", resolved.WebsiteUrl);
        Assert.Equal("https://registry.example/repo", resolved.VcsUrl);
        Assert.Equal(ComponentMetadataSources.Registry, resolved.Source);
    }

    [Fact]
    public void SbomFillsOnlyTheFieldsTheRegistryHasNoAnswerFor()
    {
        var resolved = ComponentMetadataResolver.Resolve(
            SbomRow(description: "from the document", author: "Document Author"),
            Facts(description: "from the manifest"));

        // The registry knew the description and nothing else. Preferring the whole registry
        // record whenever any part of it exists would discard a real author to fill a gap with
        // nothing, so the fallback is per field.
        Assert.Equal("from the manifest", resolved.Description);
        Assert.Equal("Document Author", resolved.Author);
        Assert.Equal(ComponentMetadataSources.Mixed, resolved.Source);
    }

    [Fact]
    public void FallsBackEntirelyToTheSbomForACoordinateTheRegistryHasNeverServed()
    {
        // The ordinary case: a component the tenant only ever read about in an uploaded document.
        var resolved = ComponentMetadataResolver.Resolve(
            SbomRow(description: "from the document", author: "Document Author"), facts: null);

        Assert.Equal("from the document", resolved.Description);
        Assert.Equal("Document Author", resolved.Author);
        Assert.Equal(ComponentMetadataSources.Sbom, resolved.Source);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ABlankRegistryValueIsAbsent(string blank)
    {
        // A blank column is not the registry answering "nothing"; treating it as an answer would
        // suppress a real value the document carried and render an empty row.
        var resolved = ComponentMetadataResolver.Resolve(
            SbomRow(description: "from the document"), Facts(description: blank));

        Assert.Equal("from the document", resolved.Description);
        Assert.Equal(ComponentMetadataSources.Sbom, resolved.Source);
    }

    [Fact]
    public void ReportsNoSourceWhenNeitherPlaneDescribesTheComponent()
    {
        var resolved = ComponentMetadataResolver.Resolve(SbomRow(), Facts());

        Assert.Null(resolved.Description);
        Assert.Null(resolved.Author);
        // Null rather than a source name: the panel renders no provenance line for an empty
        // section instead of claiming one of the two planes said nothing.
        Assert.Null(resolved.Source);
    }

    [Fact]
    public void ResolutionDoesNotMutateTheStoredSbomClaim()
    {
        var row = SbomRow(description: "the document's own words");
        ComponentMetadataResolver.Resolve(row, Facts(description: "the manifest's words"));

        // Precedence is a read-time decision. sbom_components keeps what was ingested, so an
        // export re-emits the document and a later registry fetch can change what is displayed
        // without anyone re-uploading.
        Assert.Equal("the document's own words", row.Description);
    }
}
