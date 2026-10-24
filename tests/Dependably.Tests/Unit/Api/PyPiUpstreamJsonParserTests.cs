using System.Text;
using Dependably.Api.PyPiProtocol;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// First-fetch parsing of the PyPI JSON API response (<see cref="PyPiUpstreamJsonParser"/>): the
/// <c>urls[]</c> entry for the requested file supplies its upload time, SHA-256, yank status and
/// PEP 740 provenance URL, and any shape it cannot read degrades to
/// <see cref="PyPiJsonMetadata.Empty"/> instead of failing the fetch.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiUpstreamJsonParserTests
{
    private const string Wheel = "requests-2.32.3-py3-none-any.whl";

    private static PyPiJsonMetadata Parse(string json) =>
        PyPiUpstreamJsonParser.ParseUrlsArrayForFile(Encoding.UTF8.GetBytes(json), Wheel);

    [Fact]
    public void Matching_entry_supplies_upload_time_digest_and_provenance()
    {
        var result = Parse("""
            {
              "urls": [
                {
                  "filename": "requests-2.32.3.tar.gz",
                  "upload_time_iso_8601": "2020-01-01T00:00:00Z",
                  "digests": { "sha256": "BBBB" }
                },
                {
                  "filename": "requests-2.32.3-py3-none-any.whl",
                  "upload_time_iso_8601": "2024-05-29T15:37:47.027Z",
                  "digests": { "sha256": "70761CFE03C773CEB22AA2F671B4757976145175CDFCA038C02654D061D6DCC6" },
                  "provenance": "https://pypi.org/integrity/requests/2.32.3/requests-2.32.3-py3-none-any.whl/provenance",
                  "yanked": false
                }
              ]
            }
            """);

        Assert.Equal(new DateTimeOffset(2024, 5, 29, 15, 37, 47, 27, TimeSpan.Zero), result.PublishedAt);
        Assert.Equal("70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6", result.Sha256Hex);
        Assert.Null(result.Deprecated);
        Assert.Equal(
            "https://pypi.org/integrity/requests/2.32.3/requests-2.32.3-py3-none-any.whl/provenance",
            result.ProvenanceUrl);
    }

    [Fact]
    public void Filename_match_ignores_case()
    {
        var result = Parse("""
            { "urls": [ { "filename": "Requests-2.32.3-PY3-none-any.whl", "digests": { "sha256": "abc" } } ] }
            """);

        Assert.Equal("abc", result.Sha256Hex);
    }

    [Fact]
    public void Yanked_file_carries_its_trimmed_reason_as_the_deprecation()
    {
        var result = Parse("""
            { "urls": [ { "filename": "requests-2.32.3-py3-none-any.whl", "yanked": true, "yanked_reason": "  broken wheel  " } ] }
            """);

        Assert.Equal("broken wheel", result.Deprecated);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("\"\"")]
    [InlineData("\"   \"")]
    public void Yanked_file_without_a_reason_is_marked_yanked(string reasonJson)
    {
        var result = Parse(
            "{ \"urls\": [ { \"filename\": \"" + Wheel + "\", \"yanked\": true, \"yanked_reason\": " + reasonJson + " } ] }");

        Assert.Equal("Yanked", result.Deprecated);
    }

    [Fact]
    public void Entry_without_optional_fields_yields_empty_fields()
    {
        var result = Parse("""
            { "urls": [ { "filename": "requests-2.32.3-py3-none-any.whl" } ] }
            """);

        Assert.Equal(PyPiJsonMetadata.Empty, result);
    }

    [Fact]
    public void Unparseable_upload_time_and_non_string_digest_are_dropped_individually()
    {
        var result = Parse("""
            {
              "urls": [
                {
                  "filename": "requests-2.32.3-py3-none-any.whl",
                  "upload_time_iso_8601": "yesterday-ish",
                  "digests": { "sha256": 42 },
                  "provenance": null
                }
              ]
            }
            """);

        Assert.Null(result.PublishedAt);
        Assert.Null(result.Sha256Hex);
        Assert.Null(result.ProvenanceUrl);
    }

    [Theory]
    [InlineData("{ \"urls\": [ { \"filename\": \"requests-2.32.3.tar.gz\", \"digests\": { \"sha256\": \"abc\" } } ] }")]
    [InlineData("{ \"urls\": [] }")]
    [InlineData("{ \"urls\": {} }")]
    [InlineData("{ \"info\": {} }")]
    [InlineData("[]")]
    [InlineData("{ not json")]
    [InlineData("")]
    public void Missing_or_unreadable_entry_yields_empty_metadata(string json) =>
        Assert.Equal(PyPiJsonMetadata.Empty, Parse(json));
}
