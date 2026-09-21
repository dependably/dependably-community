using System.Text.Json;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// CISA D13a/D13d: <see cref="SbomAdditionalIdentifiers"/>'s two overflow rules — a whole-array
/// bound that keeps a prefix instead of dropping everything, and a per-value bound that drops an
/// over-long identifier instead of truncating it.
///
/// <para><b>Why "drop the whole set" is not merely lossy but WRONG.</b> The very column this class
/// serializes is what <c>SbomExportService</c> reads to decide whether to emit a POSITIVE
/// <c>dependably:identifier-status = "unknown"</c> claim (CISA's two-state unknown/withheld
/// vocabulary) — a component whose document asserted forty SWHIDs and whose stored column ended
/// up NULL because all forty together exceeded the old 2000-char bound would render with that
/// claim, which is false: the author did not fail to assert an identifier, this codebase failed to
/// keep any of the ones it was given. Bulk intrinsic identifiers (many SWHIDs/OmniBOR ids for one
/// component) are exactly the use case D13c exists to serve, not a pathological input — the
/// threshold that turned this from lossy into false was reachable at roughly 25 ordinary-sized
/// SWHID entries.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomAdditionalIdentifiersTests
{
    private static (string Kind, string Value) SwhidEntry(int i) =>
        ("swhid", $"swh:1:cnt:{i:D8}ed024d3859793618152ea559a168bbcbb5{i % 10}");

    /// <summary>
    /// Two hundred SWHID-sized entries — comfortably past ANY reasonable whole-array bound,
    /// including a much wider one than the original 2000-char ceiling the finding reproduced
    /// against (40 SWHID-sized entries already overflowed that one). The mutant this catches is
    /// the PREVIOUS all-or-nothing implementation itself — reverting
    /// <see cref="SbomAdditionalIdentifiers.Serialize"/> to "drop the whole array when the full
    /// serialization exceeds the bound" turns this red because the result becomes null (every
    /// entry lost) instead of a non-empty prefix. The count is deliberately generous rather than
    /// tuned to the exact current bound, so a future widening of the ceiling does not silently
    /// stop this test from ever overflowing anything.
    /// </summary>
    [Fact]
    public void Serialize_WithManyEntries_KeepsANonEmptyPrefixInsteadOfDroppingTheWholeSet()
    {
        var many = Enumerable.Range(0, 200).Select(SwhidEntry).ToList();

        string? json = SbomAdditionalIdentifiers.Serialize(many);

        Assert.NotNull(json);
        var kept = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json)!;
        Assert.True(kept.Count > 0, "Expected at least one entry to survive; the whole set was dropped.");
        // Proves the fixture actually overflows the bound (rather than this assertion passing
        // vacuously because every entry happened to fit) — a genuine partial keep, not a full one.
        Assert.True(
            kept.Count < many.Count,
            $"Expected the 200-entry input to overflow the bound and drop some entries; all {kept.Count} survived.");

        // Every kept entry must be a VERBATIM match against one of the inputs — never a truncated
        // fragment of one (that would be finding 6's defect wearing finding 1's clothes).
        var inputValues = many.Select(e => e.Value).ToHashSet(StringComparer.Ordinal);
        foreach (var entry in kept)
        {
            Assert.Equal("swhid", entry["kind"]);
            Assert.Contains(entry["value"], inputValues);
        }

        // Kept entries are a PREFIX, in the original order — not an arbitrary subset.
        for (int i = 0; i < kept.Count; i++)
        {
            Assert.Equal(many[i].Value, kept[i]["value"]);
        }
    }

    /// <summary>A small set well under the bound round-trips whole — the ordinary case is not narrowed by the overflow guard.</summary>
    [Fact]
    public void Serialize_WithFewEntries_KeepsAllOfThem()
    {
        var few = new List<(string Kind, string Value)>
        {
            ("cpe", "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"),
            ("swhid", "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"),
        };

        string? json = SbomAdditionalIdentifiers.Serialize(few);

        Assert.NotNull(json);
        var kept = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json)!;
        Assert.Equal(2, kept.Count);
    }

    [Fact]
    public void Serialize_WithNoEntries_ReturnsNull()
    {
        Assert.Null(SbomAdditionalIdentifiers.Serialize([]));
    }

    /// <summary>
    /// D13c/D13d + finding 6: an identifier is an IDENTITY, not presentation text — a truncated
    /// CPE is a DIFFERENT, wrong CPE the export boundary would then assert as the component's
    /// identity, not a shorter version of the right one. <see cref="SbomAdditionalIdentifiers.AcceptValue"/>
    /// must drop an over-long value whole rather than clip it.
    /// </summary>
    [Fact]
    public void AcceptValue_WithAnOverLongIdentifier_DropsItWholeRatherThanTruncatingIt()
    {
        string overLong = "cpe:2.3:a:acme:" + new string('x', 500) + ":1.0:*:*:*:*:*:*:*";

        string? accepted = SbomAdditionalIdentifiers.AcceptValue(overLong);

        Assert.Null(accepted);
    }

    [Fact]
    public void AcceptValue_WithAnOrdinaryIdentifier_ReturnsItUnchanged()
    {
        const string ordinary = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*";

        Assert.Equal(ordinary, SbomAdditionalIdentifiers.AcceptValue(ordinary));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AcceptValue_WithNoRealValue_ReturnsNull(string? raw)
    {
        Assert.Null(SbomAdditionalIdentifiers.AcceptValue(raw));
    }

    /// <summary>
    /// The finding-6 mutant, exercised through the real ingest entry point rather than only the
    /// helper directly: an over-long CPE on a component that ALSO carries a normal SWHID must
    /// drop only the CPE, verbatim-or-absent, never a truncated prefix of it — and must not take
    /// the SWHID down with it.
    /// </summary>
    [Fact]
    public void CycloneDxParser_WithAnOverLongCpeAlongsideANormalSwhid_DropsOnlyTheCpeWhole()
    {
        string overLongCpe = "cpe:2.3:a:acme:" + new string('x', 500) + ":1.0:*:*:*:*:*:*:*";
        const string swhid = "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2";
        string document = $$"""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.7",
              "components": [
                {
                  "type": "library", "name": "over-long-cpe-widget", "version": "1.0.0",
                  "cpe": "{{overLongCpe}}",
                  "swhid": ["{{swhid}}"]
                }
              ]
            }
            """;

        var parsed = CycloneDxParser.Parse(JsonDocument.Parse(document).RootElement);
        string? json = Assert.Single(parsed.Components).AdditionalIdentifiersJson;

        Assert.NotNull(json);
        Assert.DoesNotContain(overLongCpe[..100], json, StringComparison.Ordinal);
        Assert.Contains(swhid, json, StringComparison.Ordinal);
    }
}
