using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class SpdxTextClassifierTests
{
    [Fact]
    public void Classify_ExactMitText_ReturnsMit()
    {
        string mit = SpdxTextFixtures.Text("MIT");
        Assert.Equal("MIT", SpdxTextClassifier.Classify(mit));
    }

    [Fact]
    public void Classify_MangledMitText_MatchesViaDiceFallback()
    {
        // Reflowed line wraps, tab runs, a rewritten copyright line, and an appended
        // vendoring note — none of these survive normalization intact, so the normalized
        // form differs from the canonical MIT text (this exercises the Dice fallback, not
        // the exact-hash path) while staying well inside the similarity threshold.
        string mit = SpdxTextFixtures.Text("MIT");
        string body = mit[(mit.IndexOf("Permission", StringComparison.Ordinal))..];
        string mangled =
            "MIT   License\r\n\r\n" +
            "Copyright (c) 2024 Jane Doe <jane@example.com>\r\n\r\n" +
            body.Replace("Permission is hereby granted", "PERMISSION\tIS\tHEREBY\tgranted", StringComparison.Ordinal) +
            "\nVendored copy included for offline builds.\n";

        Assert.NotEqual(mit, mangled);
        Assert.Equal("MIT", SpdxTextClassifier.Classify(mangled));
    }

    [Fact]
    public void Classify_UnrelatedProse_ReturnsNull()
    {
        string prose = """
            This module implements a small HTTP client wrapper used internally by the
            reconciliation job. It retries transient failures with exponential backoff and
            logs structured events for every attempt. See the README for configuration
            options and default timeouts.
            """;
        Assert.Null(SpdxTextClassifier.Classify(prose));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\n\t \n")]
    public void Classify_EmptyOrWhitespace_ReturnsNull(string text)
    {
        Assert.Null(SpdxTextClassifier.Classify(text));
    }

    // ── Deprecated-id structural guard ──────────────────────────────────────

    [Fact]
    public void Classify_DeprecatedIdText_NeverReturnsADeprecatedId()
    {
        // Corpus construction drops every deprecated id before Classify ever sees it, so no
        // deprecated id can be returned regardless of how similar its text is to anything
        // else. Some deprecated texts (e.g. an "-with-…-exception" snippet, or a genuinely
        // one-off historical license) have no non-deprecated corpus entry within the
        // similarity threshold and correctly classify to null — this loop pins the
        // guarantee that actually holds structurally: never a deprecated id, not "always a
        // confident match".
        var deprecatedIds = SpdxTextFixtures.DeprecatedIds().ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(deprecatedIds);

        foreach (string deprecatedId in deprecatedIds)
        {
            string text = SpdxTextFixtures.Text(deprecatedId);
            string? result = SpdxTextClassifier.Classify(text);
            Assert.False(
                result is not null && deprecatedIds.Contains(result),
                $"Classify({deprecatedId}) returned deprecated id '{result}'.");
        }
    }

    [Theory]
    [InlineData("GPL-2.0", "GPL-2.0-only")]
    [InlineData("GPL-3.0", "GPL-3.0-only")]
    [InlineData("AGPL-3.0", "AGPL-3.0-only")]
    [InlineData("LGPL-2.1", "LGPL-2.1-only")]
    public void Classify_KnownDeprecatedBareId_ResolvesToNonDeprecatedVariant(string deprecatedId, string expected)
    {
        string text = SpdxTextFixtures.Text(deprecatedId);
        Assert.Equal(expected, SpdxTextClassifier.Classify(text));
    }

    // ── Duplicate-text-group tie-break determinism ──────────────────────────

    [Fact]
    public void Classify_GplDuplicateGroup_PrefersOnlyOverOrLater()
    {
        // GPL-2.0-only and GPL-2.0-or-later share byte-for-byte normalized text (SPDX's
        // license text does not itself encode the "or later" clause). The shorter,
        // ordinal-first id wins the tie-break.
        string orLaterText = SpdxTextFixtures.Text("GPL-2.0-or-later");
        Assert.Equal("GPL-2.0-only", SpdxTextClassifier.Classify(orLaterText));
    }

    [Fact]
    public void Classify_MplDuplicateGroup_PrefersPlainMpl()
    {
        string exceptionText = SpdxTextFixtures.Text("MPL-2.0-no-copyleft-exception");
        Assert.Equal("MPL-2.0", SpdxTextClassifier.Classify(exceptionText));
    }

    [Fact]
    public void Classify_CalDuplicateGroup_PrefersPlainCal()
    {
        string combinedWorkText = SpdxTextFixtures.Text("CAL-1.0-Combined-Work-Exception");
        Assert.Equal("CAL-1.0", SpdxTextClassifier.Classify(combinedWorkText));
    }

    [Fact]
    public void Classify_OflDuplicateGroup_PrefersPlainOfl11()
    {
        string rfnText = SpdxTextFixtures.Text("OFL-1.1-RFN");
        Assert.Equal("OFL-1.1", SpdxTextClassifier.Classify(rfnText));
    }
}
