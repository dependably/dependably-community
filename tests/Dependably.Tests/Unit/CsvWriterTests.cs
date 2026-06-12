using System.Text;
using Dependably.Api;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class CsvWriterTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("", "")]
    [InlineData("with,comma", "\"with,comma\"")]
    [InlineData("with\"quote", "\"with\"\"quote\"")]
    [InlineData("line\r\nbreak", "\"line\r\nbreak\"")]
    [InlineData("just\nnewline", "\"just\nnewline\"")]
    public void EscapeField_quotes_only_when_required(string input, string expected)
    {
        Assert.Equal(expected, CsvWriter.EscapeField(input));
    }

    [Fact]
    public void EscapeField_null_returns_empty()
    {
        Assert.Equal("", CsvWriter.EscapeField(null));
    }

    [Theory]
    // OWASP CSV-injection guard: a leading formula trigger gets a single-quote prefix
    // and is force-quoted so spreadsheets render the field as text.
    [InlineData("=1+1", "\"'=1+1\"")]
    [InlineData("=cmd|' /C calc'!A0", "\"'=cmd|' /C calc'!A0\"")]
    [InlineData("+1234567890", "\"'+1234567890\"")]
    [InlineData("-2+3", "\"'-2+3\"")]
    [InlineData("@SUM(A1:A9)", "\"'@SUM(A1:A9)\"")]
    [InlineData("\tleading-tab", "\"'\tleading-tab\"")]
    [InlineData("\rleading-cr", "\"'\rleading-cr\"")]
    public void EscapeField_neutralizes_leading_formula_triggers(string input, string expected)
    {
        Assert.Equal(expected, CsvWriter.EscapeField(input));
    }

    [Theory]
    // Triggers are only neutralized at position 0 — embedded occurrences are data.
    [InlineData("a=b", "a=b")]
    [InlineData("user+tag@example.test", "user+tag@example.test")]
    [InlineData("pkg:npm/left-pad@1.3.0", "pkg:npm/left-pad@1.3.0")]
    [InlineData("2026-06-09T00:00:00Z", "2026-06-09T00:00:00Z")]
    public void EscapeField_leaves_embedded_trigger_chars_alone(string input, string expected)
    {
        Assert.Equal(expected, CsvWriter.EscapeField(input));
    }

    [Fact]
    public void WriteRow_joins_with_commas_and_appends_CRLF()
    {
        var sb = new StringBuilder();
        CsvWriter.WriteRow(sb, "a", "b,c", "d\"e", null);
        Assert.Equal("a,\"b,c\",\"d\"\"e\",\r\n", sb.ToString());
    }
}
