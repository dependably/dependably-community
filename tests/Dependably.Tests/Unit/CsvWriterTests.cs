using System.Text;
using Dependably.Api;
using Xunit;

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

    [Fact]
    public void WriteRow_joins_with_commas_and_appends_CRLF()
    {
        var sb = new StringBuilder();
        CsvWriter.WriteRow(sb, "a", "b,c", "d\"e", null);
        Assert.Equal("a,\"b,c\",\"d\"\"e\",\r\n", sb.ToString());
    }
}
