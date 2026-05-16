using System.Text;

namespace Dependably.Api;

/// <summary>
/// Minimal RFC 4180-conformant CSV writer used by audit/activity export. Quotes only
/// the fields that need it (contain <c>,</c>, <c>"</c>, <c>\r</c>, or <c>\n</c>);
/// embedded quotes are doubled. Newline is CRLF per the spec so Excel and other
/// spreadsheet tools round-trip the file without locale-dependent re-quoting.
/// </summary>
internal static class CsvWriter
{
    public static string EscapeField(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var needsQuote = value.IndexOfAny([',', '"', '\r', '\n']) >= 0;
        if (!needsQuote) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    public static void WriteRow(StringBuilder sb, params string?[] fields)
    {
        for (var i = 0; i < fields.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(EscapeField(fields[i]));
        }
        sb.Append("\r\n");
    }
}
