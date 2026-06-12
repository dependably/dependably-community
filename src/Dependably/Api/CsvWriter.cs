using System.Text;

namespace Dependably.Api;

/// <summary>
/// Minimal RFC 4180-conformant CSV writer used by audit/activity export. Quotes only
/// the fields that need it (contain <c>,</c>, <c>"</c>, <c>\r</c>, or <c>\n</c>);
/// embedded quotes are doubled. Newline is CRLF per the spec so Excel and other
/// spreadsheet tools round-trip the file without locale-dependent re-quoting.
/// Fields starting with a spreadsheet formula trigger (<c>=</c>, <c>+</c>, <c>-</c>,
/// <c>@</c>, TAB, or CR) are prefixed with a single quote and force-quoted, per OWASP
/// CSV-injection guidance, so attacker-influenced values (package versions, emails)
/// render as text instead of executing when an auditor opens the export.
/// </summary>
internal static class CsvWriter
{
    public static string EscapeField(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        bool formulaTrigger = value[0] is '=' or '+' or '-' or '@' or '\t' or '\r';
        if (formulaTrigger)
        {
            value = "'" + value;
        }

        bool needsQuote = formulaTrigger || value.IndexOfAny([',', '"', '\r', '\n']) >= 0;
        return !needsQuote ? value : "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    public static void WriteRow(StringBuilder sb, params string?[] fields)
    {
        for (int i = 0; i < fields.Length; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append(EscapeField(fields[i]));
        }
        sb.Append("\r\n");
    }
}
