namespace Dependably.Protocol;

/// <summary>
/// CVSS v3.x scoring and severity-text normalisation. Shared by <see cref="OsvClient"/> and
/// <c>LocalOsvSource</c> so offline scans produce the same numeric scores as remote scans.
/// </summary>
public static class OsvScoring
{
    /// <summary>
    /// Parses an OSV severity entry's score field. Some advisories append the numeric score
    /// after the vector ("CVSS:3.1/... 9.8"); fall back to computing from the vector when
    /// only the vector is present. Sets <paramref name="severity"/> to the corresponding
    /// CRITICAL/HIGH/MEDIUM/LOW band when a score is produced.
    /// </summary>
    public static double? ParseCvssBaseScore(string vector, out string? severity)
    {
        severity = null;

        var parts = vector.Trim().Split(' ');
        if (parts.Length > 1 && double.TryParse(parts[^1],
            System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var appended))
        {
            severity = CvssScoreToSeverity(appended);
            return appended;
        }

        var computed = ComputeCvss3Score(parts[0]);
        if (computed is not null)
            severity = CvssScoreToSeverity(computed.Value);
        return computed;
    }

    public static string CvssScoreToSeverity(double score) => score switch
    {
        >= 9.0 => "CRITICAL",
        >= 7.0 => "HIGH",
        >= 4.0 => "MEDIUM",
        >  0.0 => "LOW",
        _      => "NONE",
    };

    public static string? NormalizeSeverity(string? raw) => raw?.ToUpperInvariant() switch
    {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" or "MODERATE" => "MEDIUM",
        "LOW" => "LOW",
        _ => raw,
    };

    /// <summary>
    /// Computes the CVSS v3.x base score from a vector string using the official formula.
    /// Handles both CVSS:3.0 and CVSS:3.1. Returns null if the vector cannot be parsed.
    /// </summary>
    public static double? ComputeCvss3Score(string vector)
    {
        if (!vector.StartsWith("CVSS:3.", StringComparison.OrdinalIgnoreCase))
            return null;

        var metrics = ParseCvssMetrics(vector);
        var values = LookupCvssValues(metrics);
        if (values is null) return null;
        var (avVal, acVal, prVal, uiVal, cVal, iVal, aVal, scopeChanged) = values.Value;

        var iscBase = 1.0 - (1.0 - cVal) * (1.0 - iVal) * (1.0 - aVal);
        var isc = scopeChanged
            ? 7.52 * (iscBase - 0.029) - 3.25 * Math.Pow(iscBase - 0.02, 15)
            : 6.42 * iscBase;

        if (isc <= 0) return 0.0;

        var exploitability = 8.22 * avVal * acVal * prVal * uiVal;
        var raw = scopeChanged
            ? Math.Min(1.08 * (isc + exploitability), 10.0)
            : Math.Min(isc + exploitability, 10.0);

        return CvssRoundup(raw);
    }

    private static Dictionary<string, string> ParseCvssMetrics(string vector)
    {
        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in vector.Split('/').Skip(1))
        {
            var colon = part.IndexOf(':');
            if (colon > 0) metrics[part[..colon]] = part[(colon + 1)..];
        }
        return metrics;
    }

    private static (double Av, double Ac, double Pr, double Ui, double C, double I, double A, bool ScopeChanged)?
        LookupCvssValues(Dictionary<string, string> metrics)
    {
        if (!metrics.TryGetValue("AV", out var av) ||
            !metrics.TryGetValue("AC", out var ac) ||
            !metrics.TryGetValue("PR", out var pr) ||
            !metrics.TryGetValue("UI", out var ui) ||
            !metrics.TryGetValue("S",  out var s)  ||
            !metrics.TryGetValue("C",  out var c)  ||
            !metrics.TryGetValue("I",  out var i)  ||
            !metrics.TryGetValue("A",  out var a))
            return null;

        var scopeChanged = s.Equals("C", StringComparison.OrdinalIgnoreCase);

        var avVal = av.ToUpperInvariant() switch { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.20, _ => -1.0 };
        var acVal = ac.ToUpperInvariant() switch { "L" => 0.77, "H" => 0.44, _ => -1.0 };
        var prVal = scopeChanged
            ? pr.ToUpperInvariant() switch { "N" => 0.85, "L" => 0.68, "H" => 0.50, _ => -1.0 }
            : pr.ToUpperInvariant() switch { "N" => 0.85, "L" => 0.62, "H" => 0.27, _ => -1.0 };
        var uiVal = ui.ToUpperInvariant() switch { "N" => 0.85, "R" => 0.62, _ => -1.0 };
        var cVal  = c.ToUpperInvariant()  switch { "N" => 0.00, "L" => 0.22, "H" => 0.56, _ => -1.0 };
        var iVal  = i.ToUpperInvariant()  switch { "N" => 0.00, "L" => 0.22, "H" => 0.56, _ => -1.0 };
        var aVal  = a.ToUpperInvariant()  switch { "N" => 0.00, "L" => 0.22, "H" => 0.56, _ => -1.0 };

        if (avVal < 0 || acVal < 0 || prVal < 0 || uiVal < 0 || cVal < 0 || iVal < 0 || aVal < 0)
            return null;

        return (avVal, acVal, prVal, uiVal, cVal, iVal, aVal, scopeChanged);
    }

    private static double CvssRoundup(double value)
    {
        var intVal = (long)Math.Round(value * 100000);
        return intVal % 10000 == 0 ? intVal / 100000.0 : (Math.Floor(intVal / 10000.0) + 1) / 10.0;
    }
}
