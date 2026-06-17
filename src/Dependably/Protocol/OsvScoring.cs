namespace Dependably.Protocol;

/// <summary>
/// CVSS v3.x scoring and severity-text normalisation. Shared by <see cref="OsvClient"/> and
/// <c>LocalOsvSource</c> so offline scans produce the same numeric scores as remote scans.
/// </summary>
public static class OsvScoring
{
    // CVSS v3 severity band thresholds (CVSS 3.1 specification §8).
    private const double CvssThresholdCritical = 9.0;
    private const double CvssThresholdHigh = 7.0;
    private const double CvssThresholdMedium = 4.0;

    // CVSS v3 rounding algorithm: multiply by 1e5, snap to 1e4 grid, divide back by 1e5.
    // Uses integer arithmetic to avoid floating-point drift (per CVSS spec §7.4).
    private const long CvssRoundingScale = 100000;
    private const long CvssRoundingGrid = 10000;
    private const double CvssRoundingDivisor = 10.0;

    /// <summary>
    /// Parses an OSV severity entry's score field. Some advisories append the numeric score
    /// after the vector ("CVSS:3.1/... 9.8"); fall back to computing from the vector when
    /// only the vector is present. Returns the numeric score and the corresponding
    /// CRITICAL/HIGH/MEDIUM/LOW severity band when a score is produced.
    /// </summary>
    public static (double? Score, string? Severity) ParseCvssBaseScore(string vector)
    {
        string[] parts = vector.Trim().Split(' ');
        if (parts.Length > 1 && double.TryParse(parts[^1],
            System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out double appended))
        {
            return (appended, CvssScoreToSeverity(appended));
        }

        double? computed = ComputeCvss3Score(parts[0]);
        return (computed, computed is not null ? CvssScoreToSeverity(computed.Value) : null);
    }

    public static string CvssScoreToSeverity(double score) => score switch
    {
        >= CvssThresholdCritical => "CRITICAL",
        >= CvssThresholdHigh => "HIGH",
        >= CvssThresholdMedium => "MEDIUM",
        > 0.0 => "LOW",
        _ => "NONE",
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
        {
            return null;
        }

        var metrics = ParseCvssMetrics(vector);
        var values = LookupCvssValues(metrics);
        if (values is null)
        {
            return null;
        }

        var (avVal, acVal, prVal, uiVal, cVal, iVal, aVal, scopeChanged) = values.Value;

        double iscBase = 1.0 - (1.0 - cVal) * (1.0 - iVal) * (1.0 - aVal);
        double isc = scopeChanged
            ? 7.52 * (iscBase - 0.029) - 3.25 * Math.Pow(iscBase - 0.02, 15)
            : 6.42 * iscBase;

        if (isc <= 0)
        {
            return 0.0;
        }

        double exploitability = 8.22 * avVal * acVal * prVal * uiVal;
        double raw = scopeChanged
            ? Math.Min(1.08 * (isc + exploitability), 10.0)
            : Math.Min(isc + exploitability, 10.0);

        return CvssRoundup(raw);
    }

    private static Dictionary<string, string> ParseCvssMetrics(string vector)
    {
        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string? part in vector.Split('/').Skip(1))
        {
            int colon = part.IndexOf(':');
            if (colon > 0)
            {
                metrics[part[..colon]] = part[(colon + 1)..];
            }
        }
        return metrics;
    }

    private static (double Av, double Ac, double Pr, double Ui, double C, double I, double A, bool ScopeChanged)?
        LookupCvssValues(Dictionary<string, string> metrics)
    {
        if (!metrics.TryGetValue("AV", out string? av) ||
            !metrics.TryGetValue("AC", out string? ac) ||
            !metrics.TryGetValue("PR", out string? pr) ||
            !metrics.TryGetValue("UI", out string? ui) ||
            !metrics.TryGetValue("S", out string? s) ||
            !metrics.TryGetValue("C", out string? c) ||
            !metrics.TryGetValue("I", out string? i) ||
            !metrics.TryGetValue("A", out string? a))
        {
            return null;
        }

        bool scopeChanged = s.Equals("C", StringComparison.OrdinalIgnoreCase);

        double avVal = av.ToUpperInvariant() switch { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.20, _ => -1.0 };
        double acVal = ac.ToUpperInvariant() switch { "L" => 0.77, "H" => 0.44, _ => -1.0 };
        double prVal = scopeChanged
            ? pr.ToUpperInvariant() switch { "N" => 0.85, "L" => 0.68, "H" => 0.50, _ => -1.0 }
            : pr.ToUpperInvariant() switch { "N" => 0.85, "L" => 0.62, "H" => 0.27, _ => -1.0 };
        double uiVal = ui.ToUpperInvariant() switch { "N" => 0.85, "R" => 0.62, _ => -1.0 };
        double cVal = c.ToUpperInvariant() switch { "N" => 0.00, "L" => 0.22, "H" => 0.56, _ => -1.0 };
        double iVal = i.ToUpperInvariant() switch { "N" => 0.00, "L" => 0.22, "H" => 0.56, _ => -1.0 };
        double aVal = a.ToUpperInvariant() switch { "N" => 0.00, "L" => 0.22, "H" => 0.56, _ => -1.0 };

        return avVal < 0 || acVal < 0 || prVal < 0 || uiVal < 0 || cVal < 0 || iVal < 0 || aVal < 0
            ? null
            : (avVal, acVal, prVal, uiVal, cVal, iVal, aVal, scopeChanged);
    }

    private static double CvssRoundup(double value)
    {
        long intVal = (long)Math.Round(value * CvssRoundingScale);
        return intVal % CvssRoundingGrid == 0
            ? intVal / (double)CvssRoundingScale
            : (Math.Floor(intVal / (double)CvssRoundingGrid) + 1) / CvssRoundingDivisor;
    }
}
