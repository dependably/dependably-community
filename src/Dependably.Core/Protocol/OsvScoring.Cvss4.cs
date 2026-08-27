// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// This file is a faithful port of FIRST.org's own reference CVSS v4.0 calculator
// (https://github.com/FIRSTdotorg/cvss-v4-calculator — cvss_lookup.js, cvss_score.js,
// max_composed.js, max_severity.js), which upstream ships under the same BSD-2-Clause licence
// carried above. CVSS v4.0 has no closed-form scoring equation — scoring reduces the vector to a
// six-digit MacroVector, looks it up in the 270-entry table below, then interpolates against
// neighbouring MacroVectors — so this file transcribes FIRST's own table and algorithm rather
// than re-deriving one from the specification prose.

namespace Dependably.Protocol;

public static partial class OsvScoring
{
    // CVSS v4.0 base metric value levels (cvss_score.js: AV_levels, PR_levels, ... AR_levels).
    // Used both to score the selected vector and to score the MacroVector's "highest severity"
    // vector fragments during interpolation.
    private static readonly Dictionary<string, double> Cvss4AvLevels = new(StringComparer.Ordinal)
    { ["N"] = 0.0, ["A"] = 0.1, ["L"] = 0.2, ["P"] = 0.3 };

    private static readonly Dictionary<string, double> Cvss4PrLevels = new(StringComparer.Ordinal)
    { ["N"] = 0.0, ["L"] = 0.1, ["H"] = 0.2 };

    private static readonly Dictionary<string, double> Cvss4UiLevels = new(StringComparer.Ordinal)
    { ["N"] = 0.0, ["P"] = 0.1, ["A"] = 0.2 };

    private static readonly Dictionary<string, double> Cvss4AcLevels = new(StringComparer.Ordinal)
    { ["L"] = 0.0, ["H"] = 0.1 };

    private static readonly Dictionary<string, double> Cvss4AtLevels = new(StringComparer.Ordinal)
    { ["N"] = 0.0, ["P"] = 0.1 };

    private static readonly Dictionary<string, double> Cvss4VcLevels = new(StringComparer.Ordinal)
    { ["H"] = 0.0, ["L"] = 0.1, ["N"] = 0.2 };

    private static readonly Dictionary<string, double> Cvss4ViLevels = new(StringComparer.Ordinal)
    { ["H"] = 0.0, ["L"] = 0.1, ["N"] = 0.2 };

    private static readonly Dictionary<string, double> Cvss4VaLevels = new(StringComparer.Ordinal)
    { ["H"] = 0.0, ["L"] = 0.1, ["N"] = 0.2 };

    private static readonly Dictionary<string, double> Cvss4ScLevels = new(StringComparer.Ordinal)
    { ["H"] = 0.1, ["L"] = 0.2, ["N"] = 0.3 };

    private static readonly Dictionary<string, double> Cvss4SiLevels = new(StringComparer.Ordinal)
    { ["S"] = 0.0, ["H"] = 0.1, ["L"] = 0.2, ["N"] = 0.3 };

    private static readonly Dictionary<string, double> Cvss4SaLevels = new(StringComparer.Ordinal)
    { ["S"] = 0.0, ["H"] = 0.1, ["L"] = 0.2, ["N"] = 0.3 };

    private static readonly Dictionary<string, double> Cvss4CrLevels = new(StringComparer.Ordinal)
    { ["H"] = 0.0, ["M"] = 0.1, ["L"] = 0.2 };

    private static readonly Dictionary<string, double> Cvss4IrLevels = new(StringComparer.Ordinal)
    { ["H"] = 0.0, ["M"] = 0.1, ["L"] = 0.2 };

    private static readonly Dictionary<string, double> Cvss4ArLevels = new(StringComparer.Ordinal)
    { ["H"] = 0.0, ["M"] = 0.1, ["L"] = 0.2 };

    // max_composed.js: per-EQ "highest severity" vector fragments, needed by GetEqMaxes to find
    // the severity distance of the to-be-scored vector from the top of its own MacroVector.
    private static readonly Dictionary<int, string[]> Cvss4MaxComposedEq1 = new()
    {
        [0] = ["AV:N/PR:N/UI:N/"],
        [1] = ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        [2] = ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    };

    private static readonly Dictionary<int, string[]> Cvss4MaxComposedEq2 = new()
    {
        [0] = ["AC:L/AT:N/"],
        [1] = ["AC:H/AT:N/", "AC:L/AT:P/"],
    };

    // Keyed [eq3][eq6] — EQ3 and EQ6 are scored jointly.
    private static readonly Dictionary<int, Dictionary<int, string[]>> Cvss4MaxComposedEq3 = new()
    {
        [0] = new Dictionary<int, string[]>
        {
            [0] = ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            [1] = ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        [1] = new Dictionary<int, string[]>
        {
            [0] = ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            [1] =
            [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        [2] = new Dictionary<int, string[]>
        {
            [1] = ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        },
    };

    private static readonly Dictionary<int, string[]> Cvss4MaxComposedEq4 = new()
    {
        [0] = ["SC:H/SI:S/SA:S/"],
        [1] = ["SC:H/SI:H/SA:H/"],
        [2] = ["SC:L/SI:L/SA:L/"],
    };

    private static readonly Dictionary<int, string[]> Cvss4MaxComposedEq5 = new()
    {
        [0] = ["E:A/"],
        [1] = ["E:P/"],
        [2] = ["E:U/"],
    };

    // max_severity.js: per-EQ maximal scoring difference (the interpolation's denominator),
    // pre-multiplied by the 0.1 step at point of use, exactly as cvss_score.js does.
    private static readonly Dictionary<int, double> Cvss4MaxSeverityEq1 = new() { [0] = 1, [1] = 4, [2] = 5 };
    private static readonly Dictionary<int, double> Cvss4MaxSeverityEq2 = new() { [0] = 1, [1] = 2 };

    private static readonly Dictionary<int, Dictionary<int, double>> Cvss4MaxSeverityEq3Eq6 = new()
    {
        [0] = new Dictionary<int, double> { [0] = 7, [1] = 6 },
        [1] = new Dictionary<int, double> { [0] = 8, [1] = 8 },
        [2] = new Dictionary<int, double> { [1] = 10 },
    };

    private static readonly Dictionary<int, double> Cvss4MaxSeverityEq4 = new() { [0] = 6, [1] = 5, [2] = 4 };

    // cvss_lookup.js: cvssLookup_global. 270 entries, keyed by the 6-digit MacroVector string.
    // Transcribed verbatim — do not round, re-derive, or "clean up" any value.
    private static readonly Dictionary<string, double> Cvss4Lookup = new(StringComparer.Ordinal)
    {
        ["000000"] = 10.0,
        ["000001"] = 9.9,
        ["000010"] = 9.8,
        ["000011"] = 9.5,
        ["000020"] = 9.5,
        ["000021"] = 9.2,
        ["000100"] = 10.0,
        ["000101"] = 9.6,
        ["000110"] = 9.3,
        ["000111"] = 8.7,
        ["000120"] = 9.1,
        ["000121"] = 8.1,
        ["000200"] = 9.3,
        ["000201"] = 9.0,
        ["000210"] = 8.9,
        ["000211"] = 8.0,
        ["000220"] = 8.1,
        ["000221"] = 6.8,
        ["001000"] = 9.8,
        ["001001"] = 9.5,
        ["001010"] = 9.5,
        ["001011"] = 9.2,
        ["001020"] = 9.0,
        ["001021"] = 8.4,
        ["001100"] = 9.3,
        ["001101"] = 9.2,
        ["001110"] = 8.9,
        ["001111"] = 8.1,
        ["001120"] = 8.1,
        ["001121"] = 6.5,
        ["001200"] = 8.8,
        ["001201"] = 8.0,
        ["001210"] = 7.8,
        ["001211"] = 7.0,
        ["001220"] = 6.9,
        ["001221"] = 4.8,
        ["002001"] = 9.2,
        ["002011"] = 8.2,
        ["002021"] = 7.2,
        ["002101"] = 7.9,
        ["002111"] = 6.9,
        ["002121"] = 5.0,
        ["002201"] = 6.9,
        ["002211"] = 5.5,
        ["002221"] = 2.7,
        ["010000"] = 9.9,
        ["010001"] = 9.7,
        ["010010"] = 9.5,
        ["010011"] = 9.2,
        ["010020"] = 9.2,
        ["010021"] = 8.5,
        ["010100"] = 9.5,
        ["010101"] = 9.1,
        ["010110"] = 9.0,
        ["010111"] = 8.3,
        ["010120"] = 8.4,
        ["010121"] = 7.1,
        ["010200"] = 9.2,
        ["010201"] = 8.1,
        ["010210"] = 8.2,
        ["010211"] = 7.1,
        ["010220"] = 7.2,
        ["010221"] = 5.3,
        ["011000"] = 9.5,
        ["011001"] = 9.3,
        ["011010"] = 9.2,
        ["011011"] = 8.5,
        ["011020"] = 8.5,
        ["011021"] = 7.3,
        ["011100"] = 9.2,
        ["011101"] = 8.2,
        ["011110"] = 8.0,
        ["011111"] = 7.2,
        ["011120"] = 7.0,
        ["011121"] = 5.9,
        ["011200"] = 8.4,
        ["011201"] = 7.0,
        ["011210"] = 7.1,
        ["011211"] = 5.2,
        ["011220"] = 5.0,
        ["011221"] = 3.0,
        ["012001"] = 8.6,
        ["012011"] = 7.5,
        ["012021"] = 5.2,
        ["012101"] = 7.1,
        ["012111"] = 5.2,
        ["012121"] = 2.9,
        ["012201"] = 6.3,
        ["012211"] = 2.9,
        ["012221"] = 1.7,
        ["100000"] = 9.8,
        ["100001"] = 9.5,
        ["100010"] = 9.4,
        ["100011"] = 8.7,
        ["100020"] = 9.1,
        ["100021"] = 8.1,
        ["100100"] = 9.4,
        ["100101"] = 8.9,
        ["100110"] = 8.6,
        ["100111"] = 7.4,
        ["100120"] = 7.7,
        ["100121"] = 6.4,
        ["100200"] = 8.7,
        ["100201"] = 7.5,
        ["100210"] = 7.4,
        ["100211"] = 6.3,
        ["100220"] = 6.3,
        ["100221"] = 4.9,
        ["101000"] = 9.4,
        ["101001"] = 8.9,
        ["101010"] = 8.8,
        ["101011"] = 7.7,
        ["101020"] = 7.6,
        ["101021"] = 6.7,
        ["101100"] = 8.6,
        ["101101"] = 7.6,
        ["101110"] = 7.4,
        ["101111"] = 5.8,
        ["101120"] = 5.9,
        ["101121"] = 5.0,
        ["101200"] = 7.2,
        ["101201"] = 5.7,
        ["101210"] = 5.7,
        ["101211"] = 5.2,
        ["101220"] = 5.2,
        ["101221"] = 2.5,
        ["102001"] = 8.3,
        ["102011"] = 7.0,
        ["102021"] = 5.4,
        ["102101"] = 6.5,
        ["102111"] = 5.8,
        ["102121"] = 2.6,
        ["102201"] = 5.3,
        ["102211"] = 2.1,
        ["102221"] = 1.3,
        ["110000"] = 9.5,
        ["110001"] = 9.0,
        ["110010"] = 8.8,
        ["110011"] = 7.6,
        ["110020"] = 7.6,
        ["110021"] = 7.0,
        ["110100"] = 9.0,
        ["110101"] = 7.7,
        ["110110"] = 7.5,
        ["110111"] = 6.2,
        ["110120"] = 6.1,
        ["110121"] = 5.3,
        ["110200"] = 7.7,
        ["110201"] = 6.6,
        ["110210"] = 6.8,
        ["110211"] = 5.9,
        ["110220"] = 5.2,
        ["110221"] = 3.0,
        ["111000"] = 8.9,
        ["111001"] = 7.8,
        ["111010"] = 7.6,
        ["111011"] = 6.7,
        ["111020"] = 6.2,
        ["111021"] = 5.8,
        ["111100"] = 7.4,
        ["111101"] = 5.9,
        ["111110"] = 5.7,
        ["111111"] = 5.7,
        ["111120"] = 4.7,
        ["111121"] = 2.3,
        ["111200"] = 6.1,
        ["111201"] = 5.2,
        ["111210"] = 5.7,
        ["111211"] = 2.9,
        ["111220"] = 2.4,
        ["111221"] = 1.6,
        ["112001"] = 7.1,
        ["112011"] = 5.9,
        ["112021"] = 3.0,
        ["112101"] = 5.8,
        ["112111"] = 2.6,
        ["112121"] = 1.5,
        ["112201"] = 2.3,
        ["112211"] = 1.3,
        ["112221"] = 0.6,
        ["200000"] = 9.3,
        ["200001"] = 8.7,
        ["200010"] = 8.6,
        ["200011"] = 7.2,
        ["200020"] = 7.5,
        ["200021"] = 5.8,
        ["200100"] = 8.6,
        ["200101"] = 7.4,
        ["200110"] = 7.4,
        ["200111"] = 6.1,
        ["200120"] = 5.6,
        ["200121"] = 3.4,
        ["200200"] = 7.0,
        ["200201"] = 5.4,
        ["200210"] = 5.2,
        ["200211"] = 4.0,
        ["200220"] = 4.0,
        ["200221"] = 2.2,
        ["201000"] = 8.5,
        ["201001"] = 7.5,
        ["201010"] = 7.4,
        ["201011"] = 5.5,
        ["201020"] = 6.2,
        ["201021"] = 5.1,
        ["201100"] = 7.2,
        ["201101"] = 5.7,
        ["201110"] = 5.5,
        ["201111"] = 4.1,
        ["201120"] = 4.6,
        ["201121"] = 1.9,
        ["201200"] = 5.3,
        ["201201"] = 3.6,
        ["201210"] = 3.4,
        ["201211"] = 1.9,
        ["201220"] = 1.9,
        ["201221"] = 0.8,
        ["202001"] = 6.4,
        ["202011"] = 5.1,
        ["202021"] = 2.0,
        ["202101"] = 4.7,
        ["202111"] = 2.1,
        ["202121"] = 1.1,
        ["202201"] = 2.4,
        ["202211"] = 0.9,
        ["202221"] = 0.4,
        ["210000"] = 8.8,
        ["210001"] = 7.5,
        ["210010"] = 7.3,
        ["210011"] = 5.3,
        ["210020"] = 6.0,
        ["210021"] = 5.0,
        ["210100"] = 7.3,
        ["210101"] = 5.5,
        ["210110"] = 5.9,
        ["210111"] = 4.0,
        ["210120"] = 4.1,
        ["210121"] = 2.0,
        ["210200"] = 5.4,
        ["210201"] = 4.3,
        ["210210"] = 4.5,
        ["210211"] = 2.2,
        ["210220"] = 2.0,
        ["210221"] = 1.1,
        ["211000"] = 7.5,
        ["211001"] = 5.5,
        ["211010"] = 5.8,
        ["211011"] = 4.5,
        ["211020"] = 4.0,
        ["211021"] = 2.1,
        ["211100"] = 6.1,
        ["211101"] = 5.1,
        ["211110"] = 4.8,
        ["211111"] = 1.8,
        ["211120"] = 2.0,
        ["211121"] = 0.9,
        ["211200"] = 4.6,
        ["211201"] = 1.8,
        ["211210"] = 1.7,
        ["211211"] = 0.7,
        ["211220"] = 0.8,
        ["211221"] = 0.2,
        ["212001"] = 5.3,
        ["212011"] = 2.4,
        ["212021"] = 1.4,
        ["212101"] = 2.4,
        ["212111"] = 1.2,
        ["212121"] = 0.5,
        ["212201"] = 1.0,
        ["212211"] = 0.3,
        ["212221"] = 0.1,
    };

    // Required CVSS v4.0 base metrics and their valid (non-"X") values — a base-only OSV vector
    // must carry all eleven with a concrete value; metrics.js confirms this domain.
    private static readonly Dictionary<string, string[]> Cvss4BaseMetricValues = new(StringComparer.OrdinalIgnoreCase)
    {
        ["AV"] = ["N", "A", "L", "P"],
        ["AC"] = ["L", "H"],
        ["AT"] = ["N", "P"],
        ["PR"] = ["N", "L", "H"],
        ["UI"] = ["N", "P", "A"],
        ["VC"] = ["H", "L", "N"],
        ["VI"] = ["H", "L", "N"],
        ["VA"] = ["H", "L", "N"],
        ["SC"] = ["H", "L", "N"],
        ["SI"] = ["H", "L", "N"],
        ["SA"] = ["H", "L", "N"],
    };

    /// <summary>
    /// Computes the CVSS v4.0 base score from a vector string, porting FIRST's own reference
    /// calculator (MacroVector reduction, 270-entry table lookup, interpolation). Scope is
    /// CVSS-B (Base) only — OSV publishes base vectors, and the threat/environmental metrics a
    /// base-only vector omits correctly default per the CVSS v4.0 specification (E:X, CR/IR/AR:X)
    /// rather than participating in the score. Returns null if the vector cannot be parsed.
    /// </summary>
    public static double? ComputeCvss4Score(string vector)
    {
        if (!vector.StartsWith("CVSS:4.", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var metrics = ParseCvssMetrics(vector);
        if (!IsValidCvss4BaseVector(metrics))
        {
            return null;
        }

        // Exception for no impact on the system (cvss_score.js shortcut).
        if (Cvss4ImpactMetrics.All(k => Cvss4M(metrics, k) == "N"))
        {
            return 0.0;
        }

        string macroVector = Cvss4MacroVector(metrics);
        return !Cvss4Lookup.TryGetValue(macroVector, out double value)
            ? null
            : Cvss4Interpolate(metrics, macroVector, value);
    }

    private static readonly string[] Cvss4ImpactMetrics = ["VC", "VI", "VA", "SC", "SI", "SA"];

    private static bool IsValidCvss4BaseVector(Dictionary<string, string> metrics)
    {
        foreach (var (metric, validValues) in Cvss4BaseMetricValues)
        {
            if (!metrics.TryGetValue(metric, out string? value) ||
                !validValues.Contains(value, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// cvss_score.js's m() helper: reads a metric's effective value, applying the base-vector
    /// defaulting rules (E:X→A, CR:X/IR:X/AR:X→H — and, since a metric a base-only vector never
    /// mentions reads as "not present" the same as an explicit X, absence defaults identically)
    /// and the modified-metric (M&lt;metric&gt;) override, which is always absent/X for a
    /// base-only OSV vector and so degrades to the plain metric value.
    /// </summary>
    private static string? Cvss4M(Dictionary<string, string> metrics, string metric)
    {
        metrics.TryGetValue(metric, out string? selected);

        return (metric is "E" or "CR" or "IR" or "AR") && (selected is null || selected == "X")
            ? (metric == "E" ? "A" : "H")
            : metrics.TryGetValue("M" + metric, out string? modified) && modified != "X"
                ? modified
                : selected;
    }

    /// <summary>cvss_score.js's macroVector(): reduces the vector to its six-digit MacroVector.</summary>
    private static string Cvss4MacroVector(Dictionary<string, string> metrics)
    {
        string av = Cvss4M(metrics, "AV")!;
        string pr = Cvss4M(metrics, "PR")!;
        string ui = Cvss4M(metrics, "UI")!;
        string ac = Cvss4M(metrics, "AC")!;
        string at = Cvss4M(metrics, "AT")!;
        string vc = Cvss4M(metrics, "VC")!;
        string vi = Cvss4M(metrics, "VI")!;
        string va = Cvss4M(metrics, "VA")!;
        string? msi = Cvss4M(metrics, "MSI");
        string? msa = Cvss4M(metrics, "MSA");
        string sc = Cvss4M(metrics, "SC")!;
        string si = Cvss4M(metrics, "SI")!;
        string sa = Cvss4M(metrics, "SA")!;
        string e = Cvss4M(metrics, "E")!;
        string cr = Cvss4M(metrics, "CR")!;
        string ir = Cvss4M(metrics, "IR")!;
        string ar = Cvss4M(metrics, "AR")!;

        string eq1 = av == "N" && pr == "N" && ui == "N"
            ? "0"
            : (av == "N" || pr == "N" || ui == "N") && !(av == "N" && pr == "N" && ui == "N") && av != "P"
                ? "1"
                : "2";

        string eq2 = ac == "L" && at == "N" ? "0" : "1";

        string eq3 = vc == "H" && vi == "H"
            ? "0"
            : !(vc == "H" && vi == "H") && (vc == "H" || vi == "H" || va == "H")
                ? "1"
                : "2";

        string eq4 = msi == "S" || msa == "S"
            ? "0"
            : sc == "H" || si == "H" || sa == "H"
                ? "1"
                : "2";

        string eq5 = e switch { "A" => "0", "P" => "1", "U" => "2", _ => "0" };

        string eq6 = (cr == "H" && vc == "H") || (ir == "H" && vi == "H") || (ar == "H" && va == "H")
            ? "0"
            : "1";

        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }

    /// <summary>
    /// cvss_score.js's interpolation step: score of the MacroVector minus the mean proportional
    /// distance from the neighbouring lower MacroVectors, rounded to one decimal place.
    /// </summary>
    private static double Cvss4Interpolate(Dictionary<string, string> metrics, string macroVector, double value)
    {
        int eq1 = macroVector[0] - '0';
        int eq2 = macroVector[1] - '0';
        int eq3 = macroVector[2] - '0';
        int eq4 = macroVector[3] - '0';
        int eq5 = macroVector[4] - '0';
        int eq6 = macroVector[5] - '0';

        string eq1NextLower = $"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}";
        string eq2NextLower = $"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}";
        string eq4NextLower = $"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}";
        string eq5NextLower = $"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}";

        double? scoreEq1NextLower = Cvss4Lookup.TryGetValue(eq1NextLower, out double v1) ? v1 : null;
        double? scoreEq2NextLower = Cvss4Lookup.TryGetValue(eq2NextLower, out double v2) ? v2 : null;
        double? scoreEq4NextLower = Cvss4Lookup.TryGetValue(eq4NextLower, out double v4) ? v4 : null;
        double? scoreEq5NextLower = Cvss4Lookup.TryGetValue(eq5NextLower, out double v5) ? v5 : null;

        double? scoreEq3Eq6NextLower;
        if (eq3 == 0 && eq6 == 0)
        {
            // 00 → 01 or 00 → 10: two candidate paths, take whichever scores higher — but
            // faithfully reproduce the reference's undefined-comparison semantics (JS's `>`
            // against an undefined operand is always false, so a missing left never wins).
            string left = $"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}";
            string right = $"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}";
            double? scoreLeft = Cvss4Lookup.TryGetValue(left, out double vl) ? vl : null;
            double? scoreRight = Cvss4Lookup.TryGetValue(right, out double vr) ? vr : null;
            bool leftWins = scoreLeft.HasValue && scoreRight.HasValue && scoreLeft.Value > scoreRight.Value;
            scoreEq3Eq6NextLower = leftWins ? scoreLeft : scoreRight;
        }
        else
        {
            string eq3Eq6NextLower = (eq3, eq6) switch
            {
                (1, 1) => $"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", // 11 → 21
                (0, 1) => $"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", // 01 → 11
                (1, 0) => $"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}", // 10 → 11
                _ => $"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}",  // 21 → 32 (does not exist)
            };
            scoreEq3Eq6NextLower = Cvss4Lookup.TryGetValue(eq3Eq6NextLower, out double v3) ? v3 : null;
        }

        string[] eq1Maxes = Cvss4MaxComposedEq1[eq1];
        string[] eq2Maxes = Cvss4MaxComposedEq2[eq2];
        string[] eq3Eq6Maxes = Cvss4MaxComposedEq3[eq3][eq6];
        string[] eq4Maxes = Cvss4MaxComposedEq4[eq4];
        string[] eq5Maxes = Cvss4MaxComposedEq5[eq5];

        var maxVectors =
            from eq1Max in eq1Maxes
            from eq2Max in eq2Maxes
            from eq3Eq6Max in eq3Eq6Maxes
            from eq4Max in eq4Maxes
            from eq5Max in eq5Maxes
            select eq1Max + eq2Max + eq3Eq6Max + eq4Max + eq5Max;

        double distAv = 0, distPr = 0, distUi = 0;
        double distAc = 0, distAt = 0;
        double distVc = 0, distVi = 0, distVa = 0;
        double distSc = 0, distSi = 0, distSa = 0;
        double distCr = 0, distIr = 0, distAr = 0;

        foreach (string maxVector in maxVectors)
        {
            distAv = Cvss4AvLevels[Cvss4M(metrics, "AV")!] - Cvss4AvLevels[Cvss4ExtractValueMetric("AV", maxVector)];
            distPr = Cvss4PrLevels[Cvss4M(metrics, "PR")!] - Cvss4PrLevels[Cvss4ExtractValueMetric("PR", maxVector)];
            distUi = Cvss4UiLevels[Cvss4M(metrics, "UI")!] - Cvss4UiLevels[Cvss4ExtractValueMetric("UI", maxVector)];

            distAc = Cvss4AcLevels[Cvss4M(metrics, "AC")!] - Cvss4AcLevels[Cvss4ExtractValueMetric("AC", maxVector)];
            distAt = Cvss4AtLevels[Cvss4M(metrics, "AT")!] - Cvss4AtLevels[Cvss4ExtractValueMetric("AT", maxVector)];

            distVc = Cvss4VcLevels[Cvss4M(metrics, "VC")!] - Cvss4VcLevels[Cvss4ExtractValueMetric("VC", maxVector)];
            distVi = Cvss4ViLevels[Cvss4M(metrics, "VI")!] - Cvss4ViLevels[Cvss4ExtractValueMetric("VI", maxVector)];
            distVa = Cvss4VaLevels[Cvss4M(metrics, "VA")!] - Cvss4VaLevels[Cvss4ExtractValueMetric("VA", maxVector)];

            distSc = Cvss4ScLevels[Cvss4M(metrics, "SC")!] - Cvss4ScLevels[Cvss4ExtractValueMetric("SC", maxVector)];
            distSi = Cvss4SiLevels[Cvss4M(metrics, "SI")!] - Cvss4SiLevels[Cvss4ExtractValueMetric("SI", maxVector)];
            distSa = Cvss4SaLevels[Cvss4M(metrics, "SA")!] - Cvss4SaLevels[Cvss4ExtractValueMetric("SA", maxVector)];

            distCr = Cvss4CrLevels[Cvss4M(metrics, "CR")!] - Cvss4CrLevels[Cvss4ExtractValueMetric("CR", maxVector)];
            distIr = Cvss4IrLevels[Cvss4M(metrics, "IR")!] - Cvss4IrLevels[Cvss4ExtractValueMetric("IR", maxVector)];
            distAr = Cvss4ArLevels[Cvss4M(metrics, "AR")!] - Cvss4ArLevels[Cvss4ExtractValueMetric("AR", maxVector)];

            if (distAv < 0 || distPr < 0 || distUi < 0
                || distAc < 0 || distAt < 0
                || distVc < 0 || distVi < 0 || distVa < 0
                || distSc < 0 || distSi < 0 || distSa < 0
                || distCr < 0 || distIr < 0 || distAr < 0)
            {
                continue;
            }

            break;
        }

        double currentDistEq1 = distAv + distPr + distUi;
        double currentDistEq2 = distAc + distAt;
        double currentDistEq3Eq6 = distVc + distVi + distVa + distCr + distIr + distAr;
        double currentDistEq4 = distSc + distSi + distSa;

        const double step = 0.1;

        double? availableDistEq1 = scoreEq1NextLower is null ? null : value - scoreEq1NextLower.Value;
        double? availableDistEq2 = scoreEq2NextLower is null ? null : value - scoreEq2NextLower.Value;
        double? availableDistEq3Eq6 = scoreEq3Eq6NextLower is null ? null : value - scoreEq3Eq6NextLower.Value;
        double? availableDistEq4 = scoreEq4NextLower is null ? null : value - scoreEq4NextLower.Value;
        double? availableDistEq5 = scoreEq5NextLower is null ? null : value - scoreEq5NextLower.Value;

        int nExistingLower = 0;
        double normalizedEq1 = 0, normalizedEq2 = 0, normalizedEq3Eq6 = 0, normalizedEq4 = 0, normalizedEq5 = 0;

        double maxSeverityEq1 = Cvss4MaxSeverityEq1[eq1] * step;
        double maxSeverityEq2 = Cvss4MaxSeverityEq2[eq2] * step;
        double maxSeverityEq3Eq6 = Cvss4MaxSeverityEq3Eq6[eq3][eq6] * step;
        double maxSeverityEq4 = Cvss4MaxSeverityEq4[eq4] * step;

        if (availableDistEq1.HasValue)
        {
            nExistingLower++;
            double percent = currentDistEq1 / maxSeverityEq1;
            normalizedEq1 = availableDistEq1.Value * percent;
        }

        if (availableDistEq2.HasValue)
        {
            nExistingLower++;
            double percent = currentDistEq2 / maxSeverityEq2;
            normalizedEq2 = availableDistEq2.Value * percent;
        }

        if (availableDistEq3Eq6.HasValue)
        {
            nExistingLower++;
            double percent = currentDistEq3Eq6 / maxSeverityEq3Eq6;
            normalizedEq3Eq6 = availableDistEq3Eq6.Value * percent;
        }

        if (availableDistEq4.HasValue)
        {
            nExistingLower++;
            double percent = currentDistEq4 / maxSeverityEq4;
            normalizedEq4 = availableDistEq4.Value * percent;
        }

        if (availableDistEq5.HasValue)
        {
            // EQ5's own proportion is always 0 — its MacroVector distance never scores.
            nExistingLower++;
            normalizedEq5 = 0;
        }

        double meanDistance = nExistingLower == 0
            ? 0
            : (normalizedEq1 + normalizedEq2 + normalizedEq3Eq6 + normalizedEq4 + normalizedEq5) / nExistingLower;

        double result = value - meanDistance;
        result = Math.Clamp(result, 0.0, 10.0);
        return Math.Round(result * 10.0, MidpointRounding.AwayFromZero) / 10.0;
    }

    /// <summary>
    /// cvss_score.js's extractValueMetric(): pulls a single metric's value out of a
    /// "METRIC:VALUE/METRIC:VALUE/…" MacroVector-max fragment.
    /// </summary>
    private static string Cvss4ExtractValueMetric(string metric, string vectorFragment)
    {
        int idx = vectorFragment.IndexOf(metric, StringComparison.Ordinal);
        string extracted = vectorFragment[(idx + metric.Length + 1)..];
        int slash = extracted.IndexOf('/');
        return slash > 0 ? extracted[..slash] : extracted;
    }
}
