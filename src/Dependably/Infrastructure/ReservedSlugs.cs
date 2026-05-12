using System.Globalization;
using System.Text;

namespace Dependably.Infrastructure;

/// <summary>
/// Tenant slug normalization + reserved-slug enforcement. Used by <see cref="SubdomainTenantResolver"/>
/// at request time and by tenant-create endpoints at write time so the same slugs are rejected
/// in both places.
/// </summary>
public static class ReservedSlugs
{
    /// <summary>
    /// Built-in reserved slugs. Operators may extend via <c>RESERVED_SUBDOMAINS</c> env var
    /// (comma-separated) — the env list is appended to this set, never replacing it.
    /// </summary>
    public static readonly IReadOnlySet<string> Builtin = new HashSet<string>(StringComparer.Ordinal)
    {
        "system", "admin", "api", "www", "mail", "static", "assets",
        "status", "docs", "help", "support", "blog", "app", "auth",
        "localhost", "host", "master", "root", "default",
    };

    /// <summary>
    /// Normalize a slug for both validation (at create time) and resolution (at request time).
    /// Returns null if the slug is invalid (reserved, malformed, IDN/punycode, wrong charset).
    /// </summary>
    public static string? Normalize(string? input, IReadOnlySet<string>? extraReserved = null)
    {
        var s = TrimAndStripPort(input);
        if (s is null) return null;

        s = s.ToLowerInvariant().Normalize(NormalizationForm.FormC);
        if (!IsValidSlugShape(s)) return null;
        if (Builtin.Contains(s)) return null;
        if (extraReserved is not null && extraReserved.Contains(s)) return null;
        return s;
    }

    private static string? TrimAndStripPort(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;
        var s = input.Trim().TrimEnd('.');
        var colonIdx = s.IndexOf(':');
        return colonIdx >= 0 ? s[..colonIdx] : s;
    }

    private static bool IsValidSlugShape(string s)
    {
        if (s.Length == 0 || s.Length > 63) return false;
        if (s.StartsWith("xn--", StringComparison.Ordinal)) return false;
        if (s[0] == '-' || s[^1] == '-') return false;

        foreach (var c in s)
        {
            var ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>
    /// Parse the <c>RESERVED_SUBDOMAINS</c> env var ("foo,bar,baz") into a set.
    /// </summary>
    public static IReadOnlySet<string> ParseExtra(string? envValue)
    {
        if (string.IsNullOrWhiteSpace(envValue)) return new HashSet<string>(0);
        return new HashSet<string>(
            envValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(s => s.ToLowerInvariant()),
            StringComparer.Ordinal);
    }
}
