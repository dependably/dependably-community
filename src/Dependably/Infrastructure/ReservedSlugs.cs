using System.Text;

namespace Dependably.Infrastructure;

/// <summary>
/// Tenant slug normalization + reserved-slug enforcement. Used by <see cref="SubdomainTenantResolver"/>
/// at request time and by tenant-create endpoints at write time so the same slugs are rejected
/// in both places.
/// </summary>
public static class ReservedSlugs
{
    // Maximum DNS label length per RFC 1035 §2.3.4.
    private const int MaxDnsLabelLength = 63;

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
        string? s = TrimAndStripPort(input);
        if (s is null)
        {
            return null;
        }

        s = s.ToLowerInvariant().Normalize(NormalizationForm.FormC);
        return !IsValidSlugShape(s) ? null
            : Builtin.Contains(s) ? null
            : extraReserved is not null && extraReserved.Contains(s) ? null
            : s;
    }

    private static string? TrimAndStripPort(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }

        string s = input.Trim().TrimEnd('.');
        int colonIdx = s.IndexOf(':');
        return colonIdx >= 0 ? s[..colonIdx] : s;
    }

    private static bool IsValidSlugShape(string s)
    {
        if (s.Length is 0 or > MaxDnsLabelLength)
        {
            return false;
        }

        if (s.StartsWith("xn--", StringComparison.Ordinal))
        {
            return false;
        }

        if (s[0] == '-' || s[^1] == '-')
        {
            return false;
        }

        foreach (char c in s)
        {
            bool ok = c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Parse the <c>RESERVED_SUBDOMAINS</c> env var ("foo,bar,baz") into a set.
    /// </summary>
    public static IReadOnlySet<string> ParseExtra(string? envValue)
    {
        return string.IsNullOrWhiteSpace(envValue)
            ? new HashSet<string>(0)
            : new HashSet<string>(
            envValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(s => s.ToLowerInvariant()),
            StringComparer.Ordinal);
    }
}
