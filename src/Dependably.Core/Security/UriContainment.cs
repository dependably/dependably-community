namespace Dependably.Security;

/// <summary>
/// Whether one URL sits beneath another's base. Shared by the Terraform mirror's archive-URL
/// resolution and by <see cref="SsrfAwareRedirectHandler"/>'s per-hop containment enforcement so a
/// single definition governs both the initial URL and every redirect target — a mirror that cannot
/// point its published archive URL off-base cannot regain that ability through a redirect either.
/// </summary>
public static class UriContainment
{
    /// <summary>
    /// True when <paramref name="candidate"/> shares <paramref name="baseUrl"/>'s scheme, host and
    /// port and its path is prefixed by the base's path at a segment boundary. Compared on parsed
    /// components rather than as strings, so a prefix that merely looks alike
    /// (<c>…/terraform-evil</c> against <c>…/terraform</c>) does not pass.
    /// </summary>
    public static bool IsBeneath(Uri candidate, string baseUrl)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var b))
        {
            return false;
        }

        if (!string.Equals(candidate.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(candidate.Host, b.Host, StringComparison.OrdinalIgnoreCase)
            || candidate.Port != b.Port)
        {
            return false;
        }

        string basePath = b.AbsolutePath.TrimEnd('/');
        return candidate.AbsolutePath.StartsWith(basePath + "/", StringComparison.Ordinal);
    }
}
