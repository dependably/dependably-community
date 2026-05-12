using System.Text;
using Dependably.Infrastructure;

namespace Dependably.Security;

/// <summary>
/// Helpers for extracting and resolving registry auth tokens from HTTP requests.
/// npm uses Bearer; PyPI and NuGet use Basic (token as password, username ignored).
/// </summary>
public static class TokenAuthExtensions
{
    /// <summary>
    /// Resolves the token from the request's Authorization header (Bearer or Basic).
    /// Returns null if no token is present or it cannot be resolved.
    /// </summary>
    public static async Task<TokenRecord?> ResolveTokenAsync(
        this HttpRequest request,
        TokenRepository tokens,
        CancellationToken ct = default)
    {
        var auth = request.Headers.Authorization.FirstOrDefault();
        if (auth is null)
            return null;

        string? raw = null;

        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            raw = auth["Bearer ".Length..].Trim();
        }
        else if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var encoded = auth["Basic ".Length..].Trim();
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                // format is user:token — take everything after the first colon as the token
                var colonIdx = decoded.IndexOf(':');
                if (colonIdx >= 0)
                    raw = decoded[(colonIdx + 1)..];
            }
            catch
            {
                return null;
            }
        }

        if (string.IsNullOrEmpty(raw))
            return null;

        return await tokens.ResolveAsync(raw, ct);
    }

    /// <summary>
    /// Capability-style permission check. Reads the JSON
    /// <see cref="TokenRecord.Capabilities"/> column as the only source of truth —
    /// issuance always populates it explicitly (see
    /// <c>Capabilities.NormalizeAndAuthorize</c>), so NULL or malformed values
    /// are treated as deny-all.
    /// Honors wildcards (<c>publish:*</c> grants <c>publish:npm</c>; <c>*</c> grants
    /// anything) via <see cref="Capabilities.Grants"/>.
    /// </summary>
    public static bool HasCapability(this TokenRecord token, string required)
    {
        if (string.IsNullOrWhiteSpace(token.Capabilities))
            return false;

        IReadOnlySet<string> granted;
        try
        {
            var list = System.Text.Json.JsonSerializer.Deserialize<string[]>(token.Capabilities);
            granted = list is null ? new HashSet<string>() : new HashSet<string>(list);
        }
        catch (System.Text.Json.JsonException)
        {
            // Malformed JSON: treat the row as having no capabilities. Better than throwing
            // mid-auth — the caller will deny, which is the safe default.
            return false;
        }

        return Capabilities.Grants(granted, required);
    }
}
