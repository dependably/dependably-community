namespace Dependably.Infrastructure;

/// <summary>
/// Default <see cref="IPublicUrlBuilder"/>. Reads scheme from <c>BASE_URL</c> when configured
/// (preserves https behind a TLS-terminating proxy that forwards http internally), falling back
/// to the request's own scheme. Host is always the inbound request host so transparent-intercept
/// deployments echo back the impersonated registry hostname.
/// </summary>
public sealed class RequestPublicUrlBuilder : IPublicUrlBuilder
{
    private readonly string? _configuredScheme;

    public RequestPublicUrlBuilder(IConfiguration config)
    {
        _configuredScheme = config["BASE_URL"] is { } bu && Uri.TryCreate(bu, UriKind.Absolute, out var uri)
            ? uri.Scheme
            : null;
    }

    public string BaseUrl(HttpContext context) => $"{Scheme(context)}://{context.Request.Host}";

    public string Absolute(HttpContext context, string path)
    {
        if (string.IsNullOrEmpty(path)) return BaseUrl(context);
        if (path[0] != '/') throw new ArgumentException("Path must start with '/'.", nameof(path));
        return $"{Scheme(context)}://{context.Request.Host}{path}";
    }

    public bool IsHttpsDeployment =>
        string.Equals(_configuredScheme, "https", StringComparison.OrdinalIgnoreCase);

    public CookieOptions SessionCookieOptions(HttpContext ctx, SameSiteMode sameSite = SameSiteMode.Strict) =>
        new CookieOptions
        {
            HttpOnly = true,
            Secure = ctx.Request.IsHttps || IsHttpsDeployment,
            SameSite = sameSite,
            IsEssential = true,
        };

    private string Scheme(HttpContext context) => _configuredScheme ?? context.Request.Scheme;
}
