using Dependably.Api;

namespace Dependably.Infrastructure.Startup;

// Request localization (i18n) and the management-API CORS policy. Split out of
// InfrastructureStartupExtensions.cs (partial class) to keep the class's dependency coupling
// spread across files below the S1200 threshold; see that file for caching/metrics registration
// and the DefaultBaseUrl constant this file's CORS registration reads.
internal static partial class InfrastructureStartupExtensions
{
    internal static void AddDependablyLocalization(this WebApplicationBuilder builder)
    {
        // i18n — request localization with en (default) and fr
        builder.Services.AddLocalization(o => o.ResourcesPath = "Resources");
        builder.Services.Configure<Microsoft.AspNetCore.Builder.RequestLocalizationOptions>(options =>
        {
            var supported = new[] { new System.Globalization.CultureInfo("en"), new System.Globalization.CultureInfo("fr") };
            options.DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture("en");
            options.SupportedCultures = supported;
            options.SupportedUICultures = supported;
            options.RequestCultureProviders = new List<Microsoft.AspNetCore.Localization.IRequestCultureProvider>
            {
                new Microsoft.AspNetCore.Localization.QueryStringRequestCultureProvider(),
                new Microsoft.AspNetCore.Localization.CookieRequestCultureProvider(),
                new Microsoft.AspNetCore.Localization.AcceptLanguageHeaderRequestCultureProvider()
            };
        });

        // ProblemResults — scoped so IStringLocalizer resolves per-request culture
        builder.Services.AddScoped<ProblemResults>();
    }

    internal static void AddDependablyCors(this WebApplicationBuilder builder)
    {
        // CORS — management API only allows BASE_URL origin. PublicBaseUrl() strips any
        // trailing slash: a CORS origin with one never matches the browser-sent Origin header.
        (string baseUrl, bool isFallback) = ResolveCorsOrigin(builder.Configuration);
        if (isFallback)
        {
            // Without BASE_URL the credentialed policy below trusts DefaultBaseUrl (a local
            // dev origin) rather than this deployment's real public URL. A browser cannot
            // present that Origin from an attacker page, so this is not itself exploitable —
            // but it silently produces a CORS allowlist that does not match the real
            // deployment, so warn rather than fail silently (mirrors the BASE_URL warnings
            // already logged for host filtering and cookie Secure policy).
            Serilog.Log.Warning(
                "BASE_URL is not set. The management API's CORS policy falls back to {FallbackOrigin} " +
                "(a local dev origin) instead of this deployment's real public URL — browser-based " +
                "management clients served from the actual deployment origin will be rejected by " +
                "CORS. Set BASE_URL to your public URL (e.g. https://repo.example.com).",
                baseUrl);
        }

        builder.Services.AddCors(o => o.AddPolicy("ManagementApi", policy =>
            policy.WithOrigins(baseUrl)
                  .AllowCredentials()
                  .WithHeaders("Content-Type", "Authorization")
                  .WithMethods("GET", "POST", "PUT", "DELETE")));
    }

    /// <summary>
    /// Resolves the CORS origin from <c>BASE_URL</c>, reporting whether the configured value
    /// was missing/blank and <see cref="DefaultBaseUrl"/> (a local dev origin) was substituted
    /// in its place. Extracted as a pure function so the fallback-detection driving the startup
    /// warning above can be unit-tested without mutating the process-wide Serilog logger.
    /// </summary>
    internal static (string Origin, bool IsFallback) ResolveCorsOrigin(IConfiguration configuration)
    {
        string? configured = configuration.PublicBaseUrl();
        return configured is null ? (DefaultBaseUrl, true) : (configured, false);
    }
}
