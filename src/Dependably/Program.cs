using System.Reflection;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Startup;
using Dependably.Security;
using Microsoft.Extensions.FileProviders;
using Serilog;

// Pre-host logger configured via IConfiguration so log levels/sinks come from appsettings.json
// + env vars. CreateLogger() (not CreateBootstrapLogger()) keeps WebApplicationFactory compatible —
// the host's UseSerilog later replaces this with the full pipeline (incl. SensitivePropertyEnricher).
var bootstrapConfig = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(bootstrapConfig)
    .WriteTo.Console()
    .CreateLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);
    Program.ConfigureBuilder(builder);
    var app = builder.Build();
    // BackgroundJobScope persists per-run rows fire-and-forget via this provider; the static
    // hook avoids threading IServiceProvider through every per-service Begin() call site.
    Dependably.Infrastructure.Observability.BackgroundJobScope.Services = app.Services;
    Program.WarnOnDeprecatedConfiguration(app.Configuration);
    Program.WarnOnAirGapContradictions(app.Configuration);
    Program.ConfigureApp(app);
    await app.RunAsync();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Host terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

// Expose Program to WebApplicationFactory in tests
public partial class Program
{
    // Static utility class — instances are created only by WebApplicationFactory's reflection.
    private Program() { }

    // Default fallback for the OSV_BASE_URL env-var.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default value for the OSV_BASE_URL env-var; this is the public OSV API the project is designed to talk to. Override in production via OSV_BASE_URL.")]
    private const string DefaultOsvBaseUrl = "https://api.osv.dev/v1";

    // Threshold above which UseSerilogRequestLogging promotes request-completion to Warning.
    private const double SlowRequestThresholdMs = 5000;

    public static void ConfigureBuilder(WebApplicationBuilder builder)
    {
        // Single clock for the whole app. Services take TimeProvider via ctor and read
        // _time.GetUtcNow(); direct DateTime/DateTimeOffset wall-clock reads are banned by
        // TimeDeterminismComplianceTests so tests can substitute a frozen clock.
        builder.Services.AddSingleton(TimeProvider.System);

        builder.AddDependablyLogging();
        builder.AddDependablyOpenTelemetry();
        builder.AddDependablyGracefulShutdown();
        builder.AddDependablyMetadataStore();
        builder.AddDependablyBlobStore();
        builder.AddDependablyRedisAndDataProtection();
        builder.ConfigureDependablyKestrel();
        builder.ConfigureDependablyForwardedHeaders();
        builder.ConfigureDependablyHostFiltering();

        // Cookie policy — None: call sites own the Secure decision via IPublicUrlBuilder.SessionCookieOptions,
        // which blends Request.IsHttps and BASE_URL to handle both proxy and plain-HTTP deployments correctly.
        builder.Services.Configure<Microsoft.AspNetCore.Builder.CookiePolicyOptions>(options =>
        {
            options.Secure = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
            options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
            options.MinimumSameSitePolicy = SameSiteMode.Lax;
        });

        builder.AddDependablyCaching();
        builder.AddDependablyBackgroundServices();
        builder.AddDependablyStagingMonitor();
        builder.AddDependablyMetrics();

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddDependablyRepositories(builder.Configuration);

        builder.AddDependablyPublishPipeline();

        // SIEM push (opt-in via env vars). Webhook and syslog both sit behind
        // ISiemForwarder; webhook wins when both are set. No-op when neither is configured.
        builder.Services.AddDependablySiemForwarding(builder.Configuration);

        // Invite email delivery (opt-in via SMTP_HOST). No-op when SMTP_HOST is absent —
        // the controller falls back to returning the invite link in the response body.
        builder.Services.AddDependablyInviteMailer(builder.Configuration);

        builder.AddDependablyProtocolServices();
        builder.AddDependablyUpstreamQueue();

        // Vulnerability scanning — OSV source branches (remote vs local) live inside the helper.
        // VulnerabilityScanService is registered as a singleton AND a hosted service so on-demand
        // scans (controller-injected) share one instance with the background scheduler.
        builder.Services.AddDependablyVulnerabilityScanning(
            builder.Configuration,
            builder.Configuration["OSV_BASE_URL"] ?? DefaultOsvBaseUrl);

        // Threat-feed enrichment (CISA KEV + FIRST.org EPSS) over the advisories the scan
        // ingests; the block gate reads the resulting is_kev / epss_score columns.
        builder.Services.AddDependablyThreatFeeds();

        // Retention background service registers its own Dependencies record separately.
        builder.Services.AddSingleton<RetentionService.Dependencies>();

        builder.AddDependablyAuthServices();
        builder.AddDependablyTenantResolution();
        builder.AddDependablyJwt();
        builder.AddDependablyRateLimiter();
        builder.AddDependablyCors();
        builder.AddDependablyHttpClients();
        builder.AddDependablyLocalization();
        builder.AddDependablyControllerAggregates();
        builder.AddDependablyControllers();
        builder.AddDependablyOpenApi();
        builder.AddDependablyCompression();
    }

    /// <summary>
    /// Emits Serilog warnings for configuration keys that are no longer read. Silent
    /// ignore is operationally dangerous: an operator who set the key expects it to
    /// take effect. Each deprecated key gets a structured field for the configured
    /// value so the warning is actionable.
    /// </summary>
    private static void WarnOnDeprecatedConfiguration(IConfiguration configuration)
    {
        // Maven:MetadataTtl — removed when Maven metadata caching moved into
        // UpstreamClient.GetOrFetchMetadataAsync (single-flight, no TTL). Operators
        // who set this in env / Helm / Terraform need to know it has no effect.
        string? mavenMetadataTtl = configuration["Maven:MetadataTtl"];
        if (!string.IsNullOrWhiteSpace(mavenMetadataTtl))
        {
            Log.Warning(
                "Configuration key Maven:MetadataTtl is deprecated and ignored (configured value: {ConfiguredValue}). Maven metadata caching is now handled by UpstreamClient (single-flight, no TTL).",
                mavenMetadataTtl);
        }
    }

    /// <summary>
    /// True when DEPLOYMENT_MODE=multi has an apex host it can route tenant subdomains
    /// under: an explicit APEX_HOST, or a BASE_URL whose host is not localhost. Mirrors
    /// the apex derivation in <see cref="SubdomainTenantResolver"/> — the default
    /// BASE_URL of http://localhost:8080 is not usable for real multi-tenant routing.
    /// </summary>
    private static bool HasUsableApexHost(ConfigurationManager configuration)
    {
        string? apex = configuration["APEX_HOST"];
        if (!string.IsNullOrWhiteSpace(apex))
        {
            return true;
        }

        string? baseUrl = configuration["BASE_URL"];
        if (!string.IsNullOrWhiteSpace(baseUrl)
            && Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
        {
            string host = uri.Host.ToLowerInvariant();
            return host is not "localhost" and not "127.0.0.1" and not "[::1]";
        }

        return false;
    }

    private static void WarnOnAirGapContradictions(IConfiguration configuration)
    {
        bool airGapped = string.Equals(configuration["AIR_GAPPED"], "true", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(configuration["AIR_GAPPED"], "1", StringComparison.OrdinalIgnoreCase);
        if (!airGapped)
        {
            return;
        }

        string? osvMode = configuration["OSV_MODE"];
        if (!string.Equals(osvMode, "local", StringComparison.OrdinalIgnoreCase))
        {
            Log.Warning(
                "AIR_GAPPED=true but OSV_MODE is not 'local' (current: '{OsvMode}'). " +
                "Vulnerability scans will fail or silently skip. Set OSV_MODE=local.",
                string.IsNullOrWhiteSpace(osvMode) ? "(not set)" : osvMode);
        }

        string? pingUrl = configuration["HEALTHCHECK_PING_URL"];
        if (!string.IsNullOrWhiteSpace(pingUrl))
        {
            Log.Warning(
                "AIR_GAPPED=true but HEALTHCHECK_PING_URL is set ({PingUrl}). " +
                "Healthcheck pings will fail in an air-gapped environment.",
                pingUrl);
        }

        string? siemWebhook = configuration["SIEM_WEBHOOK_URL"];
        if (!string.IsNullOrWhiteSpace(siemWebhook))
        {
            Log.Information(
                "AIR_GAPPED=true and SIEM_WEBHOOK_URL is configured. " +
                "SIEM webhook delivery will fail if the endpoint is unreachable from this host.");
        }

        string? otlpEndpoint = configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
        if (!string.IsNullOrWhiteSpace(otlpEndpoint))
        {
            Log.Information(
                "AIR_GAPPED=true and OTEL_EXPORTER_OTLP_ENDPOINT is configured. " +
                "OTLP telemetry export will fail if the collector is unreachable from this host.");
        }

        string? syslogHost = configuration["SIEM_SYSLOG_HOST"];
        if (!string.IsNullOrWhiteSpace(syslogHost))
        {
            Log.Information(
                "AIR_GAPPED=true and SIEM_SYSLOG_HOST is configured. " +
                "Syslog SIEM delivery will fail if the host is unreachable.");
        }
    }

    public static void ConfigureApp(WebApplication app)
    {
        // ── Middleware pipeline (order matters) ─────────────────────────────────

        // Forwarded headers run first. When TRUSTED_PROXIES is set, every downstream consumer
        // of Connection.RemoteIpAddress and Request.IsHttps — the /metrics IP allowlist,
        // rate-limit partition keys, audit source_ip, HSTS emission, cookie Secure decisions —
        // sees the client-facing values rewritten from X-Forwarded-For / X-Forwarded-Proto by
        // the trusted proxy. When TRUSTED_PROXIES is unset, ForwardedHeaders.None is configured
        // (fail-closed) and this middleware is a no-op: all consumers see the raw socket peer.
        app.UseForwardedHeaders();

        // Strict-multi-tenancy: populate HttpContext.Items["TenantContext"] from the configured
        // ITenantResolver (single mode → SingleTenantResolver; multi mode → SubdomainTenantResolver).
        // All controllers read tenant identity from this context; URLs are tenant-implicit.
        app.UseMiddleware<Dependably.Infrastructure.SubdomainTenantMiddleware>();

        // Push canonical taxonomy properties (TenantId, OrgId, RequestId, TraceId, SpanId)
        // into Serilog's LogContext so every log emitted downstream — including
        // UseSerilogRequestLogging's completion summary — carries them. Must sit after
        // SubdomainTenantMiddleware (which populates TenantContext) and before
        // UseSerilogRequestLogging (which is registered below).
        // See dependably-enterprise/docs/observability/taxonomy.md for property names.
        app.UseMiddleware<Dependably.Infrastructure.Observability.TenantEnrichmentMiddleware>();

        // Transparent intercept. When ROUTING_MODE=transparent and the inbound Host
        // matches a configured ecosystem hostname (HOST_ROUTING), prepends the ecosystem prefix
        // so the existing prefix-routed controllers handle the request unchanged. Always-on
        // middleware: when the map is empty (default deployment) it is a no-op pass-through.
        app.UseMiddleware<Dependably.Infrastructure.TransparentInterceptMiddleware>();

        // Upload size limits — reads the TenantContext resolved above (so it must sit after
        // SubdomainTenantMiddleware) and the ecosystem path prefix (so it must sit after
        // TransparentInterceptMiddleware's host→prefix rewrite), and must run before routing
        // so the max body size is set before the body is read.
        app.UseMiddleware<Dependably.Security.UploadSizeLimitMiddleware>();

        // Security headers — must be first after upload limit
        app.UseMiddleware<SecurityHeadersMiddleware>();

        // Metrics access restriction
        app.UseMiddleware<MetricsAccessMiddleware>();

        // AIR_GAPPED mode — translate UpstreamClient.AirGappedException into 503 with
        // a clear problem-JSON body. Sits high in the pipeline so it catches exceptions
        // from any controller / protocol path that hits the upstream client.
        app.UseMiddleware<Dependably.Infrastructure.AirGappedExceptionMiddleware>();

        // Translate StagingDiskFullException into 507 Insufficient Storage problem-JSON.
        // Sits adjacent to the air-gap handler so all storage-layer exception mappings
        // live together in the pipeline.
        app.UseMiddleware<Dependably.Infrastructure.StagingDiskFullExceptionMiddleware>();

        // Translate UpstreamFetchFailedException (transient upstream 403/429/5xx exhausted) into
        // 503/502 problem-JSON so package managers retry rather than treat the response as a
        // fatal policy block (403) or absence (404).
        app.UseMiddleware<Dependably.Infrastructure.UpstreamFetchFailedExceptionMiddleware>();

        // Translate TenantNotReadyException raised by ITenantStorageResolver.GetRegistryAsync
        // into 404 / 423 / 503 problem-JSON responses instead of letting it bubble to a 500.
        // Sits adjacent to the air-gap handler so all storage-layer exception mappings live
        // together in the pipeline.
        app.UseMiddleware<Dependably.Infrastructure.TenantNotReadyExceptionMiddleware>();

        app.UseResponseCompression();
        app.UseSerilogRequestLogging(opts => opts.GetLevel = SerilogRequestLogLevel);

        app.UseCors("ManagementApi");
        app.UseRequestLocalization();
        app.UseCookiePolicy();
        app.UseAuthentication();
        app.UseAuthorization();

        // CSRF defense-in-depth for management API cookie sessions. Checks Sec-Fetch-Site
        // (modern browsers) then falls back to Origin. Runs after auth so the cookie has
        // already been validated; skips requests with an Authorization header (API token /
        // protocol clients) and the SAML ACS path (cross-site IdP POST by design).
        app.UseMiddleware<Dependably.Security.CsrfDefenseMiddleware>();

        // Liveness / readiness probes. All carry the per-IP "anon" rate-limit policy:
        // generous enough for orchestrator probes, but an unauthenticated flood can no
        // longer amplify load onto the backing stores via /ready's fan-out checks.
        app.MapGet("/health", () => Results.Ok(new { status = "ok" })).RequireRateLimiting("anon");
        string version = typeof(Program).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(Program).Assembly.GetName().Version?.ToString()
            ?? "unknown";
        // /version is an operator/monitoring surface (the SPA never calls it), so it sits
        // behind the same IP allowlist as /metrics — anonymous internet callers can't
        // fingerprint the deployed build for CVE matching. The default allowlist permits
        // loopback, so local `curl /version` checks keep working.
        app.MapGet("/version", async (HttpContext ctx, MetricsAccessConfig metricsAccess, ScrapeDiagnostics scrapeDiag) =>
        {
            var resolved = await metricsAccess.ResolveAsync(ctx.RequestAborted);
            var remote = ctx.Connection.RemoteIpAddress;
            if (remote is null || !MetricsAccessMiddleware.IsIpAllowed(remote, resolved.Allowed))
            {
                scrapeDiag.Record(remote, ScrapeDiagnostics.Outcome.DeniedIp);
                await MetricsAccessMiddleware.WriteScrapeDeniedAuditAsync(ctx, remote, "/version", scrapeDiag);
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }
            return Results.Ok(new { version });
        }).RequireRateLimiting("anon");
        app.MapGet("/ready", BuildReadyHandler()).RequireRateLimiting("anon");

        app.UseRateLimiter();

        // Serve embedded Svelte frontend. The embedded provider needs the build-time
        // wwwroot manifest; tests without a built frontend fall through to physical/null.
        Microsoft.Extensions.FileProviders.IFileProvider embeddedProvider;
        try
        {
            embeddedProvider = new ManifestEmbeddedFileProvider(typeof(Program).Assembly, "wwwroot");
        }
        catch (InvalidOperationException)
        {
            string wwwrootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot");
            embeddedProvider = Directory.Exists(wwwrootPath)
                ? new Microsoft.Extensions.FileProviders.PhysicalFileProvider(wwwrootPath)
                : new Microsoft.Extensions.FileProviders.NullFileProvider();
        }
        app.UseStaticFiles(new StaticFileOptions { FileProvider = embeddedProvider });

        ConfigureSwaggerAndOpenApi(app);

        app.MapControllers();

        // SPA fallback — serve index.html for all non-API, non-registry paths.
        // Two endpoints: an explicit "/package/{**path}" pattern that drops the default
        // `:nonfile` route constraint (so /package/nuget/microsoft.extensions.dependencyinjection
        // still resolves even though its final segment contains dots), plus the default
        // fallback which keeps `:nonfile` and ensures requests for missing static assets
        // (e.g. /assets/index-stale.css when a cached index.html points at an old hash)
        // return 404 rather than HTML — otherwise the browser sees a MIME mismatch.
        // Catch-all parameter is structural (it relaxes the `:nonfile` constraint); the handler
        // reads ctx.Request.Path directly and has no signature to consume it through.
#pragma warning disable ASP0018
        app.MapFallback("/package/{**_}", BuildSpaFallback(embeddedProvider));
#pragma warning restore ASP0018
        app.MapFallback(BuildSpaFallback(embeddedProvider));
    }

    // Mounts the Swagger UI at /api/v1/docs/ (management) and /docs/ (protocol), registers
    // redirect middleware for bare-path canonical form, gates the management subtree behind the
    // metrics IP allowlist, and maps the gated OpenAPI spec endpoint.
    private static void ConfigureSwaggerAndOpenApi(WebApplication app)
    {
        // Vendored Swagger UI mounted at two URLs — one per OpenAPI document.
        // /api/v1/docs/ → management spec (/openapi/management.json)
        // /docs/        → protocol  spec (/openapi/protocol.json)
        // The shell (index.html + JS/CSS) is identical at both mounts; assets use
        // relative paths, and swagger-initializer.js picks the spec URL based on
        // window.location.pathname. The bare /api/v1/docs and /docs URLs redirect
        // to their trailing-slash form so relative asset paths resolve correctly.
        var swaggerProvider = new SubPathFileProvider(app.Environment.WebRootFileProvider, "/swagger");

        // Canonicalize bare doc URLs and gate the management subtree behind the metrics
        // IP allowlist. Two separate middleware registrations are kept deliberately so each
        // one has a single responsibility and Sonar S3776 complexity stays below threshold.
        app.Use(SwaggerDocRedirectMiddleware);
        app.Use(ManagementDocsAllowlistMiddleware);

        // Mount 1 — Management API (existing UI URL preserved). The doc-shell endpoint
        // is excluded from OpenAPI so it doesn't pollute the spec or contract gate.
        app.UseStaticFiles(new StaticFileOptions { FileProvider = swaggerProvider, RequestPath = "/api/v1/docs" });
        app.MapGet("/api/v1/docs/", BuildSwaggerShellHandler(swaggerProvider)).ExcludeFromDescription();

        // Mount 2 — Registry Protocols
        app.UseStaticFiles(new StaticFileOptions { FileProvider = swaggerProvider, RequestPath = "/docs" });
        app.MapGet("/docs/", BuildSwaggerShellHandler(swaggerProvider)).ExcludeFromDescription();

        // Prometheus exposition served by OpenTelemetry's Prometheus exporter.
        // RED metrics (rate/errors/duration) come automatically from
        // AddAspNetCoreInstrumentation in ConfigureOpenTelemetry. The IP
        // allowlist on /metrics is preserved by MetricsAccessMiddleware
        // earlier in the pipeline. See docs/observability/metrics.md.
        // Deliberately outside the OpenAPI inventory (management and protocol documents):
        // operator-only scrape endpoint, IP-allowlisted, documented in docs/observability.
        app.MapPrometheusScrapingEndpoint("/metrics");

        // OpenAPI specs — management document is gated behind the metrics IP allowlist
        // (same policy as /version and /metrics) to prevent unauthenticated enumeration
        // of the control-plane surface. The protocol document remains public: those routes
        // are client-discoverable by their upstream ecosystem specifications anyway.
        app.MapOpenApi("/openapi/{documentName}.json")
           .AddEndpointFilter(ManagementOpenApiAllowlistFilter);
    }

    // Canonicalizes bare Swagger doc paths to their trailing-slash form so the relative asset
    // paths in the shared swagger shell (./swagger-ui.css etc.) resolve correctly. Done via
    // middleware rather than a second MapGet endpoint because ASP.NET Core endpoint routing
    // treats `/foo` and `/foo/` as the same template — registering both throws
    // AmbiguousMatchException at request time.
    private static Task SwaggerDocRedirectMiddleware(HttpContext ctx, RequestDelegate next)
    {
        string? path = ctx.Request.Path.Value;
        if (path is "/api/v1/docs" or "/docs")
        {
            ctx.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
            ctx.Response.Headers.Location = path + "/" + ctx.Request.QueryString.Value;
            return Task.CompletedTask;
        }
        return next(ctx);
    }

    // Gates the management Swagger UI static-asset subtree (/api/v1/docs/*) behind the metrics
    // IP allowlist. The protocol Swagger UI (/docs/) is intentionally public — package-manager
    // clients discover it by spec. Runs before UseStaticFiles so assets under /api/v1/docs are
    // never served to callers outside the allowlist.
    private static async Task ManagementDocsAllowlistMiddleware(HttpContext ctx, RequestDelegate next)
    {
        if (ctx.Request.Path.StartsWithSegments("/api/v1/docs"))
        {
            var metricsAccess = ctx.RequestServices.GetRequiredService<MetricsAccessConfig>();
            var resolved = await metricsAccess.ResolveAsync(ctx.RequestAborted);
            var remote = ctx.Connection.RemoteIpAddress;
            if (remote is null || !MetricsAccessMiddleware.IsIpAllowed(remote, resolved.Allowed))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsync("Forbidden");
                return;
            }
        }
        await next(ctx);
    }

    // Endpoint filter that gates the management OpenAPI spec behind the metrics IP allowlist.
    // The protocol spec (/openapi/protocol.json) is left public.
    private static async ValueTask<object?> ManagementOpenApiAllowlistFilter(
        EndpointFilterInvocationContext invocationContext, EndpointFilterDelegate next)
    {
        var ctx = invocationContext.HttpContext;
        if (ctx.GetRouteValue("documentName") is string docName
            && string.Equals(docName, "management", StringComparison.OrdinalIgnoreCase))
        {
            var metricsAccess = ctx.RequestServices.GetRequiredService<MetricsAccessConfig>();
            var resolved = await metricsAccess.ResolveAsync(ctx.RequestAborted);
            var remote = ctx.Connection.RemoteIpAddress;
            if (remote is null || !MetricsAccessMiddleware.IsIpAllowed(remote, resolved.Allowed))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }
        }
        return await next(invocationContext);
    }

    // Serves the Swagger shell index.html for a given file provider. UseDefaultFiles relies on
    // GetDirectoryContents(subpath).Exists, which the dev StaticWebAssets provider returns false
    // for; serve the shell explicitly via this helper, reused by both Swagger UI mounts.
    private static Func<HttpContext, Task> BuildSwaggerShellHandler(
        Dependably.Infrastructure.SubPathFileProvider provider) =>
        async ctx =>
        {
            var file = provider.GetFileInfo("/index.html");
            if (!file.Exists)
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            ctx.Response.ContentType = "text/html";
            await ctx.Response.SendFileAsync(file);
        };

    // Serilog request-log level selector. Extracted from ConfigureApp to keep the
    // middleware-composition method below the Sonar S3776 complexity threshold.
    private static Serilog.Events.LogEventLevel SerilogRequestLogLevel(
        HttpContext ctx, double elapsed, Exception? ex)
    {
        return ex is not null
            ? Serilog.Events.LogEventLevel.Error
            : ctx.Request.Path.StartsWithSegments("/ready") || ctx.Request.Path.StartsWithSegments("/health")
            ? Serilog.Events.LogEventLevel.Verbose
            : elapsed > SlowRequestThresholdMs ? Serilog.Events.LogEventLevel.Warning : Serilog.Events.LogEventLevel.Information;
    }

    private static readonly string[] NonSpaPathPrefixes =
        ["/api/", "/simple/", "/npm/", "/nuget/", "/packages/", "/pypi/", "/maven/", "/rpm/", "/v2/", "/saml/",
         "/docs/", "/openapi/", "/cargo/", "/go/"];

    private static readonly string[] NonSpaExactPaths = ["/health", "/ready", "/metrics", "/docs", "/cargo/config.json"];

    private static bool IsNonSpaPath(string path) =>
        NonSpaPathPrefixes.Any(p => path.StartsWith(p, StringComparison.Ordinal))
        || NonSpaExactPaths.Contains(path);

    private static Func<HttpContext, Task> BuildSpaFallback(Microsoft.Extensions.FileProviders.IFileProvider embeddedProvider) =>
        async ctx =>
        {
            string path = ctx.Request.Path.Value ?? "";
            // Known API/registry prefixes that matched no route are genuine 404s, for any method.
            if (IsNonSpaPath(path))
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            // Otherwise this is an SPA-eligible path: only GET/HEAD navigation resolves to
            // index.html. A non-GET reaching here matched no real route (e.g. a mis-targeted
            // `twine upload` POSTing to the bare host instead of /pypi/legacy/) — returning 200
            // HTML would silently swallow the body and mask the misconfiguration as a success,
            // so reject with 405 to make the client fail loudly.
            if (!HttpMethods.IsGet(ctx.Request.Method) && !HttpMethods.IsHead(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                ctx.Response.Headers.Allow = "GET, HEAD";
                return;
            }
            var file = embeddedProvider.GetFileInfo("index.html");
            if (file.Exists)
            {
                ctx.Response.ContentType = "text/html";
                await ctx.Response.SendFileAsync(file);
            }
        };

    private static Func<ReadinessAggregator, ShutdownState, CancellationToken, Task<IResult>> BuildReadyHandler() =>
        async (aggregator, shutdown, ct) =>
        {
            if (shutdown.IsShuttingDown)
            {
                return Results.Json(new { status = "draining" }, statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var checks = await aggregator.CheckAsync(ct);
            bool allOk = checks.Values.All(v => v is null);

            // Per-check ok/error only. Raw failure detail (file paths, Redis endpoints,
            // driver error text) is logged server-side by ReadinessAggregator and never
            // returned to the anonymous caller.
            var body = new
            {
                status = allOk ? "ready" : "degraded",
                checks = checks.ToDictionary(kv => kv.Key, kv => kv.Value is null ? "ok" : "error"),
            };

            return allOk
                ? Results.Ok(body)
                : Results.Json(body, statusCode: StatusCodes.Status503ServiceUnavailable);
        };
}
