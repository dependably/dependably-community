using System.Reflection;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Migration;
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
    // One-shot maintenance modes. `Dependably migrate-to-postgres` / `verify-postgres-migration`
    // move a standalone SQLite deployment onto the Postgres an HA deployment requires, and confirm
    // the move was complete. They run the copy and exit instead of starting the web host, so the
    // procedure needs no artefact beyond the product image itself.
    if (DatabaseMigrationCommand.IsMigrationVerb(args))
    {
        using var migrationLoggerFactory = LoggerFactory.Create(logging => logging.AddSerilog(Log.Logger));
        return await DatabaseMigrationCommand.RunAsync(
            args, bootstrapConfig, migrationLoggerFactory, TimeProvider.System);
    }

    var builder = WebApplication.CreateBuilder(args);
    Program.ConfigureBuilder(builder);
    var app = builder.Build();
    // BackgroundJobScope persists per-run rows fire-and-forget via this provider; the static
    // hook avoids threading IServiceProvider through every per-service Begin() call site.
    Dependably.Infrastructure.Observability.BackgroundJobScope.Services = app.Services;
    Program.WarnOnDeprecatedConfiguration(app.Configuration);
    Program.WarnOnAirGapContradictions(app.Configuration);
    Program.ValidateEdgeConfiguration(app.Configuration);
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

        // ── Core wiring (protocol + storage + infrastructure) ───────────────────
        builder.AddDependablyLogging();
        builder.AddDependablyOpenTelemetry();
        builder.AddDependablyGracefulShutdown();
        builder.AddDependablyMetadataStore();
        builder.AddDependablyBlobStore();

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

        // ── Management wiring: HA Redis + Data Protection key ring ───────────────
        // Registered after AddDependablyBackgroundServices (which registers CoreStartupService,
        // the schema-migration hosted service) rather than before it: IHost starts hosted services
        // in registration order, and the framework's DataProtectionHostedService eagerly loads the
        // key ring from data_protection_keys at startup. Registering it here guarantees
        // CoreStartupService's schema migration creates that table before the key ring is first read.
        builder.AddDependablyRedisAndDataProtection();

        builder.AddDependablyStagingMonitor();
        builder.AddDependablyMetrics();

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddDependablyRepositories(builder.Configuration);
        builder.Services.AddDependablyManagementRepositories();

        // Mail foundation: instance-level SMTP config resolver + the MailKit sender every
        // outbound email (invites, alert delivery, email-config test-send) funnels through.
        builder.Services.AddDependablyMail(builder.Configuration);

        builder.AddDependablyPublishPipeline();

        // ── Management wiring: SIEM / webhook / invite-mail delivery ─────────────
        // SIEM push (opt-in via env vars). Webhook and syslog both sit behind
        // ISiemForwarder; webhook wins when both are set. No-op when neither is configured.
        builder.Services.AddDependablySiemForwarding(builder.Configuration);

        // Per-org outbound webhook dispatcher (always registered; the queue is only active
        // when subscriptions exist). WEBHOOK_ALLOW_PRIVATE controls the SSRF predicate.
        builder.Services.AddDependablyWebhookDispatcher(builder.Configuration);

        // Per-org alert Slack delivery (always registered; the queue is only active for orgs
        // with Slack enabled + a webhook URL configured). Same WEBHOOK_ALLOW_PRIVATE SSRF gate.
        builder.Services.AddDependablyAlertNotifier(builder.Configuration);

        // Operator-realm Slack notifications for tenant-lifecycle and operator-account events
        // (always registered; inert in single mode since its producers are apex-gated system
        // endpoints). Deliberately a separate seam from the per-org alert notifier above.
        builder.Services.AddDependablySystemEventNotifier();

        // Invite email delivery, always registered — availability is a DB-backed runtime
        // signal (instance SMTP config), not a startup-time env var. The controller falls
        // back to returning the invite link in the response body when unconfigured.
        builder.Services.AddDependablyInviteMailer();

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

        // ── Management wiring: first-factor auth, JWT, MFA identity, background jobs ──
        builder.AddDependablyManagementAuthServices();
        builder.AddDependablyTenantResolution();
        builder.AddDependablyJwt();
        builder.AddDependablyIdentity();
        builder.AddDependablyManagementBackgroundServices();
        builder.AddDependablyRateLimiter();
        builder.AddDependablyRedisRateLimitPolicies();
        builder.AddDependablyCors();
        builder.AddDependablyHttpClients();
        builder.AddDependablyLocalization();
        builder.AddDependablyTerminalExceptionHandler();
        builder.AddDependablyControllerAggregates();
        builder.AddDependablyManagementControllerAggregates();
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

        // APEX_HOST is no longer read. The apex hostname is derived solely from the host
        // portion of BASE_URL. Operators who set APEX_HOST need to know it has no effect.
        string? apexHost = configuration["APEX_HOST"];
        if (!string.IsNullOrWhiteSpace(apexHost))
        {
            Log.Warning(
                "Configuration key APEX_HOST is deprecated and ignored (configured value: {ConfiguredValue}). " +
                "The apex hostname is now derived from BASE_URL. Set BASE_URL to your public URL " +
                "(e.g. https://repo.example.com) — the host portion is used as the apex.",
                apexHost);
        }
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

    // Validates DEPLOYMENT_MODE=edge configuration. EDGE_MASTER_URL and EDGE_MASTER_TOKEN are
    // mandatory (an edge node has no reason to exist without its master) — a missing value is a
    // hard startup error, not a warning. Contradictory multi-tenant / SSO / SAML config is warned
    // on, mirroring WarnOnAirGapContradictions: an edge is single-realm and headless, so those
    // knobs have no effect and their presence signals a misconfigured deployment.
    private static void ValidateEdgeConfiguration(IConfiguration configuration)
    {
        string mode = (configuration["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        if (mode != "edge")
        {
            return;
        }

        string masterUrl = (configuration["EDGE_MASTER_URL"] ?? "").Trim();
        string masterToken = (configuration["EDGE_MASTER_TOKEN"] ?? "").Trim();

        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(masterUrl))
        {
            missing.Add("EDGE_MASTER_URL");
        }

        if (string.IsNullOrWhiteSpace(masterToken))
        {
            missing.Add("EDGE_MASTER_TOKEN");
        }

        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                $"DEPLOYMENT_MODE=edge requires {string.Join(" and ", missing)} to be set. "
                + "An edge node's sole upstream is the central master, authenticated with one "
                + "reader token — set the master URL and token, then restart.");
        }

        if (!Uri.TryCreate(masterUrl, UriKind.Absolute, out var uri)
            || uri.Scheme is not "http" and not "https")
        {
#pragma warning disable S5332 // The http:// literal is diagnostic text in an error message, not an insecure transport.
            throw new InvalidOperationException(
                $"DEPLOYMENT_MODE=edge but EDGE_MASTER_URL ('{masterUrl}') is not an absolute "
                + "http:// or https:// URL.");
#pragma warning restore S5332
        }

        // Contradictory configuration: an edge collapses to one implicit realm and ships no
        // management/SSO plane, so these knobs are inert. Warn rather than fail so an operator
        // migrating an existing config sees the dead settings without a boot block.
        foreach (string key in new[] { "SAML_ENABLED", "REQUIRE_MFA" })
        {
            string? value = configuration[key];
            if (!string.IsNullOrWhiteSpace(value)
                && !string.Equals(value, "false", StringComparison.OrdinalIgnoreCase))
            {
                Log.Warning(
                    "DEPLOYMENT_MODE=edge but {Key} is set ({Value}). An edge node is headless and "
                    + "single-realm; this setting has no effect.",
                    key, value);
            }
        }

        if (string.Equals(configuration["DEPENDABLY_DEPLOYMENT_MODE"], "ha", StringComparison.OrdinalIgnoreCase))
        {
            Log.Warning(
                "DEPLOYMENT_MODE=edge with DEPENDABLY_DEPLOYMENT_MODE=ha. Each edge node is a "
                + "standalone cache with its own SQLite and cache volume; HA orchestration of the "
                + "management plane does not apply to an edge.");
        }
    }

    // Test seam for the edge startup guard so the fail-fast behaviour can be asserted without
    // booting a full host. Delegates to the same private validator used at startup.
    internal static void ValidateEdgeConfigurationForTest(IConfiguration configuration) =>
        ValidateEdgeConfiguration(configuration);

    public static void ConfigureApp(WebApplication app)
    {
        // ── Middleware pipeline (order matters) ─────────────────────────────────

        // Terminal exception handler, outermost so it sees every exception the typed
        // middlewares below decline. Turns an otherwise bare framework 500 into localized
        // problem+json with a correlation id, and writes the single structured Error log.
        app.UseDependablyTerminalExceptionHandler();

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

        // Translate TenantStorageQuotaExceededException (proxy cache fill would exceed the
        // tenant's storage quota) into 413 problem-JSON. Sits adjacent to the other
        // storage-layer exception mappings.
        app.UseMiddleware<Dependably.Infrastructure.TenantStorageQuotaExceededExceptionMiddleware>();

        // Translate UpstreamFetchFailedException (transient upstream 403/429/5xx exhausted) into
        // 503/502 problem-JSON so package managers retry rather than treat the response as a
        // fatal policy block (403) or absence (404).
        app.UseMiddleware<Dependably.Infrastructure.UpstreamFetchFailedExceptionMiddleware>();

        // Translate a SsrfBlockedException that escapes an ecosystem download path (no local
        // catch) into 502 problem-JSON. Sits adjacent to UpstreamFetchFailedExceptionMiddleware
        // so all upstream-fetch exception mappings live together in the pipeline.
        app.UseMiddleware<Dependably.Infrastructure.SsrfBlockedExceptionMiddleware>();

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
        // longer amplify load onto the backing stores via /ready's fan-out checks. The
        // mapping is shared with the headless edge root via the Core HealthEndpoints helper.
        Dependably.Infrastructure.Health.HealthEndpoints.MapHealthAndReady(app);
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

        // Edge-only, anonymous read-only status surface. Mapped only when DEPLOYMENT_MODE=edge;
        // in every other mode the route is never registered (404) and stays out of the OpenAPI
        // documents / ApiContract gate.
        Dependably.Api.EdgeStatusEndpoint.Map(app, version);

        app.UseRateLimiter();

        // Serve embedded Svelte frontend. The embedded provider needs the build-time
        // wwwroot manifest; tests without a built frontend fall through to physical/null.
        Microsoft.Extensions.FileProviders.IFileProvider embeddedProvider;
        try
        {
            // The embedded SPA + swagger assets ship in Dependably.Management (the wwwroot tree
            // moved there with the management plane). Anchor the manifest provider on a management
            // type so the build-time wwwroot manifest is read from that assembly, not the root.
            embeddedProvider = new ManifestEmbeddedFileProvider(
                typeof(Dependably.Infrastructure.ManagementAssemblyMarker).Assembly, "wwwroot");
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
    // IP allowlist AND an authenticated management session. The protocol Swagger UI (/docs/) is
    // intentionally public — package-manager clients discover it by spec. Runs before
    // UseStaticFiles so assets under /api/v1/docs are never served to callers outside the
    // allowlist or without a session. The IP allowlist alone only bounds *where* a caller can be;
    // requiring a session too means the control-plane API contract (every admin/system route,
    // its parameters, and its schemas) can't be read by an unauthenticated caller who merely
    // shares a subnet with an operator workstation.
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
            if (!HasAuthenticatedManagementSession(ctx))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsync("Unauthorized");
                return;
            }
        }
        await next(ctx);
    }

    // Endpoint filter that gates the management OpenAPI spec behind the metrics IP allowlist AND
    // an authenticated management session (tenant or system_admin JWT) — a caller inside the
    // allowlist with no session can no longer enumerate the entire control-plane API surface for
    // reconnaissance. The protocol spec (/openapi/protocol.json) is left public.
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
            if (!HasAuthenticatedManagementSession(ctx))
            {
                return Results.StatusCode(StatusCodes.Status401Unauthorized);
            }
        }
        return await next(invocationContext);
    }

    // True when the request carries a validated JWT (cookie session or Bearer) with a
    // recognized management scope — <c>tenant</c> (an org member) or <c>system</c>
    // (a system_admin, multi mode only). UseAuthentication runs earlier in the pipeline, so
    // HttpContext.User already reflects the authentication result by the time this is checked.
    private static bool HasAuthenticatedManagementSession(HttpContext ctx)
    {
        var user = ctx.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        string? scope = user.FindFirst("scope")?.Value;
        return scope is "tenant" or "system";
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
         "/docs/", "/openapi/", "/cargo/", "/go/", "/edge/", "/apk/", "/terraform/"];

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
}
