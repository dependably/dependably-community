using System.Reflection;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Startup;
using Dependably.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Serilog;

// Pre-host logger configured via IConfiguration so log levels/sinks come from appsettings.json
// + env vars. CreateLogger() (not CreateBootstrapLogger()) keeps WebApplicationFactory compatible —
// the host's UseSerilog later replaces this with the full pipeline.
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
    Dependably.Infrastructure.Observability.BackgroundJobScope.Services = app.Services;
    Program.ValidateEdgeConfiguration(app.Configuration);
    Program.ConfigureApp(app);
    await app.RunAsync();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Edge host terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

/// <summary>
/// Composition root for the headless <c>dependably/edge</c> image. This assembly references
/// <c>Dependably.Core</c> ONLY — never <c>Dependably.Management</c> — so the published output
/// structurally cannot contain the management-plane dependency closure (ITfoxtec SAML, the
/// IdentityModel/JWT stack, JwtBearer, Redis, BCrypt, zxcvbn, OpenApi, the SPA). Attack-surface
/// reduction is enforced by the assembly reference graph, not by runtime stripping.
///
/// <para>Edge identity is constitutional: this root registers <see cref="EdgeMode"/> as the only
/// tenancy model and refuses to start if <c>DEPLOYMENT_MODE</c> names any other tenancy value.
/// It composes only the Core extension set — no <c>AddDependablyManagement*</c>, no JwtBearer, no
/// SPA, no OpenAPI documents.</para>
/// </summary>
public partial class Program
{
    // Static composition class — instances are created only by WebApplicationFactory's reflection.
    private Program() { }

    public static void ConfigureBuilder(WebApplicationBuilder builder)
    {
        // Edge identity is constitutional: this image IS an edge, so it does not read
        // DEPLOYMENT_MODE to decide edginess. First reject any contradictory tenancy value (the
        // startup guard also enforces this, but doing it here fails before any service is wired),
        // then pin DEPLOYMENT_MODE=edge into configuration so every Core seam that keys on it —
        // EdgeMode, the FirstBootService edge branch, the SingleTenantResolver selection, the SSRF
        // master allowlist — resolves to edge without the operator having to set the variable.
        ValidateEdgeConfiguration(builder.Configuration);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = "edge",
        });

        // Single clock for the whole app; services take TimeProvider via ctor. Direct wall-clock
        // reads are banned by TimeDeterminismComplianceTests so tests can substitute a frozen clock.
        builder.Services.AddSingleton(TimeProvider.System);

        // ── Core wiring (protocol + storage + infrastructure) — no management plane ──
        builder.AddDependablyLogging();
        builder.AddDependablyOpenTelemetry();
        builder.AddDependablyGracefulShutdown();
        builder.AddDependablyMetadataStore();
        builder.AddDependablyBlobStore();

        builder.ConfigureDependablyKestrel();
        builder.ConfigureDependablyForwardedHeaders();
        builder.ConfigureDependablyHostFiltering();

        builder.AddDependablyCaching();
        builder.AddDependablyBackgroundServices();
        builder.AddDependablyStagingMonitor();
        builder.AddDependablyMetrics();

        // In-process distributed lock. Core's HealthcheckPinger and the per-job HA coordination take
        // IDistributedLock; the Redis-backed impl and the standalone InProcessDistributedLock
        // registration both live in the management plane's Redis wiring. An edge is single-node with
        // no Redis by design, so it registers the in-process lock directly (the same one a
        // standalone full host uses). IRedisHealthProbe is left unregistered — ReadinessAggregator
        // resolves it optionally, so /ready simply reports no Redis check on an edge.
        builder.Services.AddSingleton<Dependably.Infrastructure.Redis.IDistributedLock,
                                      Dependably.Infrastructure.Redis.InProcessDistributedLock>();

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddDependablyRepositories(builder.Configuration);

        // Secret-at-rest primitives. The Core startup service envelope-encrypts instance secrets
        // and reads upstream auth secrets, so it depends on EnvelopeProtector + the master-key
        // provider. Management normally registers these inside its Identity wiring; the edge
        // registers only these two (no MFA/Identity spine) so the closure stays management-free.
        builder.Services.TryAddSingleton<IMasterKeyProvider, EnvFileMasterKeyProvider>();
        builder.Services.AddSingleton<EnvelopeProtector>();

        // No-op audit emitter. PublishAuditor (constructed by the publish pipeline below) injects
        // IAuditEmitter, which only the management plane's AuditEmitter implements — that impl
        // depends on the SIEM queue and webhook sink the edge never wires up. Publish is 405-blocked
        // on an edge (EdgePublishGuard), so PublishAuditor never emits; the no-op exists purely so
        // the DI graph resolves. Cache-edge audit events have no store and no consumer.
        builder.Services.AddSingleton<IAuditEmitter, NoOpAuditEmitter>();

        // No-op package-event sink. The vulnerability-scan pipeline (Core) takes IPackageEventSink
        // as a hard dependency; outbound webhook delivery is a management-plane feature (queue +
        // subscription table + SSRF-guarded worker all live in Dependably.Management), and an edge
        // manages no subscriptions. Discarding is honest — Dispatch is fire-and-forget by contract.
        builder.Services.AddSingleton<Dependably.Infrastructure.Webhooks.IPackageEventSink,
                                      Dependably.Infrastructure.Webhooks.NoOpPackageEventSink>();

        // No-op alert notifier. AlertService (Core) — a hard dependency of the quarantine and
        // vulnerability-scan pipelines — takes IAlertNotifier; Slack delivery (queue + SSRF-guarded
        // client + settings repository) is a management-plane feature an edge never wires up.
        // Alerts are still raised and persisted; only the outbound Slack push is skipped.
        builder.Services.AddSingleton<Dependably.Infrastructure.Alerts.IAlertNotifier,
                                      Dependably.Infrastructure.Alerts.NoOpAlertNotifier>();

        builder.AddDependablyPublishPipeline();

        builder.AddDependablyProtocolServices();
        builder.AddDependablyUpstreamQueue();

        // Vulnerability scanning source + threat feeds. The edge's block gate reads the ingested
        // advisory columns; the scan source branches (remote vs local) inside the helper.
        builder.Services.AddDependablyVulnerabilityScanning(
            builder.Configuration,
            builder.Configuration["OSV_BASE_URL"] ?? DefaultOsvBaseUrl);
        builder.Services.AddDependablyThreatFeeds();

        // Tenant resolution collapses to the single seeded edge org (SingleTenantResolver).
        builder.AddDependablyTenantResolution();

        // Authentication: the ApiToken scheme is the complete auth surface a protocol-only host
        // needs (npm Bearer / PyPI+NuGet Basic / NuGet X-NuGet-ApiKey all resolve through it). It
        // pulls in NO JwtBearer package types. A "Bearer" alias scheme is registered against the
        // same handler because the protocol controllers gate on
        // [Authorize(AuthenticationSchemes = "Bearer,ApiToken")] — without a registered "Bearer"
        // scheme the authorization middleware throws at request time. On a full host the alias slot
        // is JwtBearer; here it resolves the same registry token, so edge behaviour is identical.
        builder.AddDependablyApiTokenAuth();
        builder.Services.AddAuthentication()
            .AddScheme<TokenAuthenticationOptions, TokenAuthenticationHandler>("Bearer", _ => { });

        builder.AddDependablyRateLimiter();
        builder.AddDependablyHttpClients();
        builder.AddDependablyLocalization();
        builder.AddDependablyControllerAggregates();

        // Protocol controllers only — registered from Dependably.Core as an application part. The
        // edge assembly hosts no controllers of its own, and there is no management controller
        // application part to add, so the management surface is absent by construction (a request
        // to /api/v1/... 404s as a plain route miss). No EdgeManagementStrippingConvention is
        // needed: there is nothing to strip. No management filters (RouteScopeFilter,
        // PasswordRotationGuard, MfaEnrollmentGuard) — those live in the management plane.
        builder.Services.AddControllers()
            .AddApplicationPart(typeof(Dependably.Api.PyPiController).Assembly)
            .AddDataAnnotationsLocalization()
            .AddJsonOptions(o =>
                o.JsonSerializerOptions.UnmappedMemberHandling =
                    System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow);

        // Response compression (Brotli then GZip). Inlined rather than shared: the management host's
        // AddDependablyCompression lives in Dependably.Management and would pull that assembly in.
        builder.Services.AddResponseCompression(o =>
        {
            o.EnableForHttps = true;
            o.Providers.Add<Microsoft.AspNetCore.ResponseCompression.BrotliCompressionProvider>();
            o.Providers.Add<Microsoft.AspNetCore.ResponseCompression.GzipCompressionProvider>();
        });

        // Fail-fast DI validation. The whole point of the edge root is that its DI graph resolves
        // without the management plane; validating on build turns any first-request activation
        // failure into a startup failure with a clear message. Scope validation catches captive
        // dependencies. Enabled only in Development so production start-up stays fast.
        if (builder.Environment.IsDevelopment())
        {
            builder.Host.UseDefaultServiceProvider(o =>
            {
                o.ValidateOnBuild = true;
                o.ValidateScopes = true;
            });
        }
    }

    // Default fallback for the OSV_BASE_URL env-var.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default value for the OSV_BASE_URL env-var; this is the public OSV API the project is designed to talk to. Override in production via OSV_BASE_URL.")]
    private const string DefaultOsvBaseUrl = "https://api.osv.dev/v1";

    // Threshold above which UseSerilogRequestLogging promotes request-completion to Warning.
    private const double SlowRequestThresholdMs = 5000;

    /// <summary>
    /// Validates the edge composition root's configuration and fails fast on a contradiction. Edge
    /// identity is constitutional here — this root IS an edge regardless of DEPLOYMENT_MODE — so a
    /// DEPLOYMENT_MODE naming any tenancy value (single/multi/header/bound) is a misconfiguration,
    /// not a mode selection: the operator deployed the edge image but pointed it at a tenancy model
    /// it cannot serve. The master URL/token are always required (an edge has no reason to exist
    /// without its master); the check reuses EdgeMode's parsing.
    /// </summary>
    internal static void ValidateEdgeConfiguration(IConfiguration configuration)
    {
        string mode = (configuration["DEPLOYMENT_MODE"] ?? "edge").Trim().ToLowerInvariant();
        if (mode is "single" or "multi" or "header" or "bound")
        {
            throw new InvalidOperationException(
                $"The dependably/edge image is a headless cache-only node; it does not read "
                + $"DEPLOYMENT_MODE to decide its tenancy model. DEPLOYMENT_MODE={mode} names a "
                + "management-plane tenancy value this image cannot serve (it ships no management "
                + "plane). Unset DEPLOYMENT_MODE (or set it to 'edge'), or deploy the full "
                + "dependably image for single/multi/header/bound modes.");
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
                $"The edge node requires {string.Join(" and ", missing)} to be set. An edge node's "
                + "sole upstream is the central master, authenticated with one reader token — set "
                + "the master URL and token, then restart.");
        }

        if (!Uri.TryCreate(masterUrl, UriKind.Absolute, out var uri)
            || uri.Scheme is not "http" and not "https")
        {
#pragma warning disable S5332 // The http:// literal is diagnostic text in an error message, not an insecure transport.
            throw new InvalidOperationException(
                $"EDGE_MASTER_URL ('{masterUrl}') is not an absolute http:// or https:// URL.");
#pragma warning restore S5332
        }
    }

    // Test seam so the edge startup guard's fail-fast behaviour can be asserted without booting a
    // full host. Delegates to the same validator used at startup.
    internal static void ValidateEdgeConfigurationForTest(IConfiguration configuration) =>
        ValidateEdgeConfiguration(configuration);

    public static void ConfigureApp(WebApplication app)
    {
        // ── Middleware pipeline (order matters), trimmed to the protocol surface ──

        // Forwarded headers first (fail-closed when TRUSTED_PROXIES is unset).
        app.UseForwardedHeaders();

        // Tenant context — SingleTenantResolver on an edge (one implicit realm).
        app.UseMiddleware<SubdomainTenantMiddleware>();

        // Push canonical taxonomy properties into Serilog's LogContext.
        app.UseMiddleware<Dependably.Infrastructure.Observability.TenantEnrichmentMiddleware>();

        // Transparent intercept (no-op unless HOST_ROUTING is configured).
        app.UseMiddleware<TransparentInterceptMiddleware>();

        // Upload size limits — after tenant + intercept, before routing.
        app.UseMiddleware<UploadSizeLimitMiddleware>();

        // Security headers.
        app.UseMiddleware<SecurityHeadersMiddleware>();

        // Metrics access restriction (IP allowlist for /metrics + /version).
        app.UseMiddleware<MetricsAccessMiddleware>();

        // Storage/upstream exception → problem-JSON translators.
        app.UseMiddleware<AirGappedExceptionMiddleware>();
        app.UseMiddleware<StagingDiskFullExceptionMiddleware>();
        app.UseMiddleware<UpstreamFetchFailedExceptionMiddleware>();
        app.UseMiddleware<TenantNotReadyExceptionMiddleware>();

        app.UseResponseCompression();
        app.UseSerilogRequestLogging(opts => opts.GetLevel = SerilogRequestLogLevel);

        app.UseRequestLocalization();
        app.UseAuthentication();
        app.UseAuthorization();

        // Liveness / readiness probes — shared mapping with the full root.
        HealthEndpoints.MapHealthAndReady(app);

        string version = typeof(Program).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(Program).Assembly.GetName().Version?.ToString()
            ?? "unknown";

        // Operator/monitoring /version behind the metrics IP allowlist (same as the full root).
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

        // Anonymous read-only edge status surface (mapped because IsEdge is always true here).
        Dependably.Api.EdgeStatusEndpoint.Map(app, version);

        app.UseRateLimiter();

        // Prometheus exposition (IP-allowlisted via MetricsAccessMiddleware earlier).
        app.MapPrometheusScrapingEndpoint("/metrics");

        // Protocol controllers only. No SPA fallback, no OpenAPI documents, no Swagger UI: an edge
        // serves registry protocol surfaces and nothing else.
        app.MapControllers();
    }

    // Serilog request-log level selector.
    private static Serilog.Events.LogEventLevel SerilogRequestLogLevel(
        HttpContext ctx, double elapsed, Exception? ex)
    {
        return ex is not null
            ? Serilog.Events.LogEventLevel.Error
            : ctx.Request.Path.StartsWithSegments("/ready") || ctx.Request.Path.StartsWithSegments("/health")
            ? Serilog.Events.LogEventLevel.Verbose
            : elapsed > SlowRequestThresholdMs ? Serilog.Events.LogEventLevel.Warning : Serilog.Events.LogEventLevel.Information;
    }
}
