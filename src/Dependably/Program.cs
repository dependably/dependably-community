using System.Globalization;
using System.Reflection;
using System.Threading.RateLimiting;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Health;
using Dependably.Infrastructure.Redis;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Formatting.Compact;
using StackExchange.Redis;

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

    // Default fallbacks for env-var configuration. Production deployments override these.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default value for the OSV_BASE_URL env-var; this is the public OSV API the project is designed to talk to. Override in production via OSV_BASE_URL.")]
    private const string DefaultOsvBaseUrl = "https://api.osv.dev/v1";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Default value for the BASE_URL env-var; only used when running locally without configuration. Override in production via BASE_URL.")]
    private const string DefaultBaseUrl = "http://localhost:8080";

    // Threshold above which UseSerilogRequestLogging promotes request-completion to Warning.
    private const double SlowRequestThresholdMs = 5000;

    public static void ConfigureBuilder(WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(opts => opts.AddServerHeader = false);

        ConfigureLogging(builder);
        ConfigureOpenTelemetry(builder);
        ConfigureGracefulShutdown(builder);
        ConfigureMetadataStore(builder);
        ConfigureBlobStore(builder);
        ConfigureRedisAndDataProtection(builder);

        ConfigureForwardedHeaders(builder);

        // Cookie policy — None: call sites own the Secure decision via IPublicUrlBuilder.SessionCookieOptions,
        // which blends Request.IsHttps and BASE_URL to handle both proxy and plain-HTTP deployments correctly.
        builder.Services.Configure<Microsoft.AspNetCore.Builder.CookiePolicyOptions>(options =>
        {
            options.Secure = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
            options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
            options.MinimumSameSitePolicy = SameSiteMode.Lax;
        });

        // Startup: schema migration + first-boot + JWT key load (must complete before other services)
        builder.Services.AddHostedService<StartupService>();

        // Leader election for background jobs in HA mode
        builder.Services.AddHostedService<LeaderElectedScheduler>();

        // Health infrastructure
        builder.Services.AddSingleton<ReadinessAggregator>();
        builder.Services.AddHostedService<HealthcheckPinger>();

        // SizeLimit bounds total in-process metadata response bytes (npm packuments, PyPI
        // simple indices, NuGet registration pages). Each entry sets Size = bytes.Length.
        // 50 MB covers hundreds of typical packuments/indices with headroom for large ones.
        builder.Services.AddMemoryCache(o => o.SizeLimit = 50 * 1024 * 1024);

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddDependablyRepositories();

        // Two-tier storage glue that isn't a repository. The repositories themselves
        // are registered by AddDependablyRepositories.
        builder.Services.AddSingleton<Dependably.Storage.UpstreamFetchCoordinator>();
        builder.Services.AddSingleton<IAirGapMode, AirGapMode>();
        builder.Services.AddHostedService<CacheEvictionService>();

        // Hosted-tier orphan reconciliation: closes the SIGKILL window in PackagePublishService
        // by sweeping the registry tier for blobs that no package_versions row references.
        // Schedule + grace are configurable; defaults to daily at 04:00 UTC with a 30-minute
        // grace window to skip in-flight publishes.
        builder.Services.AddHostedService<OrphanBlobReconcilerService>();
        builder.Services.AddHostedService<Dependably.Infrastructure.Observability.BlobStoreSizePoller>();
        builder.Services.AddHostedService<Dependably.Infrastructure.Observability.TenantCountPoller>();

        // Staging disk space monitoring. IStagingDiskInfo reads DriveInfo for the
        // staging volume; StagingDiskMonitor samples it on a 60 s timer and emits
        // OTel gauges + a Serilog warning when free space falls below the threshold.
        string? configuredStagingPath = builder.Configuration["PROXY_STAGING_PATH"];
        string resolvedStagingPath = string.IsNullOrWhiteSpace(configuredStagingPath)
            ? Path.GetTempPath()
            : configuredStagingPath;
        builder.Services.AddSingleton<Dependably.Infrastructure.IStagingDiskInfo>(
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(resolvedStagingPath));
        builder.Services.AddHostedService<Dependably.Infrastructure.Observability.StagingDiskMonitor>();

        builder.Services.AddSingleton<Dependably.Security.MetricsAccessConfig>(sp =>
        {
            var orgs = sp.GetRequiredService<OrgRepository>();
            var configuration = sp.GetRequiredService<IConfiguration>();
            return new Dependably.Security.MetricsAccessConfig(
                orgs.GetInstanceSettingAsync, configuration);
        });
        builder.Services.AddSingleton<Dependably.Security.ScrapeDiagnostics>();
        builder.Services.AddSingleton<Dependably.Infrastructure.Observability.MetricsSnapshotProvider>();

        // Feature-flagged claim gate for publish/import paths. Default off; operators
        // flip CLAIM_ENFORCEMENT=on once their initial claim set is in place.
        builder.Services.AddSingleton<Dependably.Security.PublishGate>();

        // Admin bulk import. One service record so the controller ctor stays
        // under S107; same shape as the protocol controllers. The factory captures
        // PROXY_STAGING_PATH once at registration time (resolved from configuration)
        // so the scoped record carries a plain string rather than an IConfiguration dep.
        builder.Services.AddScoped<Dependably.Api.ImportControllerServices>(sp =>
        {
            string? configuredStaging = builder.Configuration["PROXY_STAGING_PATH"];
            string stagingPath = string.IsNullOrWhiteSpace(configuredStaging)
                ? Path.GetTempPath()
                : configuredStaging;
            return new Dependably.Api.ImportControllerServices(
                Guard: sp.GetRequiredService<Dependably.Security.OrgAccessGuard>(),
                PublishGate: sp.GetRequiredService<Dependably.Security.PublishGate>(),
                Orgs: sp.GetRequiredService<Dependably.Infrastructure.OrgRepository>(),
                Publish: sp.GetRequiredService<Dependably.Infrastructure.Publish.IPackagePublishService>(),
                ClaimResolver: sp.GetRequiredService<Dependably.Infrastructure.ClaimResolver>(),
                Licenses: sp.GetRequiredService<Dependably.Infrastructure.LicenseRepository>(),
                LimitResolver: sp.GetRequiredService<Dependably.Protocol.IUploadLimitResolver>(),
                StagingPath: stagingPath,
                Cache: sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>());
        });

        // Shared publish-flow tail (path safety, claim gate, dedup, blob put, version create,
        // audit). Used by NpmController/PyPiController/NuGetController publish handlers and
        // by ImportController bulk endpoints — replaces six near-identical inlined flows.
        builder.Services.AddSingleton<Dependably.Infrastructure.Publish.PublishAuditor>();
        builder.Services.AddSingleton<Dependably.Infrastructure.Publish.IPackagePublishService,
                                      Dependably.Infrastructure.Publish.PackagePublishService>();

        // Claim REST surface. State machine + repository already registered
        // above; the controller services record bundles the deps.
        builder.Services.AddScoped<Dependably.Api.ClaimsControllerServices>();

        // SIEM push (opt-in via env vars). Webhook and syslog both sit behind
        // ISiemForwarder; webhook wins when both are set. No-op when neither is configured.
        builder.Services.AddDependablySiemForwarding(builder.Configuration);

        // Invite email delivery (opt-in via SMTP_HOST). No-op when SMTP_HOST is absent —
        // the controller falls back to returning the invite link in the response body.
        builder.Services.AddDependablyInviteMailer(builder.Configuration);

        // Protocol services
        builder.Services.AddSingleton<UpstreamClient>();
        builder.Services.AddSingleton<UpstreamRegistryResolver>();
        builder.Services.AddSingleton<IUpstreamUrlValidator, UpstreamUrlValidator>();
        // Connect-time SSRF gate shared by the upstream HTTP handlers. Validates the IP
        // actually dialed (every connection + every redirect hop), closing the DNS-rebinding
        // window the URL-level pre-check cannot. Predicate is the same SsrfGuard block-list.
        builder.Services.AddSingleton(new SsrfConnectCallback(SsrfGuard.IsBlockedIp));
        builder.Services.AddSingleton<AllowlistService>();
        builder.Services.AddSingleton<BlockGateService>();

        // Maven upstream proxy
        builder.Services.AddSingleton<Dependably.Protocol.MavenUpstreamFetcher>();

        // RPM upstream proxy
        builder.Services.AddSingleton<Dependably.Protocol.RpmUpstreamProxyServices>();
        builder.Services.AddSingleton<Dependably.Protocol.RpmUpstreamProxy>();

        // OCI upstream proxy — auth service is singleton (owns token cache + semaphores)
        builder.Services.AddOptions<Dependably.Configuration.OciOptions>()
            .BindConfiguration("Oci")
            .ValidateOnStart();
        builder.Services.AddSingleton<Microsoft.Extensions.Options.IValidateOptions<Dependably.Configuration.OciOptions>,
            Dependably.Configuration.OciOptionsValidator>();
        builder.Services.AddSingleton<Dependably.Protocol.OciUpstreamAuthService>();
        builder.Services.AddSingleton<Dependably.Protocol.OciUpstreamResolver>();
        builder.Services.AddSingleton<Dependably.Protocol.OciUploadService>();

        // Vulnerability scanning — OSV source branches (remote vs local) live inside the helper.
        // VulnerabilityScanService is registered as a singleton AND a hosted service so on-demand
        // scans (controller-injected) share one instance with the background scheduler.
        builder.Services.AddDependablyVulnerabilityScanning(
            builder.Configuration,
            builder.Configuration["OSV_BASE_URL"] ?? DefaultOsvBaseUrl);

        // Threat-feed enrichment (CISA KEV + FIRST.org EPSS) over the advisories the scan
        // ingests; the block gate reads the resulting is_kev / epss_score columns.
        builder.Services.AddDependablyThreatFeeds();

        // Other background services
        builder.Services.AddHostedService<RetentionService>();
        builder.Services.AddHostedService<Dependably.Background.TenantHardDeleteService>();
        builder.Services.AddHostedService<DeprecationRefreshService>();
        builder.Services.AddHostedService<StatsRefreshService>();
        builder.Services.AddHostedService<SamlCertExpiryCheckService>();

        // Auth services
        builder.Services.AddSingleton<LoginService>();
        builder.Services.AddSingleton<OrgAccessGuard>();
        builder.Services.AddSingleton<Dependably.Security.PasswordPolicy>();

        // Tenant resolution — strategy selected by DEPLOYMENT_MODE at startup.
        // DEPLOYMENT_MODE=single (default) → SingleTenantResolver (ignores Host, returns the one tenant)
        // DEPLOYMENT_MODE=multi          → SubdomainTenantResolver (Host → tenant slug → orgs row)
        // DEPLOYMENT_MODE=header         → HeaderTenantResolver (X-Dependably-Tenant header → orgs row; intercept mode behind trusted edge proxy)
        // DEPLOYMENT_MODE=bound          → DeploymentBoundTenantResolver (BOUND_TENANT_SLUG, ignores request; intercept mode for single-tenant enterprise)
        // Scoped lifetime so per-request DB queries don't bleed across requests.
        string tenancyMode = (builder.Configuration["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        switch (tenancyMode)
        {
            case "multi":
                builder.Services.AddScoped<ITenantResolver, SubdomainTenantResolver>();
                // Eviction hook for tenant-lifecycle endpoints. Resolver is scoped, but the
                // cache it touches is IMemoryCache (singleton), so any instance can evict.
                builder.Services.AddScoped<ITenantSlugCacheInvalidator>(
                    sp => (SubdomainTenantResolver)sp.GetRequiredService<ITenantResolver>());
                // Multi mode resolves tenants by subdomain under an apex host. Without a real
                // apex host, every bare/IP/non-subdomain request falls to apex/uninitialized and
                // per-tenant login methods (forms, SAML) never render. Warn so the misconfig is
                // visible instead of silently hiding the login page.
                if (!HasUsableApexHost(builder.Configuration))
                {
                    Log.Warning(
                        "DEPLOYMENT_MODE=multi but no usable APEX_HOST (and BASE_URL is unset or localhost). "
                        + "Tenants are reached at slug.apexhost; non-subdomain hosts resolve to apex/uninitialized "
                        + "and per-tenant login methods such as SAML will not appear. Set APEX_HOST, or use "
                        + "DEPLOYMENT_MODE=single for a single-tenant appliance.");
                }

                break;
            case "header":
                builder.Services.AddScoped<ITenantResolver, HeaderTenantResolver>();
                break;
            case "bound":
                builder.Services.AddScoped<ITenantResolver, DeploymentBoundTenantResolver>();
                break;
            default:
                builder.Services.AddScoped<ITenantResolver, SingleTenantResolver>();
                break;
        }

        // Public URL construction. Stateless; reads BASE_URL once at startup for the scheme override
        // and derives host from the inbound request.
        builder.Services.AddSingleton<IPublicUrlBuilder, RequestPublicUrlBuilder>();

        // Transparent intercept host→ecosystem map. Always registered; the middleware
        // is a no-op when HOST_ROUTING is unset (default deployment).
        builder.Services.AddSingleton<HostEcosystemMap>();

        ConfigureJwtAuthentication(builder);

        builder.Services.AddAuthorization();
        // Capability enforcement: dynamic policy provider materialises a policy per
        // [RequireCapability("...")] attribute; the handler resolves the principal's role
        // claim through Capabilities.ForRole and checks Capabilities.Grants.
        builder.Services.AddSingleton<IAuthorizationPolicyProvider, CapabilityPolicyProvider>();
        builder.Services.AddSingleton<IAuthorizationHandler, CapabilityHandler>();

        // Global RouteScopeFilter rejects any /api/v1/ request whose JWT lacks a
        // `scope` claim and pins each scope to its realm: tenant routes require
        // scope=tenant + matching tid, system routes require scope=system + apex.
        builder.Services.AddScoped<Dependably.Security.RouteScopeFilter>();
        // Forces a user holding a temporary password to rotate it before using the API.
        builder.Services.AddScoped<Dependably.Security.PasswordRotationGuard>();

        ConfigureRateLimiter(builder);

        // CORS — management API only allows BASE_URL origin. PublicBaseUrl() strips any
        // trailing slash: a CORS origin with one never matches the browser-sent Origin header.
        string baseUrl = builder.Configuration.PublicBaseUrl() ?? DefaultBaseUrl;
        builder.Services.AddCors(o => o.AddPolicy("ManagementApi", policy =>
            policy.WithOrigins(baseUrl)
                  .AllowCredentials()
                  .WithHeaders("Content-Type", "Authorization")
                  .WithMethods("GET", "POST", "PUT", "DELETE")));

        // Named HTTP client for upstream proxy requests
        // ConnectTimeout=30s, total timeout=5min, max 3 redirects, max 10 connections/server
        builder.Services.AddHttpClient("upstream", client => client.Timeout = TimeSpan.FromMinutes(5))
        .ConfigurePrimaryHttpMessageHandler(sp => new System.Net.Http.SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(30),
            MaxConnectionsPerServer = 10,
            MaxAutomaticRedirections = 3,
            AllowAutoRedirect = true,
            ResponseDrainTimeout = TimeSpan.FromSeconds(30),
            // api.nuget.org's registration5-gz-* variants force Content-Encoding: gzip
            // regardless of Accept-Encoding. Other upstream metadata endpoints (PyPI's
            // simple index, npm's registry) negotiate normally. Package blob downloads are
            // already compressed at the file level (.tar.gz, .tgz, .nupkg=zip) and upstream
            // CDNs serve them with Content-Encoding: identity, so checksum bytes are
            // unaffected.
            AutomaticDecompression = System.Net.DecompressionMethods.All,
            // SSRF gate: validate the dialed IP on every connection and redirect hop.
            ConnectCallback = sp.GetRequiredService<SsrfConnectCallback>().ConnectAsync,
        });

        // Named HTTP client for OCI upstream proxy.
        // Timeout is configurable via Oci:UpstreamHttpTimeout (default 30 min — large layer blobs).
        // AutomaticDecompression is disabled: OCI layer blobs are already compressed at the file
        // level and we need the raw bytes for SHA-256 digest verification.
        builder.Services.AddHttpClient("OciUpstream", (sp, client) =>
        {
            var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<Dependably.Configuration.OciOptions>>();
            client.Timeout = opts.Value.UpstreamHttpTimeout;
        })
        .ConfigurePrimaryHttpMessageHandler(sp => new System.Net.Http.SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(30),
            MaxConnectionsPerServer = 20,
            MaxAutomaticRedirections = 5,
            AllowAutoRedirect = true,
            ResponseDrainTimeout = TimeSpan.FromSeconds(30),
            // Do NOT decompress: OCI layer blobs are raw compressed tarballs.
            // Decompressing would corrupt the digest (the digest is over the compressed bytes).
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            // SSRF gate: OciUpstreamResolver does no URL pre-check, so the connect callback
            // is the sole gate here — it validates the dialed IP on every hop.
            ConnectCallback = sp.GetRequiredService<SsrfConnectCallback>().ConnectAsync,
        });

        // Fallback generic client (used by non-upstream code)
        builder.Services.AddHttpClient();

        // Named client for outbound healthcheck pinger — no redirects, no auth, short timeout
        builder.Services.AddHttpClient("healthcheck-pinger", client => client.Timeout = TimeSpan.FromSeconds(
                int.TryParse(builder.Configuration["HEALTHCHECK_PING_TIMEOUT_SECONDS"], out int t) ? t : 10))
        .ConfigurePrimaryHttpMessageHandler(sp => new System.Net.Http.SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            // SSRF defense-in-depth: HEALTHCHECK_PING_URL is operator-supplied, but a
            // misconfigured or over-trusted value must not reach private/link-local
            // ranges — same shared gate as the upstream proxy clients.
            ConnectCallback = sp.GetRequiredService<SsrfConnectCallback>().ConnectAsync,
        });

        // Upload limit resolver
        builder.Services.AddSingleton<Dependably.Protocol.IUploadLimitResolver, Dependably.Protocol.UploadLimitResolver>();

        // i18n — request localization with en (default) and fr
        builder.Services.AddLocalization(o => o.ResourcesPath = "Resources");
        builder.Services.Configure<RequestLocalizationOptions>(options =>
        {
            var supported = new[] { new CultureInfo("en"), new CultureInfo("fr") };
            options.DefaultRequestCulture = new RequestCulture("en");
            options.SupportedCultures = supported;
            options.SupportedUICultures = supported;
            options.RequestCultureProviders = new List<IRequestCultureProvider>
            {
                new QueryStringRequestCultureProvider(),
                new CookieRequestCultureProvider(),
                new AcceptLanguageHeaderRequestCultureProvider()
            };
        });

        // ProblemResults — scoped so IStringLocalizer resolves per-request culture
        builder.Services.AddScoped<ProblemResults>();

        // Controller dependency aggregates — let DI assemble these from already-registered
        // singletons. Each is a single ctor param on its respective controller, replacing
        // 12-15 individual injections (S107). Bodies still reference the unpacked fields.
        builder.Services.AddScoped<NpmControllerServices>();
        builder.Services.AddScoped<NuGetControllerServices>();
        builder.Services.AddScoped<PyPiControllerServices>();
        builder.Services.AddScoped<MavenControllerServices>();
        builder.Services.AddSingleton<Dependably.Protocol.IRpmUpstreamProxy, Dependably.Protocol.RpmUpstreamProxy>();
        builder.Services.AddScoped<RpmControllerServices>();
        builder.Services.AddSingleton<Dependably.Storage.RpmRepodataService>();
        builder.Services.AddScoped<OciControllerServices>();
        builder.Services.AddScoped<OrgControllerServices>();
        builder.Services.AddSingleton<Dependably.Api.GoLatestFetchCoordinator>();
        builder.Services.AddScoped<GoControllerServices>();

        // Controllers + OpenAPI
        // Explicit application part ensures controllers are found even when ConfigureBuilder
        // is called from a different entry assembly (e.g. the test project).
        builder.Services.AddControllers(options =>
            {
                options.Filters.AddService<Dependably.Security.RouteScopeFilter>();
                // After RouteScopeFilter (realm first), block flagged users until they rotate.
                options.Filters.AddService<Dependably.Security.PasswordRotationGuard>();
            })
            .AddApplicationPart(typeof(Program).Assembly)
            .AddDataAnnotationsLocalization()
            .AddJsonOptions(o =>
                // Strict API stance — unknown JSON fields fail binding with a 400. Prevents
                // silent intent loss (e.g. callers misspelling a field name or sending a
                // retired field), and complements the explicit retired-field guards in
                // controller actions.
                o.JsonSerializerOptions.UnmappedMemberHandling =
                    System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow);
        // Two named OpenAPI documents — split by route prefix so the management API
        // (versioned, /api/v1/…) and the registry protocol surfaces (canonical roots
        // mandated by each upstream spec: /v2/ OCI, /simple/ PyPI, /npm/, /nuget/v3/, …)
        // get separate specs and separate UI mounts. The split is route-prefix-driven,
        // not attribute-driven, so new controllers land in the right document automatically.
        static bool IsManagementPath(Microsoft.AspNetCore.Mvc.ApiExplorer.ApiDescription api) =>
            api.RelativePath is { } path
            && path.StartsWith("api/v1/", StringComparison.OrdinalIgnoreCase);

        static void ConfigureCommonOpenApi(Microsoft.AspNetCore.OpenApi.OpenApiOptions options)
        {
            options.AddDocumentTransformer<Dependably.Infrastructure.OpenApi.SecuritySchemeDocumentTransformer>();
            options.AddDocumentTransformer<Dependably.Infrastructure.OpenApi.DocumentMetadataTransformer>();
            options.AddOperationTransformer<Dependably.Infrastructure.OpenApi.SecuritySchemeOperationTransformer>();
        }

        builder.Services.AddOpenApi("management", options =>
        {
            ConfigureCommonOpenApi(options);
            options.ShouldInclude = IsManagementPath;
        });

        builder.Services.AddOpenApi("protocol", options =>
        {
            ConfigureCommonOpenApi(options);
            options.ShouldInclude = api => !IsManagementPath(api);
        });

        // Response compression — Brotli preferred, then GZip
        builder.Services.AddResponseCompression(o =>
        {
            o.EnableForHttps = true;
            o.Providers.Add<Microsoft.AspNetCore.ResponseCompression.BrotliCompressionProvider>();
            o.Providers.Add<Microsoft.AspNetCore.ResponseCompression.GzipCompressionProvider>();
        });
    }

    // Forwarded headers — honour X-Forwarded-For/Proto/Host so Request.IsHttps and Request.Host
    // reflect the client-facing values behind a TLS-terminating reverse proxy. When TRUSTED_PROXIES
    // is set, only those source IPs/networks may set X-Forwarded-*; otherwise forwarded headers are
    // accepted from any immediate forwarder (back-compat for existing self-hosted deployments behind
    // varied proxies — StartupService warns that this is spoofable). X-Forwarded-Host is included so
    // SubdomainTenantResolver reads the rewritten Request.Host instead of the raw header directly,
    // ensuring proxy allowlist validation applies equally to tenant resolution.
    private static void ConfigureForwardedHeaders(WebApplicationBuilder builder)
    {
        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();

            var (networks, proxies) = Dependably.Infrastructure.ConfigurationExtensions.ParseTrustedProxies(builder.Configuration["TRUSTED_PROXIES"]);
            if (networks.Count > 0 || proxies.Count > 0)
            {
                foreach (var n in networks)
                {
                    options.KnownIPNetworks.Add(n);
                }

                foreach (var p in proxies)
                {
                    options.KnownProxies.Add(p);
                }

                options.ForwardLimit = null; // walk the chain to the first untrusted hop
            }
        });
    }

    // JWT authentication — secret loaded at startup after first-boot via a deferred key resolver
    // so the secret is read from DB after schema init. Pairs the Bearer scheme (admin/UI path,
    // cookie-backed) with the ApiToken scheme for protocol clients.
    private static void ConfigureJwtAuthentication(WebApplicationBuilder builder)
    {
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Events = new JwtBearerEvents
                {
                    // Read JWT from cookie for UI sessions
                    OnMessageReceived = ctx =>
                    {
                        ctx.Token = ctx.Request.Cookies["dependably_session"];
                        return Task.CompletedTask;
                    },
                    // Reject revoked tokens (logged-out sessions) and tenant sessions whose
                    // token_version is stale (invalidated by a password change).
                    OnTokenValidated = OnJwtTokenValidatedAsync,
                };
                // Keep JWT claim names as-is (role, sub, org_id) without mapping to ClaimTypes URIs
                options.MapInboundClaims = false;
                // Validation parameters are configured after first-boot below
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidateIssuerSigningKey = true,
                    // Explicit algorithm allow-list so only HS256 tokens are accepted, matching issuance in LoginService
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                    // Placeholder — replaced after first-boot with actual secret
                    IssuerSigningKey = new SymmetricSecurityKey(new byte[32])
                };
            })
            // API-token scheme for protocol endpoints. Endpoints opt in via
            // [Authorize(AuthenticationSchemes = "Bearer,ApiToken")] — JWT (admin path)
            // and API tokens (npm/pypi/nuget clients) both authenticate. Anonymous-pull
            // endpoints don't add [Authorize] and stay on their existing
            // ResolveTokenAsync flow so the "no token + AnonymousPull=true" case still
            // works.
            .AddScheme<TokenAuthenticationOptions, TokenAuthenticationHandler>(
                TokenAuthenticationDefaults.Scheme, _ => { });
    }

    // Validates a JWT after signature verification: checks the jti against the revocation
    // store, then for tenant-scope sessions verifies the token_version claim hasn't been
    // superseded by a password change. System-scope JWTs (scope != "tenant") skip the
    // version check — they reference system_admins, not the per-tenant users table.
    private static async Task OnJwtTokenValidatedAsync(TokenValidatedContext ctx)
    {
        string? jti = ctx.Principal?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti)?.Value;
        if (jti is not null)
        {
            var revocations = ctx.HttpContext.RequestServices.GetRequiredService<JwtRevocationRepository>();
            if (await revocations.IsRevokedAsync(jti))
            {
                ctx.Fail("Token has been revoked.");
                return;
            }
        }

        // Tenant sessions snapshot users.token_version at issuance (`tver` claim,
        // absent = 1 to match the column default). A password change bumps the stored
        // version, staling every previously issued session.
        if (ctx.Principal?.FindFirst("scope")?.Value != "tenant")
        {
            return;
        }

        string? sub = ctx.Principal.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
        if (sub is null)
        {
            return;
        }

        long claimVersion = long.TryParse(ctx.Principal.FindFirst("tver")?.Value, out long v) ? v : 1;
        var versions = ctx.HttpContext.RequestServices.GetRequiredService<UserTokenVersionStore>();
        long? current = await versions.GetCurrentVersionAsync(sub);
        if (current is null || claimVersion < current.Value)
        {
            ctx.Fail("Session has been invalidated.");
        }
    }

    // Serilog — structured JSON logging with sensitive field redaction.
    // Optional OTel logs bridge (Serilog.Sinks.OpenTelemetry) ships log records via
    // OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set. Air-gap deployments leave it unset
    // and keep the console sink only. See docs/observability/logs.md.
    private static void ConfigureLogging(WebApplicationBuilder builder)
    {
        builder.Host.UseSerilog((ctx, services, cfg) =>
        {
            cfg.ReadFrom.Configuration(ctx.Configuration)
               .ReadFrom.Services(services)
               .Enrich.FromLogContext()
               .Enrich.With<SensitivePropertyEnricher>()
               .Destructure.With<LogSanitizingDestructuringPolicy>()
               .WriteTo.Console(new RenderedCompactJsonFormatter());

            string? otlpEndpoint = ctx.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
            if (!string.IsNullOrWhiteSpace(otlpEndpoint))
            {
                cfg.WriteTo.OpenTelemetry(o =>
                {
                    o.Endpoint = otlpEndpoint;
                    o.ResourceAttributes = new Dictionary<string, object>
                    {
                        ["service.name"] = ctx.Configuration["OTEL_SERVICE_NAME"] ?? "dependably",
                        ["service.namespace"] = "dependably-community",
                        ["service.version"] = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
                        ["deployment.environment"] = ctx.Configuration["DEPLOYMENT_ENVIRONMENT"] ?? "unknown",
                        ["dependably.instance.role"] = ctx.Configuration["DEPENDABLY_INSTANCE_ROLE"] ?? "single",
                    };
                });
            }
        });
    }

    // OpenTelemetry SDK — metrics + traces. Exports metrics via the built-in
    // Prometheus scraping endpoint (registered later as /metrics) and, when
    // OTEL_EXPORTER_OTLP_ENDPOINT is set, also via OTLP push (metrics + traces).
    // See docs/observability/metrics.md and docs/observability/traces.md.
    private static void ConfigureOpenTelemetry(WebApplicationBuilder builder)
    {
        string? otlpEndpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
        double sampleRatio = double.TryParse(
            builder.Configuration["OTEL_TRACES_SAMPLER_ARG"],
            out double ratio) ? ratio : 0.1;

        builder.Services.AddSingleton<Dependably.Infrastructure.Observability.TenantSpanEnricher>();

        builder.Services.AddOpenTelemetry()
            .ConfigureResource(rb => rb
                .AddService(
                    serviceName: builder.Configuration["OTEL_SERVICE_NAME"] ?? "dependably",
                    serviceNamespace: "dependably-community",
                    serviceVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0")
                .AddAttributes(new Dictionary<string, object>
                {
                    ["deployment.environment"] = builder.Configuration["DEPLOYMENT_ENVIRONMENT"] ?? "unknown",
                    ["dependably.instance.role"] = builder.Configuration["DEPENDABLY_INSTANCE_ROLE"] ?? "single",
                    // OTel .NET's default resource detector doesn't add these; set explicitly
                    // so taxonomy.md's commitment to host.name / process.runtime.name holds.
                    ["host.name"] = Environment.MachineName,
                    ["process.runtime.name"] = "dotnet",
                    ["process.runtime.version"] = Environment.Version.ToString(),
                }))
            .WithMetrics(mb =>
            {
                mb.AddAspNetCoreInstrumentation()
                  .AddHttpClientInstrumentation()
                  .AddMeter(Dependably.Infrastructure.Observability.DependablyMeter.MeterName)
                  .AddPrometheusExporter();

                if (!string.IsNullOrWhiteSpace(otlpEndpoint))
                {
                    mb.AddOtlpExporter();
                }
            })
            .WithTracing(tb =>
            {
                tb.AddAspNetCoreInstrumentation(opts =>
                    // Stamp dependably.operation on framework-emitted server spans
                    // using the route→operation map. EnrichWithHttpResponse runs
                    // after routing, so http.route is already set on the activity.
                    opts.EnrichWithHttpResponse = (activity, _) =>
                    {
                        string? route = activity.GetTagItem("http.route") as string;
                        string? method = activity.GetTagItem("http.request.method") as string;
                        string? op = Dependably.Infrastructure.Observability.OperationTagger.Map(route, method);
                        if (op is not null)
                        {
                            activity.SetTag("dependably.operation", op);
                        }
                    })
                  .AddHttpClientInstrumentation()
                  .AddSource(Dependably.Infrastructure.Observability.DependablyActivitySource.SourceName)
                  .AddProcessor<Dependably.Infrastructure.Observability.TenantSpanEnricher>()
                  .SetSampler(new ParentBasedSampler(new TraceIdRatioBasedSampler(sampleRatio)));

                if (!string.IsNullOrWhiteSpace(otlpEndpoint))
                {
                    tb.AddOtlpExporter();
                }
            });
    }

    // Graceful shutdown — configurable pre-stop delay + drain period
    private static void ConfigureGracefulShutdown(WebApplicationBuilder builder)
    {
        int gracePeriod = int.TryParse(builder.Configuration["SHUTDOWN_GRACE_PERIOD"], out int gp) ? gp : 30;
        builder.Host.ConfigureHostOptions(o => o.ShutdownTimeout = TimeSpan.FromSeconds(gracePeriod));
        builder.Services.AddSingleton<ShutdownState>();
        builder.Services.AddHostedService<ShutdownOrchestrator>();
    }

    private static void ConfigureMetadataStore(WebApplicationBuilder builder)
    {
        string dbProvider = (builder.Configuration["DB_PROVIDER"] ?? "sqlite").ToLowerInvariant();
        string? dbConnStr = builder.Configuration["DB_CONNECTION_STRING"];
        string dbPath = builder.Configuration["DB_PATH"] ?? "/data/dependably.db";

        IMetadataStore metadataStore = dbProvider switch
        {
            "postgres" => new NpgsqlMetadataStore(
                dbConnStr ?? throw new InvalidOperationException("DB_CONNECTION_STRING required for DB_PROVIDER=postgres")),
            // Cache=Shared is the legacy SQLite shared-cache mode that introduces
            // table-level locking and reduces WAL read concurrency. WAL with private
            // per-connection caches is the recommended configuration.
            _ => new SqliteMetadataStore($"Data Source={dbPath};Mode=ReadWriteCreate")
        };
        builder.Services.AddSingleton<IMetadataStore>(metadataStore);
        builder.Services.AddSingleton<SchemaInitializer>();
        builder.Services.AddSingleton<FirstBootService>();
    }

    // Blob storage. STORAGE_BACKEND selects the default backend for both tiers; per-tier
    // overrides (STORAGE_BACKEND_CACHE / STORAGE_BACKEND_REGISTRY plus the corresponding
    // backend-specific vars suffixed _CACHE / _REGISTRY) opt one or both tiers into a
    // different backing store for split-tier deployments.
    //
    // The default IBlobStore registration resolves to the REGISTRY tier so legacy callers
    // that don't know about the split land on durable storage (the safer default — losing
    // a registry write loses a published artefact, while losing a cache write just causes
    // a re-fetch from upstream).
    private static void ConfigureBlobStore(WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<TieredBlobStorage>(_ =>
        {
            var cfg = builder.Configuration;
            var defaultStore = BlobStoreFactory.Create(cfg);
            // A per-tier override (any *_CACHE / *_REGISTRY env var) tells the factory
            // to build that tier its own store. Without an override the tier shares the
            // default instance, preserving the current single-IBlobStore behaviour for
            // legacy deployments.
            var cache = HasTierOverride(cfg, "CACHE")
                ? BlobStoreFactory.CreateForTier(cfg, "CACHE")
                : defaultStore;
            var registry = HasTierOverride(cfg, "REGISTRY")
                ? BlobStoreFactory.CreateForTier(cfg, "REGISTRY")
                : defaultStore;
            return new TieredBlobStorage(cache, registry);
        });
        builder.Services.AddSingleton<IBlobStore>(sp =>
            sp.GetRequiredService<TieredBlobStorage>().Registry);
        // Tenant-aware registry resolver. Singleton lifetime is non-negotiable: the
        // enterprise impl memoizes per-tenant S3BlobStore instances and per-request
        // scoping would defeat the cache and leak S3 clients. Community impl returns
        // the singleton registry regardless of tenant, but still applies status +
        // provisioning-state gates defensively.
        builder.Services.AddSingleton<ITenantStorageResolver, GlobalTenantStorageResolver>();
    }

    /// <summary>
    /// True if any tier-specific storage env var is set for the given suffix. We don't try
    /// to be clever about which combinations are valid; a single override is enough to
    /// signal "this tier wants its own backend" and the factory throws if required vars
    /// are missing.
    /// </summary>
    private static bool HasTierOverride(ConfigurationManager cfg, string tier) =>
        !string.IsNullOrWhiteSpace(cfg[$"STORAGE_BACKEND_{tier}"])
        || !string.IsNullOrWhiteSpace(cfg[$"LOCAL_STORAGE_PATH_{tier}"])
        || !string.IsNullOrWhiteSpace(cfg[$"S3_BUCKET_{tier}"])
        || !string.IsNullOrWhiteSpace(cfg[$"AZURE_CONNECTION_STRING_{tier}"]);

    // Redis — optional in standalone mode, required in HA mode. When configured, also
    // shares Data Protection keys across replicas via Redis.
    private static void ConfigureRedisAndDataProtection(WebApplicationBuilder builder)
    {
        builder.Services.Configure<RedisOptions>(opts =>
        {
            opts.ConnectionString = builder.Configuration["REDIS_CONNECTION_STRING"];
            opts.Password = builder.Configuration["REDIS_PASSWORD"];
            opts.Ssl = bool.TryParse(builder.Configuration["REDIS_SSL"], out bool ssl) && ssl;
            opts.Database = int.TryParse(builder.Configuration["REDIS_DATABASE"], out int db) ? db : 0;
            opts.KeyPrefix = builder.Configuration["REDIS_KEY_PREFIX"] ?? "dependably:";
        });

        string deploymentMode = (builder.Configuration["DEPENDABLY_DEPLOYMENT_MODE"] ?? "standalone").ToLowerInvariant();
        string? redisConnStr = builder.Configuration["REDIS_CONNECTION_STRING"];

        if (deploymentMode == "ha" && string.IsNullOrWhiteSpace(redisConnStr))
        {
            throw new InvalidOperationException(
                "DEPENDABLY_DEPLOYMENT_MODE=ha requires REDIS_CONNECTION_STRING to be set.");
        }

        if (string.IsNullOrWhiteSpace(redisConnStr))
        {
            builder.Services.AddSingleton<IDistributedLock, InProcessDistributedLock>();
            builder.Services.AddSingleton<ILockoutStore, SqliteLockoutStore>();
            return;
        }

        // Capture the mux reference so Data Protection can use it without BuildServiceProvider()
        ConnectionMultiplexer? capturedMux = null;
        builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<RedisOptions>>().Value;
            var logger = sp.GetRequiredService<ILogger<IConnectionMultiplexer>>();
            var mux = ConnectionMultiplexer.Connect(opts.BuildConfigurationOptions());
            mux.ConnectionFailed += (_, e) =>
                logger.LogWarning("Redis connection failed: {Endpoint} {FailureType}", e.EndPoint, e.FailureType);
            mux.ConnectionRestored += (_, e) =>
                logger.LogInformation("Redis connection restored: {Endpoint}", e.EndPoint);
            capturedMux = mux;
            return mux;
        });
        builder.Services.AddSingleton<IRedisClient, RedisClient>();
        builder.Services.AddSingleton<IDistributedLock, RedisDistributedLock>();
        builder.Services.AddSingleton<ILockoutStore, RedisLockoutStore>();

        // Func<IDatabase> defers resolution until after DI is built.
        builder.Services.AddDataProtection()
            .SetApplicationName("dependably")
            .PersistKeysToStackExchangeRedis(
                () => capturedMux?.GetDatabase()
                    ?? throw new InvalidOperationException("Redis multiplexer not yet initialized."),
                "DataProtection-Keys");
    }

    // Rate limiting — Redis-backed when REDIS_CONNECTION_STRING is set; in-process otherwise.
    private static void ConfigureRateLimiter(WebApplicationBuilder builder)
    {
        bool useRedis = !string.IsNullOrWhiteSpace(builder.Configuration["REDIS_CONNECTION_STRING"]);
        builder.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.OnRejected = (ctx, _) =>
            {
                ctx.HttpContext.Response.Headers.RetryAfter =
                    ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter)
                        ? ((int)retryAfter.TotalSeconds).ToString()
                        : "60";

                // Metric. Endpoint metadata carries the policy name set by
                // [EnableRateLimiting("…")]; partition prefix lets operators identify which
                // token (12-hex SHA prefix) or IP is being rate-locked without leaking the
                // full hash on the cardinality budget.
                string policy = ctx.HttpContext.GetEndpoint()
                    ?.Metadata.GetMetadata<EnableRateLimitingAttribute>()
                    ?.PolicyName ?? "unknown";
                string partition = Dependably.Security.RateLimitPartitions.GetMetricLabel(ctx.HttpContext);
                Dependably.Infrastructure.Observability.DependablyMeter.RateLimitRejected.Add(1,
                    new KeyValuePair<string, object?>("policy", policy),
                    new KeyValuePair<string, object?>("partition", partition));

                return ValueTask.CompletedTask;
            };

            if (useRedis)
            {
                o.AddPolicy<string, RedisRateLimitPolicy>("login");
                o.AddPolicy<string, RedisRateLimitPolicy>("invite");
                o.AddPolicy<string, RedisRateLimitPolicy>("token-create");
                // Download / push run in-process even with Redis configured. The
                // limiter state is per-second sliding-window over a request-derived
                // partition key — Redis round-trips would land on the very hot path we're
                // trying to protect.
                AddDownloadPushLimiters(builder.Configuration, o);
            }
            else
            {
                AddInProcessLimiters(builder.Configuration, o);
                AddDownloadPushLimiters(builder.Configuration, o);
            }

            // The anonymous-probe limiter is in-process in both modes: liveness /
            // bootstrap endpoints are polled per replica, so per-replica state is the
            // correct scope and Redis round-trips would add latency to health probes.
            AddAnonymousProbeLimiter(builder.Configuration, o);

            // Global default covers authenticated management endpoints (/api/v1/*) that
            // carry no endpoint-specific policy. The SPA and CI tooling hit /api/v1 at
            // human-interactive rates; 300 requests/min per principal handles normal bursts
            // (package-list pagination, audit log queries, settings reads) without 429s.
            // Paths outside /api/v1/ and /api/v1/docs/* get NoLimiter — protocol surfaces,
            // health probes, and Swagger UI assets are guarded by their own policies.
            AddManagementApiLimiter(builder.Configuration, o);
        });
    }

    // Download / push limiters. Partition by token-hash with IP fallback so a single
    // misbehaving client can't saturate the writer queue and DoS other tenants.
    private static void AddDownloadPushLimiters(ConfigurationManager cfg, RateLimiterOptions o)
    {
        // Defaults sized for real-world enterprise CI bursts, not single-tenant lab use:
        // a normal `npm install` of a Next.js-sized app fires ~600 tarball GETs from one
        // partition in a few seconds, and pnpm/yarn parallelize harder. 1000 permits/sec
        // covers a single developer's worst burst without 429s; sustained abuse still
        // 429s once the queue fills. Operators dial DOWNLOAD_RATE_LIMIT_PERMITS up for
        // bigger fleets.
        //
        // QueueLimit = 500 is the change that matters most for UX. With QueueLimit=0,
        // a brief over-burst (npm scheduling 800 fetches in one tick) returns 429
        // immediately and the install fails. With queueing, the same burst waits
        // microseconds for permits to refill, which is invisible to the client.
        // The cap + queue together still bound sustained abuse: once the queue fills,
        // additional requests get 429 with Retry-After (emitted by OnRejected above)
        // and a well-behaved client backs off.
        int downloadLimit = int.TryParse(cfg["DOWNLOAD_RATE_LIMIT_PERMITS"], out int dp) ? dp : 1000;
        int downloadQueue = int.TryParse(cfg["DOWNLOAD_RATE_LIMIT_QUEUE"], out int dq) ? dq : 500;
        o.AddPolicy("download", httpContext =>
        {
            string key = Dependably.Security.RateLimitPartitions.GetPartitionKey(httpContext);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = downloadLimit,
                    Window = TimeSpan.FromSeconds(1),
                    SegmentsPerWindow = 4,
                    QueueLimit = downloadQueue,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                });
        });

        // Push is rarer; a much lower ceiling protects the writer queue from a malformed
        // publish loop. 20 req/s burst per token.
        int pushLimit = int.TryParse(cfg["PUSH_RATE_LIMIT_PERMITS"], out int pp) ? pp : 20;
        o.AddPolicy("push", httpContext =>
        {
            string key = Dependably.Security.RateLimitPartitions.GetPartitionKey(httpContext);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = pushLimit,
                    Window = TimeSpan.FromSeconds(1),
                    SegmentsPerWindow = 4,
                    QueueLimit = 0,
                });
        });

        // Bulk import is the most resource-intensive write path: every request reads N
        // artefacts, runs ecosystem detection, stages to disk, and writes to blob store.
        // 5 requests per minute per token is generous for legitimate operator workflows
        // (a CI import script that fires more than 5 bulk batches per minute is unusual)
        // while preventing a malicious or runaway client from saturating the staging I/O
        // and writer queue. Configurable via IMPORT_RATE_LIMIT_PERMITS.
        int importLimit = int.TryParse(cfg["IMPORT_RATE_LIMIT_PERMITS"], out int ip) ? ip : 5;
        o.AddPolicy("import", httpContext =>
        {
            string key = Dependably.Security.RateLimitPartitions.GetPartitionKey(httpContext);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = importLimit,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = 4,
                    QueueLimit = 0,
                });
        });
    }

    // In-process login / invite / token-create limiters. Partitioned per client IP —
    // mirroring the Redis path's `{ip}:{policy}` buckets — so one attacker exhausting
    // its own window cannot lock out every other client instance-wide. The key is the
    // normalized remote IP (not the token-preferring download/push key): these endpoints
    // are hit before credentials are validated, and an attacker-supplied Authorization
    // header must not buy a fresh partition per attempt.
    private static void AddInProcessLimiters(ConfigurationManager cfg, Microsoft.AspNetCore.RateLimiting.RateLimiterOptions o)
    {
        int loginLimit = int.TryParse(cfg["LOGIN_RATE_LIMIT_PERMITS"], out int p) ? p : 10;
        AddPerIpFixedWindowLimiter(o, "login", loginLimit, TimeSpan.FromMinutes(1));

        AddPerIpFixedWindowLimiter(o, "invite", 20, TimeSpan.FromHours(1));

        int tokenCreateLimit = int.TryParse(cfg["TOKEN_CREATE_RATE_LIMIT_PERMITS"], out int t) ? t : 60;
        AddPerIpFixedWindowLimiter(o, "token-create", tokenCreateLimit, TimeSpan.FromHours(1));
    }

    // Per-IP cap for the unauthenticated probe surface (/health, /ready, /version,
    // /api/v1/bootstrap, /api/v1/auth/methods, /api/v1/licenses). /ready fans out to
    // DB + blob store + Redis per call, so an anonymous flood amplifies load onto the
    // backing stores. The default budget is generous: orchestrator health probes run a
    // few requests per minute per prober, far below 120/min per source IP.
    private static void AddAnonymousProbeLimiter(ConfigurationManager cfg, Microsoft.AspNetCore.RateLimiting.RateLimiterOptions o)
    {
        int anonLimit = int.TryParse(cfg["ANON_RATE_LIMIT_PERMITS"], out int a) ? a : 120;
        AddPerIpFixedWindowLimiter(o, "anon", anonLimit, TimeSpan.FromMinutes(1));
    }

    // Default guard for the authenticated management surface (/api/v1/*). Partitions by
    // the principal identity — API-token hash first, then authenticated user (sub claim
    // from the cookie session), then client IP for anonymous requests — so a misbehaving
    // automation client or a NAT'd-office burst can't starve other principals.
    // /api/v1/docs/* is exempt: Swagger UI assets are IP-allowlisted, not API traffic,
    // and should not consume API budget.
    // Non-management paths receive NoLimiter; endpoint-specific policies (login, push,
    // download, …) stack on top.
    // QueueLimit=0: management callers receive 429 immediately and should back off
    // exponentially; the SPA handles this at the fetch layer.
    private static void AddManagementApiLimiter(ConfigurationManager cfg, Microsoft.AspNetCore.RateLimiting.RateLimiterOptions o)
    {
        int permitLimit = int.TryParse(cfg["MANAGEMENT_RATE_LIMIT_PERMITS"], out int m) ? m : 300;
        o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        {
            string? path = ctx.Request.Path.Value;
            if (path is null
                || !path.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/v1/docs/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/api/v1/docs", StringComparison.OrdinalIgnoreCase))
            {
                return RateLimitPartition.GetNoLimiter<string>("none");
            }

            string key = Dependably.Security.RateLimitPartitions.GetManagementPartitionKey(ctx);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = 6,
                    QueueLimit = 0,
                });
        });
    }

    // Requests with no resolvable remote IP (in-process probes) share one "unknown"
    // bucket rather than bypassing the limiter entirely.
    private static void AddPerIpFixedWindowLimiter(
        Microsoft.AspNetCore.RateLimiting.RateLimiterOptions o, string policyName, int permitLimit, TimeSpan window)
    {
        o.AddPolicy(policyName, httpContext =>
        {
            string key = httpContext.GetNormalizedRemoteIp() ?? "unknown";
            return RateLimitPartition.GetFixedWindowLimiter(key,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = window,
                    QueueLimit = 0,
                });
        });
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

        // Forwarded headers run first so every downstream consumer of
        // Connection.RemoteIpAddress and Request.IsHttps — the /metrics IP allowlist,
        // rate-limit partition keys, audit source_ip, HSTS emission, cookie Secure
        // decisions — sees the client-facing values rewritten from X-Forwarded-For /
        // X-Forwarded-Proto (subject to TRUSTED_PROXIES). Nothing in the pipeline
        // needs the raw proxy-connection values.
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
        app.MapGet("/version", async (HttpContext ctx, MetricsAccessConfig metricsAccess) =>
        {
            var resolved = await metricsAccess.ResolveAsync(ctx.RequestAborted);
            var remote = ctx.Connection.RemoteIpAddress;
            return remote is null || !MetricsAccessMiddleware.IsIpAllowed(remote, resolved.Allowed)
                ? Results.StatusCode(StatusCodes.Status403Forbidden)
                : Results.Ok(new { version });
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

        // Vendored Swagger UI mounted at two URLs — one per OpenAPI document.
        // /api/v1/docs/ → management spec (/openapi/management.json)
        // /docs/        → protocol  spec (/openapi/protocol.json)
        // The shell (index.html + JS/CSS) is identical at both mounts; assets use
        // relative paths, and swagger-initializer.js picks the spec URL based on
        // window.location.pathname. The bare /api/v1/docs and /docs URLs redirect
        // to their trailing-slash form so relative asset paths resolve correctly.
        var swaggerProvider = new SubPathFileProvider(app.Environment.WebRootFileProvider, "/swagger");

        // UseDefaultFiles relies on GetDirectoryContents(subpath).Exists, which the dev
        // StaticWebAssets provider returns false for; serve the shell explicitly via a
        // local helper reused by both mounts.
        Func<HttpContext, Task> ServeSwaggerShell(Microsoft.Extensions.FileProviders.IFileProvider provider) =>
            async ctx =>
            {
                var file = provider.GetFileInfo("/index.html");
                if (!file.Exists)
                {
                    ctx.Response.StatusCode = 404;
                    return;
                }
                ctx.Response.ContentType = "text/html";
                await ctx.Response.SendFileAsync(file);
            };

        // Canonicalize bare doc URLs to their trailing-slash form so the relative asset
        // paths in the shared swagger shell (./swagger-ui.css etc.) resolve correctly.
        // Done via middleware rather than a second MapGet endpoint because ASP.NET Core
        // endpoint routing treats `/foo` and `/foo/` as the same template — registering
        // both throws AmbiguousMatchException at request time. Middleware runs before
        // endpoint matching, so there's no ambiguity.
        app.Use(async (ctx, next) =>
        {
            string? path = ctx.Request.Path.Value;
            if (path is "/api/v1/docs" or "/docs")
            {
                ctx.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
                ctx.Response.Headers.Location = path + "/" + ctx.Request.QueryString.Value;
                return;
            }
            await next();
        });

        // Mount 1 — Management API (existing UI URL preserved). The doc-shell endpoint
        // is excluded from OpenAPI so it doesn't pollute the spec or contract gate.
        app.UseStaticFiles(new StaticFileOptions { FileProvider = swaggerProvider, RequestPath = "/api/v1/docs" });
        app.MapGet("/api/v1/docs/", ServeSwaggerShell(swaggerProvider)).ExcludeFromDescription();

        // Mount 2 — Registry Protocols
        app.UseStaticFiles(new StaticFileOptions { FileProvider = swaggerProvider, RequestPath = "/docs" });
        app.MapGet("/docs/", ServeSwaggerShell(swaggerProvider)).ExcludeFromDescription();

        // Prometheus exposition served by OpenTelemetry's Prometheus exporter.
        // RED metrics (rate/errors/duration) come automatically from
        // AddAspNetCoreInstrumentation in ConfigureOpenTelemetry. The IP
        // allowlist on /metrics is preserved by MetricsAccessMiddleware
        // earlier in the pipeline. See docs/observability/metrics.md.
        // Deliberately outside the OpenAPI inventory (management and protocol documents):
        // operator-only scrape endpoint, IP-allowlisted, documented in docs/observability.
        app.MapPrometheusScrapingEndpoint("/metrics");

        // OpenAPI specs — named-document pattern serves both /openapi/management.json
        // and /openapi/protocol.json. No back-compat for /api/v1/openapi.json.
        app.MapOpenApi("/openapi/{documentName}.json");

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
         "/docs/", "/openapi/", "/cargo/"];

    private static readonly string[] NonSpaExactPaths = ["/health", "/ready", "/metrics", "/docs", "/cargo/config.json"];

    private static bool IsNonSpaPath(string path) =>
        NonSpaPathPrefixes.Any(p => path.StartsWith(p, StringComparison.Ordinal))
        || NonSpaExactPaths.Contains(path);

    private static Func<HttpContext, Task> BuildSpaFallback(Microsoft.Extensions.FileProviders.IFileProvider embeddedProvider) =>
        async ctx =>
        {
            string path = ctx.Request.Path.Value ?? "";
            if (IsNonSpaPath(path))
            {
                ctx.Response.StatusCode = 404;
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
