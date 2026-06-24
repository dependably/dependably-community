using System.Threading.RateLimiting;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Redis;
using Dependably.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers authentication (JWT Bearer + ApiToken), tenant resolution, authorization
/// policies, rate limiting, and Redis + Data Protection when configured.
/// </summary>
internal static class AuthStartupExtensions
{
    // Placeholder JWT key length (bytes) used before the real secret is loaded from the DB.
    private const int JwtKeyPlaceholderLength = 32;

    // Sliding-window rate-limiter segments per window (balances accuracy vs. memory).
    private const int RateLimitWindowSegments = 4;

    // Management API limiter uses more segments for finer-grained burst smoothing.
    private const int ManagementRateLimitWindowSegments = 6;

    // Default permit count for the invite rate limiter (per IP, per hour).
    private const int InviteRateLimitPermitsDefault = 20;

    internal static void AddDependablyTenantResolution(this WebApplicationBuilder builder)
    {
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
                // Multi mode resolves tenants by subdomain under an apex host derived from BASE_URL.
                // Without a real (non-localhost) BASE_URL host, every bare/IP/non-subdomain request
                // falls to apex/uninitialized and per-tenant login methods (forms, SAML) never render.
                // Warn so the misconfig is visible instead of silently hiding the login page.
                if (!BaseUrlHostHelper.IsUsableApexHost(builder.Configuration["BASE_URL"]))
                {
                    Serilog.Log.Warning(
                        "DEPLOYMENT_MODE=multi but BASE_URL is unset or contains a localhost host. "
                        + "Tenants are reached at slug.apexhost; non-subdomain hosts resolve to apex/uninitialized "
                        + "and per-tenant login methods such as SAML will not appear. Set BASE_URL to a "
                        + "non-localhost URL (e.g. https://repo.example.com), or use "
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
    }

    internal static void AddDependablyJwt(this WebApplicationBuilder builder)
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
                    IssuerSigningKey = new SymmetricSecurityKey(new byte[JwtKeyPlaceholderLength])
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

        // The bearer handler reads its clock from the same DI TimeProvider that LoginService
        // issues tokens with, so a substituted clock can never split issue and validation time.
        builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<TimeProvider>((options, time) => options.TimeProvider = time);

        builder.Services.AddAuthorization();
        // Capability enforcement: dynamic policy provider materialises a policy per
        // [RequireCapability("...")] attribute; the handler resolves the principal's role
        // claim through Capabilities.ForRole and checks Capabilities.Grants.
        builder.Services.AddSingleton<IAuthorizationPolicyProvider, CapabilityPolicyProvider>();
        builder.Services.AddSingleton<IAuthorizationHandler, CapabilityHandler>();

        // Global RouteScopeFilter rejects any /api/v1/ request whose JWT lacks a
        // `scope` claim and pins each scope to its realm: tenant routes require
        // scope=tenant + matching tid, system routes require scope=system + apex.
        builder.Services.AddScoped<RouteScopeFilter>();
        // Forces a user holding a temporary password to rotate it before using the API.
        builder.Services.AddScoped<PasswordRotationGuard>();
        // Forces a user to complete MFA enrollment when the policy requires it.
        builder.Services.AddScoped<MfaEnrollmentGuard>();
    }

    // Validates a JWT after signature verification: checks the jti against the revocation
    // store, then verifies the token_version claim for both tenant and system scope sessions
    // so a password change immediately invalidates all outstanding sessions regardless of
    // which surface issued them.
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

        string? scope = ctx.Principal?.FindFirst("scope")?.Value;
        string? sub = ctx.Principal?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;

        if (sub is null || (scope != "tenant" && scope != "system"))
        {
            return;
        }

        // Both tenant and system sessions snapshot the issuing user's token_version in the
        // `tver` claim (absent → 1, matching the column default). A password change bumps the
        // stored version, staling every previously issued session. System JWTs carry the tver
        // claim too, defaulting to 1 when absent for back-compat with sessions minted before it existed.
        long claimVersion = long.TryParse(ctx.Principal?.FindFirst("tver")?.Value, out long v) ? v : 1;

        long? current;
        if (scope == "tenant")
        {
            var versions = ctx.HttpContext.RequestServices.GetRequiredService<UserTokenVersionStore>();
            current = await versions.GetCurrentVersionAsync(sub);
        }
        else
        {
            var versions = ctx.HttpContext.RequestServices.GetRequiredService<Dependably.Infrastructure.Identity.SystemAdminTokenVersionStore>();
            current = await versions.GetCurrentVersionAsync(sub);
        }

        if (current is null || claimVersion < current.Value)
        {
            ctx.Fail("Session has been invalidated.");
        }
    }

    internal static void AddDependablyRedisAndDataProtection(this WebApplicationBuilder builder)
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
            // Standalone path: in-process distributed lock and SQLite-backed lockout store.
            builder.Services.AddSingleton<IDistributedLock, InProcessDistributedLock>();
            builder.Services.AddSingleton<ILockoutStore, SqliteLockoutStore>();
        }
        else
        {
            // HA path: Redis-backed distributed lock, rate-limit state, and lockout store.
            // Capture the mux reference so Data Protection can use it without BuildServiceProvider().
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
            return;
        }

        // Always configure a durable DB-backed DataProtection key ring for standalone deployments
        // so encrypted values (SAML test cookies, future uses) survive process restarts. The ring
        // is cached in-memory by KeyRingProvider once loaded; the DB is written only on key rotation.
        // Security posture: the XML key material is stored unencrypted in the SQLite DB — the same
        // posture as the jwt_secret and mfa_encryption_key already stored in instance_settings.
        builder.Services.AddSingleton<DbXmlRepository>();
        builder.Services.AddDataProtection()
            .SetApplicationName("dependably");
        builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(sp =>
            new ConfigureOptions<KeyManagementOptions>(opts =>
                opts.XmlRepository = sp.GetRequiredService<DbXmlRepository>()));
    }

    internal static void AddDependablyRateLimiter(this WebApplicationBuilder builder)
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
                string partition = RateLimitPartitions.GetMetricLabel(ctx.HttpContext);
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

            // Metadata limiter is always in-process: npm/PyPI/NuGet packument/index GETs are
            // already on the very hot path — a Redis round-trip per request would negate the
            // latency advantage of the in-process RenderedResponseCache. The sliding window and
            // queue depth together absorb short bursts (CI tool startup stampede) while still
            // shedding sustained floods with 429.
            AddMetadataLimiter(builder.Configuration, o);

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
            string key = RateLimitPartitions.GetPartitionKey(httpContext);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = downloadLimit,
                    Window = TimeSpan.FromSeconds(1),
                    SegmentsPerWindow = RateLimitWindowSegments,
                    QueueLimit = downloadQueue,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                });
        });

        // Push is rarer; a much lower ceiling protects the writer queue from a malformed
        // publish loop. 20 req/s burst per token.
        int pushLimit = int.TryParse(cfg["PUSH_RATE_LIMIT_PERMITS"], out int pp) ? pp : 20;
        o.AddPolicy("push", httpContext =>
        {
            string key = RateLimitPartitions.GetPartitionKey(httpContext);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = pushLimit,
                    Window = TimeSpan.FromSeconds(1),
                    SegmentsPerWindow = RateLimitWindowSegments,
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
            string key = RateLimitPartitions.GetPartitionKey(httpContext);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = importLimit,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = RateLimitWindowSegments,
                    QueueLimit = 0,
                });
        });
    }

    // Metadata limiter: guards npm packument, PyPI simple index, and NuGet registration GETs.
    // Partitioned by the real source IP (not token-hash) because these endpoints are hit both
    // by authenticated clients and anonymous proxies, and a token-hash partition would give
    // an attacker an unbounded number of fresh buckets via forged Authorization headers.
    // When TRUSTED_PROXIES is unset the remote IP is the socket peer (fail-closed), so the
    // partition key is always a reliable proxy for the source.
    // Default: 500 permits/s sliding window, queue depth 100 so a brief CI startup burst
    // (multiple parallel install processes hitting one packument) is absorbed without 429s.
    // Sustained floods see 429 once the queue fills. Operators dial METADATA_RATE_LIMIT_PERMITS
    // up for large-fleet deployments.
    private static void AddMetadataLimiter(ConfigurationManager cfg, RateLimiterOptions o)
    {
        int metadataLimit = int.TryParse(cfg["METADATA_RATE_LIMIT_PERMITS"], out int mp) ? mp : 500;
        int metadataQueue = int.TryParse(cfg["METADATA_RATE_LIMIT_QUEUE"], out int mq) ? mq : 100;
        o.AddPolicy("metadata", httpContext =>
        {
            string key = httpContext.GetNormalizedRemoteIp() ?? "unknown";
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = metadataLimit,
                    Window = TimeSpan.FromSeconds(1),
                    SegmentsPerWindow = RateLimitWindowSegments,
                    QueueLimit = metadataQueue,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                });
        });
    }

    // In-process login / invite / token-create limiters. Partitioned per client IP —
    // mirroring the Redis path's `{ip}:{policy}` buckets — so one attacker exhausting
    // its own window cannot lock out every other client instance-wide. The key is the
    // normalized remote IP (not the token-preferring download/push key): these endpoints
    // are hit before credentials are validated, and an attacker-supplied Authorization
    // header must not buy a fresh partition per attempt.
    private static void AddInProcessLimiters(ConfigurationManager cfg, RateLimiterOptions o)
    {
        int loginLimit = int.TryParse(cfg["LOGIN_RATE_LIMIT_PERMITS"], out int p) ? p : 10;
        AddPerIpFixedWindowLimiter(o, "login", loginLimit, TimeSpan.FromMinutes(1));

        AddPerIpFixedWindowLimiter(o, "invite", InviteRateLimitPermitsDefault, TimeSpan.FromHours(1));

        int tokenCreateLimit = int.TryParse(cfg["TOKEN_CREATE_RATE_LIMIT_PERMITS"], out int t) ? t : 60;
        AddPerIpFixedWindowLimiter(o, "token-create", tokenCreateLimit, TimeSpan.FromHours(1));
    }

    // Per-IP cap for the unauthenticated probe surface (/health, /ready, /version,
    // /api/v1/bootstrap, /api/v1/auth/methods, /api/v1/licenses). /ready fans out to
    // DB + blob store + Redis per call, so an anonymous flood amplifies load onto the
    // backing stores. The default budget is generous: orchestrator health probes run a
    // few requests per minute per prober, far below 120/min per source IP.
    private static void AddAnonymousProbeLimiter(ConfigurationManager cfg, RateLimiterOptions o)
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
    private static void AddManagementApiLimiter(ConfigurationManager cfg, RateLimiterOptions o)
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

            string key = RateLimitPartitions.GetManagementPartitionKey(ctx);
            return RateLimitPartition.GetSlidingWindowLimiter(key,
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = ManagementRateLimitWindowSegments,
                    QueueLimit = 0,
                });
        });
    }

    // Requests with no resolvable remote IP (in-process probes) share one "unknown"
    // bucket rather than bypassing the limiter entirely.
    private static void AddPerIpFixedWindowLimiter(
        RateLimiterOptions o, string policyName, int permitLimit, TimeSpan window)
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

}
