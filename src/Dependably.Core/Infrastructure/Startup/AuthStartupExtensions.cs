using System.Threading.RateLimiting;
using Dependably.Security;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers the Core authentication surface's tenant resolution and the rate-limiter policies.
/// Neither pulls in JwtBearer or the Redis client: JWT-bearer registration and the HA Redis /
/// Data Protection wiring live in Dependably.Management (the full management host layers them on
/// top of the ApiToken scheme registered by <see cref="CoreAuthStartupExtensions"/>).
/// </summary>
internal static class AuthStartupExtensions
{
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
            case "edge":
                // Edge is a headless cache-only node serving one logical cache: it collapses to a
                // single implicit realm, so it reuses the single-tenant resolver (the one seeded
                // edge org). There is no per-request tenant routing on an edge.
                builder.Services.AddScoped<ITenantResolver, SingleTenantResolver>();
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

    // IPv6 network prefix (bits) that rate-limit partition keys collapse to. A routed /64 is the
    // smallest allocation a single subscriber receives, so keying below it (the full /128) lets one
    // attacker mint 2^64 fresh budgets. Operators can widen or narrow via RATE_LIMIT_IPV6_PREFIX;
    // clamped to a legal prefix length. Audit source_ip fields are unaffected — they keep the full
    // address (see GetRateLimitPartitionIp vs GetNormalizedRemoteIp).
    internal static int ResolveIpv6PartitionPrefix(ConfigurationManager cfg) =>
        int.TryParse(cfg["RATE_LIMIT_IPV6_PREFIX"], out int p) && p is >= 1 and <= 128
            ? p
            : IpAddressExtensions.DefaultIpv6PartitionPrefixBits;

    internal static void AddDependablyRateLimiter(this WebApplicationBuilder builder)
    {
        bool useRedis = !string.IsNullOrWhiteSpace(builder.Configuration["REDIS_CONNECTION_STRING"]);
        int ipv6Prefix = ResolveIpv6PartitionPrefix(builder.Configuration);
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
                // [EnableRateLimiting("…")]; the partition attribute carries only the bounded
                // partition kind (token|user|ip|unknown), never the key — the key embeds a
                // caller-controlled source address, so emitting it would let a caller mint
                // time series at will.
                string policy = ctx.HttpContext.GetEndpoint()
                    ?.Metadata.GetMetadata<EnableRateLimitingAttribute>()
                    ?.PolicyName ?? "unknown";
                string partition = RateLimitPartitions.GetMetricLabel(ctx.HttpContext, ipv6Prefix);
                Dependably.Infrastructure.Observability.DependablyMeter.RateLimitRejected.Add(1,
                    new KeyValuePair<string, object?>("policy", policy),
                    new KeyValuePair<string, object?>("partition", partition));

                return ValueTask.CompletedTask;
            };

            // The login / invite / token-create limiters are Redis-backed when a connection string
            // is configured. That policy type (RedisRateLimitPolicy) lives in Dependably.Management
            // with the Redis client, so the management wiring adds those three policies via
            // AddDependablyRedisRateLimitPolicies. This Core method registers the in-process
            // variants only when Redis is absent — the complete rate-limiter surface a no-Redis
            // (edge/standalone) host needs. Download/push run in-process in both modes.
            if (!useRedis)
            {
                AddInProcessLimiters(builder.Configuration, o, ipv6Prefix);
            }

            AddDownloadPushLimiters(builder.Configuration, o, ipv6Prefix);

            // The anonymous-probe limiter is in-process in both modes: liveness /
            // bootstrap endpoints are polled per replica, so per-replica state is the
            // correct scope and Redis round-trips would add latency to health probes.
            AddAnonymousProbeLimiter(builder.Configuration, o, ipv6Prefix);

            // Metadata limiter is always in-process: npm/PyPI/NuGet packument/index GETs are
            // already on the very hot path — a Redis round-trip per request would negate the
            // latency advantage of the in-process RenderedResponseCache. The sliding window and
            // queue depth together absorb short bursts (CI tool startup stampede) while still
            // shedding sustained floods with 429.
            AddMetadataLimiter(builder.Configuration, o, ipv6Prefix);

            // Global default covers authenticated management endpoints (/api/v1/*) that
            // carry no endpoint-specific policy. The SPA and CI tooling hit /api/v1 at
            // human-interactive rates; 300 requests/min per principal handles normal bursts
            // (package-list pagination, audit log queries, settings reads) without 429s.
            // Paths outside /api/v1/ and /api/v1/docs/* get NoLimiter — protocol surfaces,
            // health probes, and Swagger UI assets are guarded by their own policies.
            AddManagementApiLimiter(builder.Configuration, o, ipv6Prefix);
        });
    }

    // Download / push limiters. Partition by token-hash with IP fallback so a single
    // misbehaving client can't saturate the writer queue and DoS other tenants.
    private static void AddDownloadPushLimiters(ConfigurationManager cfg, RateLimiterOptions o, int ipv6Prefix)
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
            string key = RateLimitPartitions.GetPartitionKey(httpContext, ipv6Prefix);
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
            string key = RateLimitPartitions.GetPartitionKey(httpContext, ipv6Prefix);
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
            string key = RateLimitPartitions.GetPartitionKey(httpContext, ipv6Prefix);
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
    private static void AddMetadataLimiter(ConfigurationManager cfg, RateLimiterOptions o, int ipv6Prefix)
    {
        int metadataLimit = int.TryParse(cfg["METADATA_RATE_LIMIT_PERMITS"], out int mp) ? mp : 500;
        int metadataQueue = int.TryParse(cfg["METADATA_RATE_LIMIT_QUEUE"], out int mq) ? mq : 100;
        o.AddPolicy("metadata", httpContext =>
        {
            string key = httpContext.GetRateLimitPartitionIp(ipv6Prefix) ?? "unknown";
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
    private static void AddInProcessLimiters(ConfigurationManager cfg, RateLimiterOptions o, int ipv6Prefix)
    {
        int loginLimit = int.TryParse(cfg["LOGIN_RATE_LIMIT_PERMITS"], out int p) ? p : 10;
        AddPerIpFixedWindowLimiter(o, "login", loginLimit, TimeSpan.FromMinutes(1), ipv6Prefix);

        int inviteLimit = int.TryParse(cfg["INVITE_RATE_LIMIT_PERMITS"], out int inv) ? inv : InviteRateLimitPermitsDefault;
        AddPerIpFixedWindowLimiter(o, "invite", inviteLimit, TimeSpan.FromHours(1), ipv6Prefix);

        int tokenCreateLimit = int.TryParse(cfg["TOKEN_CREATE_RATE_LIMIT_PERMITS"], out int t) ? t : 60;
        AddPerIpFixedWindowLimiter(o, "token-create", tokenCreateLimit, TimeSpan.FromHours(1), ipv6Prefix);
    }

    // Per-IP cap for the unauthenticated probe surface (/health, /ready, /version,
    // /api/v1/bootstrap, /api/v1/auth/methods, /api/v1/licenses, /api/v1/remediation/skills*).
    // /ready fans out to
    // DB + blob store + Redis per call, so an anonymous flood amplifies load onto the
    // backing stores. The default budget is generous: orchestrator health probes run a
    // few requests per minute per prober, far below 120/min per source IP.
    private static void AddAnonymousProbeLimiter(ConfigurationManager cfg, RateLimiterOptions o, int ipv6Prefix)
    {
        int anonLimit = int.TryParse(cfg["ANON_RATE_LIMIT_PERMITS"], out int a) ? a : 120;
        AddPerIpFixedWindowLimiter(o, "anon", anonLimit, TimeSpan.FromMinutes(1), ipv6Prefix);
    }

    // GlobalLimiter: the fail-closed backstop that runs for EVERY request. Three postures,
    // resolved by RateLimitPartitions.ClassifyGlobalScope:
    //
    //   Deferred        — the endpoint declares its own [EnableRateLimiting]/[DisableRateLimiting]
    //                     policy (download/push/metadata/login/anon/…) or is a Swagger docs asset:
    //                     NoLimiter here, so the global never double-counts on top of it.
    //   ManagementApi   — an authenticated /api/v1/* surface with no endpoint policy: per-principal
    //                     sliding window (API-token hash → sub claim → source subnet), so a
    //                     misbehaving automation client or a NAT'd-office burst can't starve others.
    //   ProtocolDefault — DEFAULT-DENY. Any other surface with no endpoint policy — a protocol route
    //                     that carries no explicit [EnableRateLimiting] — gets a per-IP default limit
    //                     rather than NoLimiter. A newly added unmetered protocol route is therefore
    //                     bounded by default instead of entirely unlimited; the compliance gate still
    //                     requires each such route to declare an explicit policy, but the default
    //                     closes the window between "route added" and "gate enforced in review".
    //
    // QueueLimit=0: callers receive 429 immediately and should back off exponentially.
    private static void AddManagementApiLimiter(ConfigurationManager cfg, RateLimiterOptions o, int ipv6Prefix)
    {
        int permitLimit = RateLimitCeilings.ResolveManagementPermitLimit(cfg);
        // Default-deny ceiling for unclassified protocol surfaces. Generous enough that an
        // orchestrator or a modest CI client polling a niche route stays well under it, tight
        // enough that an unmetered-route flood (upstream-fetch amplification, catalogue scans)
        // cannot exhaust the shared upstream semaphore or the single-writer DB. Any route that
        // legitimately needs more throughput carries an explicit download/metadata policy.
        int protocolDefault = RateLimitCeilings.ResolveProtocolDefaultPermitLimit(cfg);
        o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        {
            switch (RateLimitPartitions.ClassifyGlobalScope(ctx))
            {
                case RateLimitPartitions.GlobalScope.ManagementApi:
                    string mkey = RateLimitPartitions.GetManagementPartitionKey(ctx, ipv6Prefix);
                    return RateLimitPartition.GetSlidingWindowLimiter(mkey,
                        _ => new SlidingWindowRateLimiterOptions
                        {
                            PermitLimit = permitLimit,
                            Window = TimeSpan.FromMinutes(1),
                            SegmentsPerWindow = ManagementRateLimitWindowSegments,
                            QueueLimit = 0,
                        });

                case RateLimitPartitions.GlobalScope.ProtocolDefault:
                    string pkey = "proto:" + (ctx.GetRateLimitPartitionIp(ipv6Prefix) ?? "unknown");
                    return RateLimitPartition.GetSlidingWindowLimiter(pkey,
                        _ => new SlidingWindowRateLimiterOptions
                        {
                            PermitLimit = protocolDefault,
                            Window = TimeSpan.FromMinutes(1),
                            SegmentsPerWindow = ManagementRateLimitWindowSegments,
                            QueueLimit = 0,
                        });

                default:
                    return RateLimitPartition.GetNoLimiter<string>("none");
            }
        });
    }

    // Requests with no resolvable remote IP (in-process probes) share one "unknown"
    // bucket rather than bypassing the limiter entirely.
    private static void AddPerIpFixedWindowLimiter(
        RateLimiterOptions o, string policyName, int permitLimit, TimeSpan window, int ipv6Prefix)
    {
        o.AddPolicy(policyName, httpContext =>
        {
            string key = httpContext.GetRateLimitPartitionIp(ipv6Prefix) ?? "unknown";
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
