using Dependably.Infrastructure.Observability;
using Dependably.Security;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Formatting.Compact;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers Serilog structured logging, OpenTelemetry metrics + traces, and the graceful
/// shutdown orchestration.
/// </summary>
internal static class ObservabilityStartupExtensions
{
    // Serilog — structured JSON logging with sensitive field redaction.
    // Optional OTel logs bridge (Serilog.Sinks.OpenTelemetry) ships log records via
    // OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set. Air-gap deployments leave it unset
    // and keep the console sink only. See docs/observability/logs.md.
    internal static void AddDependablyLogging(this WebApplicationBuilder builder)
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
    internal static void AddDependablyOpenTelemetry(this WebApplicationBuilder builder)
    {
        string? otlpEndpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
        double sampleRatio = double.TryParse(
            builder.Configuration["OTEL_TRACES_SAMPLER_ARG"],
            out double ratio) ? ratio : 0.1;

        builder.Services.AddSingleton<TenantSpanEnricher>();

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
                  .AddMeter(DependablyMeter.MeterName)
                  // Built-in .NET runtime meter (net10): GC heap/collections/pause,
                  // thread-pool size+queue, process CPU+working-set, exceptions, lock
                  // contention. Emits the stable `dotnet.*` instruments directly, so no
                  // extra instrumentation package is needed — these are the resource-
                  // saturation signals the performance dashboard charts under load.
                  .AddMeter("System.Runtime")
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
                        string? op = OperationTagger.Map(route, method);
                        if (op is not null)
                        {
                            activity.SetTag("dependably.operation", op);
                        }
                    })
                  .AddHttpClientInstrumentation()
                  .AddSource(DependablyActivitySource.SourceName)
                  .AddProcessor<TenantSpanEnricher>()
                  .SetSampler(new ParentBasedSampler(new TraceIdRatioBasedSampler(sampleRatio)));

                if (!string.IsNullOrWhiteSpace(otlpEndpoint))
                {
                    tb.AddOtlpExporter();
                }
            });
    }

    // Graceful shutdown — configurable pre-stop delay + drain period
    internal static void AddDependablyGracefulShutdown(this WebApplicationBuilder builder)
    {
        int gracePeriod = int.TryParse(builder.Configuration["SHUTDOWN_GRACE_PERIOD"], out int gp) ? gp : 30;
        builder.Host.ConfigureHostOptions(o => o.ShutdownTimeout = TimeSpan.FromSeconds(gracePeriod));
        builder.Services.AddSingleton<ShutdownState>();
        builder.Services.AddHostedService<ShutdownOrchestrator>();
    }
}
