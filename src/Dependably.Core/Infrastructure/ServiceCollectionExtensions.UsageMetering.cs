using Dependably.Infrastructure.Usage;

namespace Dependably.Infrastructure;

public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the egress metering write path: the bounded event writer and the hosted service
    /// that drains it into <c>usage_events</c>. Paired with <see cref="EgressMeteringMiddleware"/>
    /// in the full application only; the edge composition does not meter.
    /// <c>USAGE_WRITER_QUEUE_CAPACITY</c> overrides the channel capacity.
    /// </summary>
    public static IServiceCollection AddDependablyUsageMetering(this IServiceCollection services, IConfiguration config)
    {
        int capacity = int.TryParse(config["USAGE_WRITER_QUEUE_CAPACITY"], out int c) && c > 0
            ? c : UsageEventWriter.DefaultChannelCapacity;
        services.AddSingleton(sp => new UsageEventWriter(sp.GetRequiredService<TimeProvider>(), capacity));
        services.AddSingleton<UsageEventWriterHostedService>();
        services.AddHostedService(sp => sp.GetRequiredService<UsageEventWriterHostedService>());
        return services;
    }
}
