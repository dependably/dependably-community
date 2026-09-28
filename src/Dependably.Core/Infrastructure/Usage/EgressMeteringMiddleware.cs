using Dependably.Infrastructure.Observability;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Meters the response bytes of every endpoint marked <see cref="MeteredEgressAttribute"/>, and
/// emits exactly one usage event per metered request.
///
/// Registered outside response compression, so it counts the bytes that actually leave the
/// process, and after tenant resolution, so the event carries the resolved org. The body feature
/// is wrapped for the duration of the request and restored afterwards. The wrapper is a pure
/// pass-through (<see cref="CountingResponseBodyFeature"/>): it adds no buffer of its own, so
/// flushing, completion, and abort behave exactly as they do on an unmetered endpoint.
///
/// What is recorded, in the <c>finally</c> after the endpoint returns:
/// <list type="bullet">
/// <item>A redirect the handler declared with
/// <see cref="EgressMeteringHttpContextExtensions.RecordRedirectedEgress"/>: the object's full
/// size, <c>delivery = 'redirect'</c>, whatever the status code.</item>
/// <item>Otherwise a 2xx response that wrote at least one byte: the bytes written,
/// <c>delivery = 'streamed'</c>, under the kind's meter. A range bills the range; an aborted
/// transfer bills what was written before the abort; HEAD, 304, and every error response bill
/// nothing.</item>
/// </list>
/// A request with no resolved tenant is never metered — there is no org to bill.
/// </summary>
public sealed class EgressMeteringMiddleware
{
    private readonly RequestDelegate _next;

    public EgressMeteringMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, UsageEventWriter writer, TimeProvider time)
    {
        var metered = context.GetEndpoint()?.Metadata.GetMetadata<MeteredEgressAttribute>();
        if (metered is null)
        {
            await _next(context);
            return;
        }

        var feature = new EgressMeteringFeature(metered.Kind);
        context.Features.Set(feature);

        var originalBody = context.Features.Get<IHttpResponseBodyFeature>()!;
        var counting = new CountingResponseBodyFeature(originalBody);
        context.Features.Set<IHttpResponseBodyFeature>(counting);

        try
        {
            await _next(context);
        }
        finally
        {
            context.Features.Set(originalBody);
            var usageEvent = BuildEvent(context, metered, feature, counting.BytesWritten, time);
            if (usageEvent is not null)
            {
                await writer.EnqueueAsync(usageEvent);
            }
        }
    }

    internal static UsageEvent? BuildEvent(
        HttpContext context,
        MeteredEgressAttribute metered,
        EgressMeteringFeature feature,
        long bytesWritten,
        TimeProvider time)
    {
        if (context.Items[TenantContext.HttpItemsKey] is not TenantContext { IsTenant: true, TenantId: { } orgId })
        {
            return null;
        }

        var now = time.GetUtcNow();

        if (feature.Redirect is { } redirect)
        {
            return redirect.Bytes == 0
                ? null
                : UsageEvent.Create(
                    Guid.CreateVersion7(now),
                    orgId,
                    UsageMeters.EgressBytes,
                    UsageDelivery.Redirect,
                    redirect.Bytes,
                    metered.Ecosystem,
                    redirect.ObjectRef,
                    now);
        }

        int status = context.Response.StatusCode;
        if (status is < 200 or > 299 || bytesWritten == 0)
        {
            return null;
        }

        string meter;
        switch (feature.Kind)
        {
            case EgressKind.Artifact:
                meter = UsageMeters.EgressBytes;
                break;
            case EgressKind.Metadata:
                meter = UsageMeters.EgressMetadataBytes;
                break;
            default:
                DependablyMeter.UsageEventsUnclassified.Add(1);
                meter = UsageMeters.EgressMetadataBytes;
                break;
        }

        return UsageEvent.Create(
            Guid.CreateVersion7(now),
            orgId,
            meter,
            UsageDelivery.Streamed,
            bytesWritten,
            metered.Ecosystem,
            null,
            now);
    }
}
