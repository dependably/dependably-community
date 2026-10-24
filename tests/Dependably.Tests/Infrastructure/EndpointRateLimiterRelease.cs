using System.Reflection;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Disposes the endpoint-policy limiter that ASP.NET Core's (internal) <c>RateLimitingMiddleware</c>
/// builds for itself and never disposes. A partitioned limiter runs a heartbeat timer until it is
/// disposed, and its partitioner closes over the middleware, whose <c>_next</c> chain reaches the
/// <c>WebApplication</c>: left running, the runtime's timer queue keeps every stopped test host —
/// its container, in-memory stores and blobs — reachable for the rest of the run, which is how
/// the integration suite outgrew a CI runner's memory. Production runs one host per process, so
/// only a process that builds many hosts needs this.
///
/// <para>The middleware is not reachable through any public API, so this walks the request
/// pipeline the server was started with: delegates, their targets, and the ASP.NET Core and
/// compiler-generated closure objects between them. A pipeline with no rate-limiting middleware,
/// or a framework change that renames the limiter field, throws rather than leaking silently.</para>
/// </summary>
internal static class EndpointRateLimiterRelease
{
    private const int MaxVisited = 50_000;

    private static readonly Type MiddlewareType =
        typeof(RateLimiterOptions).Assembly.GetType("Microsoft.AspNetCore.RateLimiting.RateLimitingMiddleware", throwOnError: true)!;

    public static void Release(IServer server)
    {
        ArgumentNullException.ThrowIfNull(server);
        object middleware = FindMiddleware(server)
            ?? throw new InvalidOperationException(
                "No RateLimitingMiddleware found in the test host's request pipeline; its endpoint limiter would keep the host alive.");

        var field = MiddlewareType.GetField("_endpointLimiter", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException(
                "RateLimitingMiddleware no longer has an _endpointLimiter field; update EndpointRateLimiterRelease.");
        (field.GetValue(middleware) as PartitionedRateLimiter<Microsoft.AspNetCore.Http.HttpContext>)?.Dispose();
    }

    private static object? FindMiddleware(object root)
    {
        var visited = new HashSet<object>(ReferenceEqualityComparer.Instance);
        Queue<object> queue = new();
        queue.Enqueue(root);
        while (queue.Count > 0 && visited.Count < MaxVisited)
        {
            object current = queue.Dequeue();
            if (!visited.Add(current))
            {
                continue;
            }

            if (current.GetType() == MiddlewareType)
            {
                return current;
            }

            if (current is Delegate del)
            {
                foreach (var d in del.GetInvocationList())
                {
                    if (d.Target is not null)
                    {
                        queue.Enqueue(d.Target);
                    }
                }
                continue;
            }

            if (current is object[] items)
            {
                foreach (object? item in items)
                {
                    if (item is not null && ShouldFollow(item))
                    {
                        queue.Enqueue(item);
                    }
                }
                continue;
            }

            for (var type = current.GetType(); type is not null && type != typeof(object); type = type.BaseType)
            {
                foreach (var f in type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                {
                    if (f.FieldType.IsValueType)
                    {
                        continue;
                    }

                    object? value = f.GetValue(current);
                    if (value is not null && ShouldFollow(value))
                    {
                        queue.Enqueue(value);
                    }
                }
            }
        }
        return null;
    }

    // The pipeline is a chain of delegates, middleware instances and closures. Anything else —
    // the service provider, repositories, caches — is the host's state, not its pipeline.
    private static bool ShouldFollow(object value)
    {
        if (value is Delegate or object[])
        {
            return true;
        }

        var type = value.GetType();
        string name = type.FullName ?? type.Name;
        return name.StartsWith("Microsoft.AspNetCore.", StringComparison.Ordinal)
            || name.Contains('<', StringComparison.Ordinal)
            || (name.StartsWith("Dependably.", StringComparison.Ordinal) && name.EndsWith("Middleware", StringComparison.Ordinal));
    }
}
