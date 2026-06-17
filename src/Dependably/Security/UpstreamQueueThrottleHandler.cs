using System.Net;
using Dependably.Infrastructure.Observability;

namespace Dependably.Security;

/// <summary>
/// A <see cref="DelegatingHandler"/> that enforces a hard cap on the number of requests
/// simultaneously waiting in the upstream connection-pool queue.
///
/// <see cref="System.Net.Http.SocketsHttpHandler"/> limits <em>open</em> connections per
/// server but allows an unbounded number of tasks to queue behind those connections. Under
/// a cache-miss burst to one upstream, many tasks accumulate holding async-state machines
/// and interim buffers until the client timeout expires — a memory pile-up followed by a
/// timeout cascade. This handler bounds that queue by acquiring a semaphore slot before
/// forwarding the request; when the semaphore is exhausted the request is rejected
/// immediately with <see cref="HttpStatusCode.ServiceUnavailable"/> rather than being
/// enqueued indefinitely.
///
/// The semaphore is shared across every HTTP client that installs this handler so the cap
/// applies to the total concurrent upstream load per process, not per-client.
/// </summary>
public sealed class UpstreamQueueThrottleHandler : DelegatingHandler
{
    private readonly SemaphoreSlim _semaphore;
    private readonly TimeSpan _acquireTimeout;
    private readonly ILogger<UpstreamQueueThrottleHandler> _logger;

    /// <summary>
    /// Initialises the handler with a shared semaphore and acquire timeout.
    /// </summary>
    /// <param name="semaphore">
    /// Process-scoped semaphore that limits concurrently queued upstream requests.
    /// Callers share the same instance across all upstream HTTP clients.
    /// </param>
    /// <param name="acquireTimeout">
    /// Maximum time to wait for a slot before returning 503. Defaults to 500 ms when null.
    /// </param>
    /// <param name="logger">Logger for shed events.</param>
    public UpstreamQueueThrottleHandler(
        SemaphoreSlim semaphore,
        TimeSpan? acquireTimeout,
        ILogger<UpstreamQueueThrottleHandler> logger)
    {
        _semaphore = semaphore;
        _acquireTimeout = acquireTimeout ?? TimeSpan.FromMilliseconds(500);
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        bool acquired = await _semaphore.WaitAsync(_acquireTimeout, cancellationToken);
        if (!acquired)
        {
            DependablyMeter.UpstreamQueueSheds.Add(1);
            _logger.LogWarning(
                "Upstream queue full: request to {Host} shed after {TimeoutMs} ms acquire wait",
                request.RequestUri?.Host,
                (int)_acquireTimeout.TotalMilliseconds);
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                ReasonPhrase = "Upstream queue depth exceeded"
            };
        }

        try
        {
            return await base.SendAsync(request, cancellationToken);
        }
        finally
        {
            _semaphore.Release();
        }
    }
}
