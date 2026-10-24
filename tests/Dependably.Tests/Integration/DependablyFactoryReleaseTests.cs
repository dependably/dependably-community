using System.Runtime.CompilerServices;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// A disposed test host must become unreachable. The integration suite builds hundreds of hosts in
/// one process; a timer that outlives its host (an unreleased rate limiter heartbeat, an
/// HttpClient handler expiry) keeps each one — container, in-memory database and blobs — alive,
/// and the suite grows until the runner runs out of memory.
/// </summary>
[Trait("Category", "Integration")]
public sealed class DependablyFactoryReleaseTests
{
    [Fact]
    public async Task DisposedHost_IsCollectable()
    {
        var services = await StartUseAndDisposeHostAsync();

        for (int attempt = 0; attempt < 50 && services.IsAlive; attempt++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            if (services.IsAlive)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), TimeProvider.System);
            }
        }

        Assert.False(services.IsAlive, "A disposed DependablyFactory host is still reachable; something rooted outside the host (typically a timer) still references it.");
    }

    // Not inlined, so no local in the caller's frame keeps the host reachable.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference> StartUseAndDisposeHostAsync()
    {
        var factory = new DependablyFactory();
        await factory.InitializeAsync();
        using (var client = factory.CreateClient())
        {
            var resp = await client.GetAsync("/health");
            Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
        }

        var services = new WeakReference(factory.Services);
        await factory.DisposeAsync();
        return services;
    }
}
