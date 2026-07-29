using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// SSRF footgun guard. The IHttpClientFactory core registers a transient default (unnamed)
/// HttpClient transitively for every named client, so a default client is always resolvable —
/// by direct injection or <c>CreateClient()</c>. It must carry the same connect-time
/// <see cref="SsrfConnectCallback"/> as the named clients, or a future default-client consumer
/// silently bypasses egress protection.
///
/// This exercises the production registration (<see cref="ProtocolStartupExtensions.AddDependablyHttpClients"/>)
/// with a callback that blocks every address and asserts the default client's connect is gated.
/// A regression to a bare, unguarded <c>AddHttpClient()</c> drops the callback and fails here.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DefaultHttpClientSsrfGuardTests
{
    private static bool HasInner<T>(Exception? ex) where T : Exception =>
        ex is not null && (ex is T || HasInner<T>(ex.InnerException));

    [Fact]
    public async Task DefaultClient_ConnectIsGatedBySsrfConnectCallback()
    {
        var builder = WebApplication.CreateBuilder();
        // Block every resolved address so the connect callback — if wired — rejects the dial
        // before any socket work.
        builder.Services.AddSingleton(new SsrfConnectCallback(_ => true));
        builder.AddDependablyHttpClients();

        await using var provider = builder.Services.BuildServiceProvider();
        var httpFactory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = httpFactory.CreateClient(Options.DefaultName);
        client.Timeout = TimeSpan.FromSeconds(5);

        // 192.0.2.1 is an RFC 5737 TEST-NET literal (no DNS): a guarded client rejects it at the
        // connect callback with SsrfBlockedException; an unguarded client would instead attempt a
        // real TCP connect (and never raise SsrfBlockedException).
        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => client.GetAsync("http://192.0.2.1/"));

        Assert.True(HasInner<SsrfBlockedException>(ex),
            $"Default HttpClient connect was not gated by SsrfConnectCallback; got {ex.GetType().Name}: {ex.Message}");
    }

    [Fact]
    public void DefaultClient_IsResolvable()
    {
        // Removing the default registration does not make it unresolvable (the factory core
        // re-adds it transitively); this pins that it stays available so the guard above always
        // has something to assert against.
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton(new SsrfConnectCallback(_ => false));
        builder.AddDependablyHttpClients();

        using var provider = builder.Services.BuildServiceProvider();
        var httpFactory = provider.GetRequiredService<IHttpClientFactory>();

        using var direct = provider.GetRequiredService<HttpClient>();
        using var named = httpFactory.CreateClient(Options.DefaultName);
        Assert.NotNull(direct);
        Assert.NotNull(named);
    }
}
