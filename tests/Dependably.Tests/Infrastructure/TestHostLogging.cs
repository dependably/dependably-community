using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Core;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Binds a test host's Serilog pipeline to a capture sink the host itself owns.
/// </summary>
internal static class TestHostLogging
{
    /// <summary>
    /// Registers <paramref name="sink"/> as an <c>ILogEventSink</c> (the type Serilog's
    /// <c>ReadFrom.Services</c> resolver looks up) and re-binds the host to a logger instance it
    /// owns, so events this host emits reach this sink and no other.
    ///
    /// <para>The production pipeline calls <c>UseSerilog</c> with the default
    /// <c>preserveStaticLogger: false</c>, which registers a <c>SerilogLoggerFactory</c> holding a
    /// <c>null</c> logger — every <c>ILogger&lt;T&gt;</c> write then resolves the ambient static
    /// <c>Log.Logger</c> at write time. That is correct for a process running one host. A test
    /// process runs many: each <see cref="Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory{T}"/>
    /// overwrites the static when it builds and resets it to a no-op when it disposes
    /// (<c>Log.CloseAndFlush</c>). A host's startup log therefore lands in whichever host most
    /// recently touched the static, and a sink registered here would miss it — or capture another
    /// host's events.</para>
    ///
    /// <para>Re-binding with <c>preserveStaticLogger: true</c> registers the concrete logger, so
    /// this host's writes are routed through it regardless of what a concurrent host does to the
    /// static. Registration order matters: this must run after the production
    /// <c>ConfigureBuilder</c> so its <c>ILoggerFactory</c> registration is the one resolved.</para>
    /// </summary>
    internal static void UseCapturingSink(WebApplicationBuilder builder, ILogEventSink sink)
    {
        builder.Services.AddSingleton(sink);
        builder.Host.UseSerilog(
            (ctx, services, cfg) => cfg
                .ReadFrom.Configuration(ctx.Configuration)
                .ReadFrom.Services(services)
                .Enrich.FromLogContext(),
            preserveStaticLogger: true);
    }
}
