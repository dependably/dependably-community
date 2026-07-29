using System.Net;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Dependably.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Exercises the terminal handler where it actually lives: outermost in a pipeline whose inner
/// frames are the six typed exception middlewares, in the order both composition roots register
/// them. The point of the arrangement is the adversarial half — a terminal handler that also
/// swallowed or reshaped the six typed responses would be a regression, so each typed exception
/// is asserted to come back exactly as it does today, and a successful request is asserted to
/// pass through untouched.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerminalExceptionHandlerPipelineTests : IAsyncLifetime
{
    private WebApplication _app = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.AddDependablyLocalization();
        builder.AddDependablyTerminalExceptionHandler();

        _app = builder.Build();

        // Same order as Program.ConfigureApp in both roots: terminal handler outermost, the
        // typed translators inside it, request localization inside those.
        _app.UseDependablyTerminalExceptionHandler();
        _app.UseMiddleware<AirGappedExceptionMiddleware>();
        _app.UseMiddleware<StagingDiskFullExceptionMiddleware>();
        _app.UseMiddleware<TenantStorageQuotaExceededExceptionMiddleware>();
        _app.UseMiddleware<UpstreamFetchFailedExceptionMiddleware>();
        _app.UseMiddleware<SsrfBlockedExceptionMiddleware>();
        _app.UseMiddleware<TenantNotReadyExceptionMiddleware>();
        _app.UseRequestLocalization();
        _app.Run(Throw);

        await _app.StartAsync();
        _client = _app.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
    }

    // Terminal endpoint: the path selects which exception escapes the handler.
    private static Task Throw(HttpContext ctx) => ctx.Request.Path.Value switch
    {
        "/ok" => ctx.Response.WriteAsync("served"),
        "/air-gapped" => throw new AirGappedException("npm/left-pad"),
        "/disk-full" => throw new StagingDiskFullException(1024, 4096),
        "/quota" => throw new TenantStorageQuotaExceededException("org-1", 999),
        "/upstream" => throw new UpstreamFetchFailedException { Url = "https://u/x", StatusCode = 503, Transient = true },
        "/ssrf" => throw new SsrfBlockedException("http://169.254.169.254/latest"),
        "/tenant" => throw new TenantNotReadyException("t-1", TenantNotReadyReason.NotFound, "tenant not found"),
        _ => throw new UnmappedProbeException(),
    };

    [Fact]
    public async Task UnmappedException_Returns500ProblemJson_WithCorrelationId_AndNoLeakage()
    {
        var response = await _client.GetAsync("/boom");
        string body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());

        var problem = JsonDocument.Parse(body).RootElement;
        Assert.Equal(500, problem.GetProperty("status").GetInt32());
        Assert.Equal("Internal Server Error", problem.GetProperty("title").GetString());
        Assert.False(string.IsNullOrWhiteSpace(problem.GetProperty("correlationId").GetString()));

        // The security half: nothing about the fault crosses the wire.
        Assert.DoesNotContain(UnmappedProbeException.Secret, body, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(UnmappedProbeException), body, StringComparison.Ordinal);
        Assert.DoesNotContain("Dependably.Tests", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FrenchClient_GetsTheFrenchProblemDocument()
    {
        // Proves the handler still resolves the negotiated culture even though it is registered
        // outside UseRequestLocalization.
        using var request = new HttpRequestMessage(HttpMethod.Get, "/boom");
        request.Headers.Add("Accept-Language", "fr");

        var response = await _client.SendAsync(request);

        var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("Erreur interne du serveur", problem.GetProperty("title").GetString());
    }

    [Theory]
    [InlineData("/air-gapped", HttpStatusCode.ServiceUnavailable, "Cache disabled in air-gapped mode")]
    [InlineData("/disk-full", HttpStatusCode.InsufficientStorage, null)]
    [InlineData("/quota", HttpStatusCode.RequestEntityTooLarge, null)]
    [InlineData("/upstream", HttpStatusCode.ServiceUnavailable, null)]
    [InlineData("/ssrf", HttpStatusCode.BadGateway, null)]
    [InlineData("/tenant", HttpStatusCode.NotFound, "Tenant not found")]
    public async Task TypedExceptions_KeepTheirOwnResponses_Unchanged(
        string path, HttpStatusCode expectedStatus, string? expectedTitle)
    {
        var response = await _client.GetAsync(path);
        var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.Equal((int)expectedStatus, problem.GetProperty("status").GetInt32());
        if (expectedTitle is not null)
        {
            Assert.Equal(expectedTitle, problem.GetProperty("title").GetString());
        }

        // The terminal handler's marker is absent: the typed middleware answered, not it.
        Assert.False(problem.TryGetProperty("correlationId", out _));
    }

    [Fact]
    public async Task SuccessfulRequest_IsUnaffected()
    {
        var response = await _client.GetAsync("/ok");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("served", await response.Content.ReadAsStringAsync());
        Assert.False(response.Headers.Contains("X-Content-Type-Options"));
    }

    private sealed class UnmappedProbeException : Exception
    {
        public const string Secret = "connection string Password=hunter2 at /srv/dependably/data";

        public UnmappedProbeException() : base(Secret) { }
    }
}
