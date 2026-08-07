using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The terminal handler is the last line between an unexpected exception and the caller, so
/// these tests assert both halves of its contract: the caller gets a usable, localized problem
/// document with a correlation id, and the caller gets <em>nothing else</em> — no exception
/// type, message, stack frame, or inner-exception text.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerminalExceptionHandlerTests
{
    // A message shaped like the things that actually leak: a connection string with a
    // credential, an absolute server path, and an internal type name.
    private const string SecretMessage =
        "Host=db01.internal;Password=hunter2 while reading /srv/dependably/data/registry.db";

    private const string InnerSecretMessage = "SqliteException: no such column secret_column";

    private static DependablyProbeException BuildRealisticException()
    {
        try
        {
            try
            {
                throw new InvalidOperationException(InnerSecretMessage);
            }
            catch (InvalidOperationException inner)
            {
                throw new DependablyProbeException(SecretMessage, inner);
            }
        }
        catch (DependablyProbeException caught)
        {
            // Thrown and caught for real so the exception carries a populated StackTrace,
            // which is what a naked framework 500 would otherwise render into the body.
            return caught;
        }
    }

    private static (TerminalExceptionHandler Handler, CapturingLoggerProvider Logs) BuildHandler()
    {
        var services = new ServiceCollection();
        var logs = new CapturingLoggerProvider();
        services.AddLogging(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        var provider = services.BuildServiceProvider();

        return (new TerminalExceptionHandler(
                provider.GetRequiredService<IStringLocalizer<SharedResource>>(),
                provider.GetRequiredService<ILogger<TerminalExceptionHandler>>()),
            logs);
    }

    private static DefaultHttpContext NewContext(string method = "GET", string path = "/api/v1/orgs")
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static void SetRequestCulture(HttpContext ctx, string culture)
        => ctx.Features.Set<IRequestCultureFeature>(
            new RequestCultureFeature(
                new RequestCulture(new CultureInfo(culture)),
                provider: null));

    private static async Task<string> ReadBodyAsync(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        using var reader = new StreamReader(ctx.Response.Body, leaveOpen: true);
        return await reader.ReadToEndAsync();
    }

    [Fact]
    public async Task UnmappedException_Returns500LocalizedProblemJson_WithCorrelationId()
    {
        var (handler, _) = BuildHandler();
        var ctx = NewContext();
        SetRequestCulture(ctx, "en");
        using var activity = new Activity("test-request").Start();

        bool handled = await handler.TryHandleAsync(ctx, BuildRealisticException(), CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(StatusCodes.Status500InternalServerError, ctx.Response.StatusCode);
        Assert.Equal("application/problem+json", ctx.Response.ContentType);
        Assert.Equal("nosniff", ctx.Response.Headers.XContentTypeOptions.ToString());

        var body = JsonDocument.Parse(await ReadBodyAsync(ctx)).RootElement;
        Assert.Equal("about:blank", body.GetProperty("type").GetString());
        Assert.Equal(500, body.GetProperty("status").GetInt32());
        Assert.Equal("Internal Server Error", body.GetProperty("title").GetString());
        Assert.Equal(
            "The request could not be completed because of an unexpected server error. " +
            "The failure has been logged; quote the correlation id when reporting it.",
            body.GetProperty("detail").GetString());

        // The correlation id is the ambient W3C trace id — the same value the observability
        // stack stamps on the logs and spans of this request, not a competing identifier.
        Assert.Equal(activity.TraceId.ToString(), body.GetProperty("correlationId").GetString());
    }

    [Fact]
    public async Task Body_LeaksNoExceptionDetail()
    {
        var (handler, _) = BuildHandler();
        var ctx = NewContext();
        var exception = BuildRealisticException();

        await handler.TryHandleAsync(ctx, exception, CancellationToken.None);

        string body = await ReadBodyAsync(ctx);
        Assert.DoesNotContain(SecretMessage, body, StringComparison.Ordinal);
        Assert.DoesNotContain(InnerSecretMessage, body, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", body, StringComparison.Ordinal);
        Assert.DoesNotContain("/srv/dependably", body, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(DependablyProbeException), body, StringComparison.Ordinal);
        Assert.DoesNotContain("InvalidOperationException", body, StringComparison.Ordinal);
        Assert.DoesNotContain("StackTrace", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(nameof(TerminalExceptionHandlerTests), body, StringComparison.Ordinal);

        // The frames themselves: every stack line names a method of this test class.
        Assert.NotNull(exception.StackTrace);
        Assert.DoesNotContain("at Dependably.Tests", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LogsExactlyOnce_AtError_WithExceptionTypeAndCorrelationId()
    {
        var (handler, logs) = BuildHandler();
        var ctx = NewContext("PUT", "/npm/left-pad");
        var exception = BuildRealisticException();
        using var activity = new Activity("test-request").Start();

        await handler.TryHandleAsync(ctx, exception, CancellationToken.None);

        var record = Assert.Single(logs.Records);
        Assert.Equal(LogLevel.Error, record.Level);
        Assert.Same(exception, record.Exception);
        Assert.Contains(nameof(DependablyProbeException), record.Message, StringComparison.Ordinal);
        Assert.Contains(activity.TraceId.ToString(), record.Message, StringComparison.Ordinal);
        Assert.Contains("/npm/left-pad", record.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Log_OmitsTheQueryString()
    {
        // A query string routinely carries a token (?api_key=…); the log line names the path only.
        var (handler, logs) = BuildHandler();
        var ctx = NewContext("GET", "/simple/requests/");
        ctx.Request.QueryString = new QueryString("?token=super-secret-token");

        await handler.TryHandleAsync(ctx, BuildRealisticException(), CancellationToken.None);

        var record = Assert.Single(logs.Records);
        Assert.DoesNotContain("super-secret-token", record.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Detail_IsLocalizedToTheNegotiatedRequestCulture()
    {
        // The handler runs outside UseRequestLocalization, so it reads the culture back off
        // IRequestCultureFeature rather than trusting the ambient CultureInfo.
        var (handler, _) = BuildHandler();
        var ctx = NewContext();
        SetRequestCulture(ctx, "fr");

        await handler.TryHandleAsync(ctx, BuildRealisticException(), CancellationToken.None);

        var body = JsonDocument.Parse(await ReadBodyAsync(ctx)).RootElement;
        Assert.Equal("Erreur interne du serveur", body.GetProperty("title").GetString());
        Assert.StartsWith(
            "La requête n'a pas pu aboutir",
            body.GetProperty("detail").GetString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Localization_DoesNotLeakTheRequestCultureIntoTheAmbientContext()
    {
        var (handler, _) = BuildHandler();
        var ctx = NewContext();
        SetRequestCulture(ctx, "fr");
        var before = CultureInfo.CurrentUICulture;

        await handler.TryHandleAsync(ctx, BuildRealisticException(), CancellationToken.None);

        Assert.Equal(before.Name, CultureInfo.CurrentUICulture.Name);
    }

    [Fact]
    public async Task WithoutAnAmbientActivity_CorrelationIdFallsBackToTraceIdentifier()
    {
        var (handler, _) = BuildHandler();
        var ctx = NewContext();
        ctx.TraceIdentifier = "0HN7ABCDEF:00000003";
        Activity.Current = null;

        await handler.TryHandleAsync(ctx, BuildRealisticException(), CancellationToken.None);

        var body = JsonDocument.Parse(await ReadBodyAsync(ctx)).RootElement;
        Assert.Equal("0HN7ABCDEF:00000003", body.GetProperty("correlationId").GetString());
    }

    [Fact]
    public async Task ResponseAlreadyStarted_ReportsUnhandled_ButStillLogs()
    {
        // Bytes are on the wire: appending a problem document would corrupt the body, so the
        // handler declines and lets the host tear the connection down — after logging, because
        // the operator still needs the record.
        var (handler, logs) = BuildHandler();
        var ctx = NewContext();
        ctx.Features.Set<IHttpResponseFeature>(new StartedResponseFeature { StatusCode = StatusCodes.Status200OK });

        bool handled = await handler.TryHandleAsync(ctx, BuildRealisticException(), CancellationToken.None);

        Assert.False(handled);
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.Single(logs.Records);
    }

    private sealed class DependablyProbeException : Exception
    {
        public DependablyProbeException(string message, Exception inner) : base(message, inner) { }
    }

    private sealed class StartedResponseFeature : IHttpResponseFeature
    {
        public int StatusCode { get; set; } = 200;
        public string? ReasonPhrase { get; set; }
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
        public Stream Body { get; set; } = new MemoryStream();
        public bool HasStarted => true;
        public void OnStarting(Func<object, Task> callback, object state) { }
        public void OnCompleted(Func<object, Task> callback, object state) { }
    }

    private sealed record LogRecord(string Category, LogLevel Level, string Message, Exception? Exception);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<LogRecord> _all = [];

        /// <summary>
        /// Records written by the handler itself. Filtered by category so the localizer's own
        /// Debug chatter cannot mask a second write from the handler.
        /// </summary>
        public IReadOnlyList<LogRecord> Records => _all
            .Where(r => r.Category == typeof(TerminalExceptionHandler).FullName)
            .ToList();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(_all, categoryName);

        public void Dispose() { }

        private sealed class CapturingLogger : ILogger
        {
            private readonly List<LogRecord> _records;
            private readonly string _category;

            public CapturingLogger(List<LogRecord> records, string category)
            {
                _records = records;
                _category = category;
            }

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => _records.Add(new LogRecord(_category, logLevel, formatter(state, exception), exception));
        }
    }
}
