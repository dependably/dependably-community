namespace Dependably.Infrastructure.Startup;

// Terminal exception handling. Split out of InfrastructureStartupExtensions.cs (partial class)
// to keep the class's dependency coupling spread across files below the S1200 threshold.
internal static partial class InfrastructureStartupExtensions
{
    /// <summary>
    /// Registers the terminal <see cref="TerminalExceptionHandler"/>. Both composition roots
    /// (the full server and the edge) call this: an unexpected exception must produce the same
    /// problem+json contract on either image.
    /// </summary>
    internal static void AddDependablyTerminalExceptionHandler(this WebApplicationBuilder builder)
    {
        builder.Services.AddExceptionHandler<TerminalExceptionHandler>();

        // ExceptionHandlerMiddleware requires either an exception-handling path or a
        // ProblemDetails service before it will build. TerminalExceptionHandler writes the
        // response itself and returns handled, so this service is only a structural
        // requirement — its fallback writer never produces a body.
        builder.Services.AddProblemDetails();
    }

    /// <summary>
    /// Installs the terminal exception handler as the outermost middleware, so it catches what
    /// the typed exception middlewares registered further in do not claim. Registering it first
    /// is what makes it terminal: a typed middleware handles its own exception before the frame
    /// ever unwinds this far, and its response passes through untouched.
    /// </summary>
    internal static void UseDependablyTerminalExceptionHandler(this IApplicationBuilder app)
        => app.UseExceptionHandler();
}
