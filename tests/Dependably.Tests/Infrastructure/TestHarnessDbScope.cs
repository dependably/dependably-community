using Dependably.Infrastructure.RowLevelSecurity;
using Microsoft.AspNetCore.Http;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Marks database access made by test code itself — seeding and asserting through
/// <see cref="DependablyFactory.Services"/> — as distinct from the host's own background work.
/// The flag is async-local and set on the test's flow when it reaches into the host's services;
/// the host is started with it cleared, so hosted services, channel consumers and timers never
/// inherit it, and requests run through <c>TestServer</c> without the caller's context.
/// </summary>
public static class TestHarnessDbScope
{
    private static readonly AsyncLocal<bool> Active = new();

    public static bool IsActive => Active.Value;

    public static void Enter() => Active.Value = true;

    public static void Clear() => Active.Value = false;

    /// <summary>
    /// Runs host code — a background pass a test drives directly — without the test-harness flag,
    /// so it binds exactly as it would in production: a pass that forgets to declare its
    /// <c>DbScope</c> raises DR001 here too instead of running as the owner. The flag is cleared
    /// only inside this call; the caller's flow keeps it.
    /// </summary>
    public static async Task AsHostAsync(Func<Task> hostWork)
    {
        ArgumentNullException.ThrowIfNull(hostWork);
        Clear();
        await hostWork();
    }

    /// <inheritdoc cref="AsHostAsync(Func{Task})"/>
    public static async Task<T> AsHostAsync<T>(Func<Task<T>> hostWork)
    {
        ArgumentNullException.ThrowIfNull(hostWork);
        Clear();
        return await hostWork();
    }
}

/// <summary>
/// The test host's ambient tenant: the production <see cref="HttpContextAmbientTenantScope"/>
/// for request and background work alike, except that test-harness access outside any request
/// runs as the owner. Background work therefore meets the row-level security backstop exactly as
/// it would in production.
/// </summary>
public sealed class HarnessAmbientTenantScope(IHttpContextAccessor accessor) : IAmbientTenantScope
{
    private readonly HttpContextAmbientTenantScope _production = new(accessor);

    public AmbientTenant Current =>
        accessor.HttpContext is null && TestHarnessDbScope.IsActive
            ? new AmbientTenant(AmbientTenantKind.Apex, null)
            : _production.Current;
}

/// <summary>
/// Marks every test method's own flow as test-harness database access, so seeding and assertions
/// made through repositories the test resolved earlier (in a constructor or fixture) are not read
/// as the host's background work. The host itself still starts with the flag cleared.
/// </summary>
[AttributeUsage(AttributeTargets.Assembly)]
public sealed class TestHarnessDbAccessAttribute : Xunit.Sdk.BeforeAfterTestAttribute
{
    public override void Before(System.Reflection.MethodInfo methodUnderTest) => TestHarnessDbScope.Enter();

    public override void After(System.Reflection.MethodInfo methodUnderTest) => TestHarnessDbScope.Clear();
}
