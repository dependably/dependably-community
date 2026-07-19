using Dependably.Infrastructure.SystemEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;

namespace Dependably.Tests.Unit.Infrastructure.SystemEvents;

/// <summary>
/// Renders <see cref="SystemEventRecord"/> through the real resource-backed localizer — not a
/// stub — so the resx entries and the {0}/{1} placeholder wiring are exercised. Also pins the
/// structural half of the operator-Slack isolation invariant: the record's own shape has no field
/// a package name, vulnerability detail, or member email could travel through.
/// </summary>
public sealed class SystemEventMessagesTests
{
    private static IStringLocalizer<Dependably.SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider()
            .GetRequiredService<IStringLocalizer<Dependably.SharedResource>>();
    }

    [Fact]
    public void TenantCreated_RendersSlugAndActor()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("tenant.created", "acme", null, "ops@example.com"), RealLocalizer());
        Assert.Equal("Dependably [system]: tenant 'acme' created by ops@example.com", msg);
    }

    [Fact]
    public void TenantDeleted_RendersSlugAndActor()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("tenant.deleted", "acme", null, "ops@example.com"), RealLocalizer());
        Assert.Equal("Dependably [system]: tenant 'acme' deleted by ops@example.com", msg);
    }

    [Fact]
    public void TenantRestored_RendersSlugAndActor()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("tenant.restored", "acme", null, "ops@example.com"), RealLocalizer());
        Assert.Equal("Dependably [system]: tenant 'acme' restored by ops@example.com", msg);
    }

    [Fact]
    public void TenantStatusChanged_RendersSlugAndActor()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("tenant.status_changed", "acme", null, "ops@example.com"), RealLocalizer());
        Assert.Equal("Dependably [system]: tenant 'acme' status changed by ops@example.com", msg);
    }

    [Fact]
    public void TenantHardDeleted_NoActor_RendersWithoutActorClause()
    {
        // Raised by the retention sweep — Actor is always null for this action.
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("tenant.hard_deleted", "acme", null, null), RealLocalizer());
        Assert.Equal("Dependably [system]: tenant 'acme' hard-deleted (retention grace period expired)", msg);
        Assert.DoesNotContain("unknown operator", msg);
    }

    [Fact]
    public void AdminCreated_NoTenant_RendersActorOnly()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("system_admin.admin_created", null, null, "ops@example.com"), RealLocalizer());
        Assert.Equal("Dependably [system]: operator account created by ops@example.com", msg);
    }

    [Fact]
    public void AdminDeleted_NoTenant_RendersActorOnly()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("system_admin.admin_deleted", null, null, "ops@example.com"), RealLocalizer());
        Assert.Equal("Dependably [system]: operator account deleted by ops@example.com", msg);
    }

    [Fact]
    public void UnknownAction_FallsBackToGenericTemplate()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("something.unmapped", "acme", null, "ops@example.com"), RealLocalizer());
        Assert.Equal("Dependably [system]: something.unmapped", msg);
    }

    [Fact]
    public void NullActor_FallsBackToUnknownOperatorPhrase()
    {
        string msg = SystemEventMessages.Build(
            new SystemEventRecord("tenant.created", "acme", null, null), RealLocalizer());
        Assert.Equal("Dependably [system]: tenant 'acme' created by an unknown operator", msg);
    }

    // ── Structural half of the isolation invariant ──────────────────────────

    [Fact]
    public void SystemEventRecord_HasNoFieldBeyondActionTenantSlugTenantNameActor()
    {
        string[] props = typeof(SystemEventRecord).GetProperties().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "Action", "Actor", "TenantName", "TenantSlug" }, props);
    }
}
