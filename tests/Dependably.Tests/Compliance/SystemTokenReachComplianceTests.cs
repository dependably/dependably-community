using System.Reflection;
using Dependably.Api;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins the reach of the <c>SystemToken</c> authentication scheme to a fixed eight-action
/// allowlist on <see cref="SystemController"/> — the tenant-lifecycle and usage-cap actions a
/// provisioning script or control plane needs, and nothing else. Every other action, on every controller, stays off the
/// scheme, and the scheme may never appear on a class-level <c>[Authorize]</c> — a class-level
/// grant would apply to every action on that controller (including ones added later), which is
/// exactly the reach this gate exists to close.
///
/// <para>
/// Scans every controller type in every application assembly (<see cref="SourceRoots.All"/>
/// resolves the source roots; this test loads the matching assembly for each so a new
/// <c>src/Dependably*</c> project is covered automatically, the same fail-closed property
/// <see cref="SourceRoots"/> gives the file-scanning gates) — not just
/// <see cref="SystemController"/> — for both class-level and action-level
/// <c>[Authorize(AuthenticationSchemes = "…")]</c> attributes naming
/// <see cref="SystemTokenDefaults.Scheme"/>. Reflection, not a source regex, so the check covers
/// the attribute ASP.NET actually evaluates rather than a string that merely looks like one.
/// Widening the reach (adding the scheme to a ninth action, to another controller's action, or
/// to any class-level <c>[Authorize]</c>) fails this test until <see cref="AllowlistedActions"/>
/// is edited too, which is the point: the allowlist can only grow with a visible, reviewable diff.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class SystemTokenReachComplianceTests
{
    private readonly ITestOutputHelper _output;

    public SystemTokenReachComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// The exact set of (controller, action) pairs a <c>dpsys_…</c> token may authenticate.
    /// Confirmed-decision fixed set — tenant lifecycle and usage caps only, no capability picker. Keyed by
    /// controller type, not action name alone, so an unrelated controller's action that happens
    /// to share one of these names can never ride along on the allowlist.
    /// </summary>
    private static readonly (Type Controller, string Action)[] AllowlistedActions =
    [
        (typeof(SystemController), nameof(SystemController.ListTenants)),
        (typeof(SystemController), nameof(SystemController.CreateTenant)),
        (typeof(SystemController), nameof(SystemController.SoftDeleteTenant)),
        (typeof(SystemController), nameof(SystemController.SetTenantStorageQuota)),
        (typeof(SystemController), nameof(SystemController.SetTenantStatus)),
        (typeof(SystemController), nameof(SystemController.RestoreTenant)),
        (typeof(SystemController), nameof(SystemController.GetTenantUsageLimits)),
        (typeof(SystemController), nameof(SystemController.SetTenantUsageLimits)),
    ];

    [Fact]
    public void SystemTokenSchemeReachesExactlyTheAllowlistedActions()
    {
        var controllers = AllControllers().ToList();
        // A reflection/assembly-load regression that emptied this list would make the gate
        // green-but-blind. Pin a floor well below the real count.
        Assert.True(controllers.Count >= 20, $"only {controllers.Count} controllers found");

        var actual = ActionsCarryingSystemTokenScheme(controllers)
            .OrderBy(p => p.Controller.FullName, StringComparer.Ordinal)
            .ThenBy(p => p.Action, StringComparer.Ordinal)
            .ToList();
        var expected = AllowlistedActions
            .OrderBy(p => p.Controller.FullName, StringComparer.Ordinal)
            .ThenBy(p => p.Action, StringComparer.Ordinal)
            .ToList();

        var missing = expected.Except(actual).ToList();
        var extra = actual.Except(expected).ToList();

        foreach (var (controller, action) in missing)
        {
            _output.WriteLine($"Allowlisted action '{controller.Name}.{action}' no longer carries the SystemToken scheme.");
        }

        foreach (var (controller, action) in extra)
        {
            _output.WriteLine(
                $"Action '{controller.Name}.{action}' carries the SystemToken scheme but is not in " +
                "AllowlistedActions — widening the token's reach needs a visible edit to this test.");
        }

        Assert.True(missing.Count == 0 && extra.Count == 0,
            "SystemToken scheme reach drifted from the allowlist. See test output.");
    }

    /// <summary>
    /// Adversarial twin: every non-allowlisted action, on every controller in every application
    /// assembly, must NOT carry the scheme — proven directly (not merely inferred from the
    /// equality assertion above) so a future refactor that renames an allowlisted action and
    /// coincidentally frees up its old name for an unrelated widened action cannot pass this gate
    /// by accident.
    /// </summary>
    [Fact]
    public void EveryOtherActionOnEveryControllerStaysOffTheScheme()
    {
        var allowlisted = new HashSet<(Type, string)>(AllowlistedActions);
        var controllers = AllControllers().ToList();

        var violations = controllers
            .SelectMany(c => ActionsOf(c).Select(m => (Controller: c, Action: m.Name, Method: m)))
            .Where(x => !allowlisted.Contains((x.Controller, x.Action)) && CarriesSystemTokenScheme(x.Method))
            .Select(x => $"{x.Controller.Name}.{x.Action}")
            .ToList();

        Assert.True(violations.Count == 0,
            "Non-allowlisted action(s) carry the SystemToken scheme: " + string.Join(", ", violations));
    }

    /// <summary>
    /// The scheme must never sit on a class-level <c>[Authorize]</c> — that would authenticate
    /// every action on the controller, present and future, defeating the fixed eight-action
    /// allowlist by construction rather than by an editable list. Checked separately from the
    /// action-level scans above, which only ever look at attributes declared on the method itself.
    /// </summary>
    [Fact]
    public void SystemTokenSchemeNeverAppearsOnAClassLevelAuthorize()
    {
        var violations = AllControllers()
            .Where(c => c.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any(CarriesSystemTokenScheme))
            .Select(c => c.Name)
            .ToList();

        Assert.True(violations.Count == 0,
            "Controller(s) carry the SystemToken scheme on a class-level [Authorize]: " + string.Join(", ", violations));
    }

    private static IEnumerable<(Type Controller, string Action)> ActionsCarryingSystemTokenScheme(
        IEnumerable<Type> controllers) =>
        controllers.SelectMany(c => ActionsOf(c)
            .Where(CarriesSystemTokenScheme)
            .Select(m => (Controller: c, Action: m.Name)));

    private static bool CarriesSystemTokenScheme(MethodInfo action) =>
        action.GetCustomAttributes<AuthorizeAttribute>(inherit: false).Any(CarriesSystemTokenScheme);

    private static bool CarriesSystemTokenScheme(AuthorizeAttribute attr) =>
        attr.AuthenticationSchemes is { } schemes
            && schemes.Split(',').Select(s => s.Trim())
                .Contains(SystemTokenDefaults.Scheme, StringComparer.Ordinal);

    private static IEnumerable<MethodInfo> ActionsOf(Type controller) =>
        controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.DeclaringType is not null
                        && m.DeclaringType != typeof(object)
                        && m.DeclaringType != typeof(ControllerBase)
                        && !m.IsSpecialName
                        && m.GetCustomAttribute<NonActionAttribute>() is null)
            .OrderBy(m => m.Name, StringComparer.Ordinal);

    /// <summary>
    /// Every non-abstract <c>*Controller</c> type assignable to <see cref="ControllerBase"/>
    /// across every application assembly (one per <see cref="SourceRoots.All"/> entry). Loading
    /// by assembly simple name — rather than reusing a single <c>typeof(...).Assembly</c> anchor
    /// per project — means a new <c>src/Dependably*</c> project with its own controllers is
    /// covered the moment it lands, with no edit here.
    /// </summary>
    private static IEnumerable<Type> AllControllers() =>
        ApplicationAssemblies()
            .SelectMany(a => a.GetTypes())
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t)
                        && !t.IsAbstract
                        && t.Name.EndsWith("Controller", StringComparison.Ordinal))
            .OrderBy(t => t.FullName, StringComparer.Ordinal);

    private static IEnumerable<Assembly> ApplicationAssemblies() =>
        SourceRoots.All()
            .Select(root => Path.GetFileName(root))
            .Distinct(StringComparer.Ordinal)
            .Select(name => Assembly.Load(new AssemblyName(name)));
}
