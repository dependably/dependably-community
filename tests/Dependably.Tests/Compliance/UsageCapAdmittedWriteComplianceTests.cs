using System.Reflection;
using Dependably.Api;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Usage;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins the exact set of protocol actions carrying <see cref="UsageCapAdmittedWriteAttribute"/>.
/// The marker lets a POST/PUT/PATCH through the usage-cap gate in
/// <c>TenantStatusEnforcementMiddleware</c>, so a marker on an action that can ingest an artefact
/// silently lifts the cap for it — an addition no refusal test notices, because every refusal test
/// names the actions it expects refused. The set is closed: admitting another action means
/// adding it here, where a reviewer sees the widening.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class UsageCapAdmittedWriteComplianceTests
{
    private static readonly Assembly CoreAssembly = typeof(NpmController).Assembly;

    private static readonly HashSet<string> Expected =
    [
        $"{nameof(NpmController)}.{nameof(NpmController.UnpublishRevPut)}",
        $"{nameof(NpmController)}.{nameof(NpmController.UnpublishRevPutScoped)}",
    ];

    [Fact]
    public void Only_the_npm_unpublish_prune_actions_are_admitted_under_a_usage_cap()
    {
        var marked = MarkedProtocolActions().Select(a => $"{a.Controller.Name}.{a.Action.Name}").ToHashSet();

        var unexpected = marked.Except(Expected).OrderBy(n => n, StringComparer.Ordinal).ToList();
        var missing = Expected.Except(marked).OrderBy(n => n, StringComparer.Ordinal).ToList();

        Assert.True(
            unexpected.Count == 0 && missing.Count == 0,
            $"[UsageCapAdmittedWrite] set drifted. Unexpected: [{string.Join(", ", unexpected)}]; missing: [{string.Join(", ", missing)}]. "
            + "The marker admits a write at the usage cap — only an action that can never raise usage may carry it.");
    }

    [Fact]
    public void Every_marked_action_is_a_write_with_a_stated_reason()
    {
        var violations = new List<string>();
        foreach (var (controller, action) in MarkedProtocolActions())
        {
            bool isWrite = action.GetCustomAttributes<HttpPutAttribute>(inherit: true).Any()
                           || action.GetCustomAttributes<HttpPostAttribute>(inherit: true).Any()
                           || action.GetCustomAttributes<HttpPatchAttribute>(inherit: true).Any();
            if (!isWrite)
            {
                violations.Add($"{controller.Name}.{action.Name}: marked but not a PUT/POST/PATCH (the gate never refuses it)");
            }

            if (string.IsNullOrWhiteSpace(action.GetCustomAttribute<UsageCapAdmittedWriteAttribute>()!.Reason))
            {
                violations.Add($"{controller.Name}.{action.Name}: marked with an empty reason");
            }
        }

        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }

    [Fact]
    public void The_marker_is_method_only_so_it_cannot_admit_a_whole_controller()
    {
        var usage = typeof(UsageCapAdmittedWriteAttribute).GetCustomAttribute<AttributeUsageAttribute>()!;

        Assert.Equal(AttributeTargets.Method, usage.ValidOn);
        Assert.False(usage.Inherited);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void A_marker_without_a_reason_is_rejected(string reason)
    {
        Assert.Throws<ArgumentException>(() => new UsageCapAdmittedWriteAttribute(reason));
    }

    private static List<(Type Controller, MethodInfo Action)> MarkedProtocolActions()
    {
        var controllers = CoreAssembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t) && !t.IsAbstract && EdgeProtocolSurface.IsProtocol(t))
            .ToList();
        Assert.True(controllers.Count >= 9, $"only {controllers.Count} protocol controllers found — inventory is broken");

        return controllers
            .SelectMany(c => c.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                .Where(m => m.GetCustomAttribute<UsageCapAdmittedWriteAttribute>() is not null)
                .Select(m => (c, m)))
            .ToList();
    }
}
