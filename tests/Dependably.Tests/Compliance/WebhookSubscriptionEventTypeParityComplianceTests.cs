using Dependably.Api;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins <see cref="WebhookController.ValidEventTypes"/> — the backend's set of subscribable
/// webhook event types — against a hardcoded literal copy of the same set. The frontend's
/// sibling test, <c>web/src/lib/settings/SettingsWebhooks.parity.test.js</c>, reads
/// <c>SettingsWebhooks.svelte</c>'s source as text and parses its actual <c>ALL_EVENT_TYPES</c>
/// array out of it (not a second hardcoded copy — a hardcoded-vs-hardcoded comparison would pass
/// whether or not the component agreed with either list) and asserts that against the same
/// literal set. The two lists still cannot be compared directly against each other at test time —
/// one lives in a .NET assembly, the other is parsed out of a Svelte component's source — so each
/// side is independently pinned to this same literal set instead; a real drift between the two
/// surfaces (the <c>package.vulnerability</c> / <c>package.vuln</c> mismatch this test guards
/// against recurring) now fails whichever side's test runs against the stale value, rather than
/// silently 422ing a save at runtime.
///
/// <b>Keep this list, the vitest list, and <see cref="WebhookController.ValidEventTypes"/> in
/// lockstep by hand</b> whenever a new subscribable event type is added — there is no shared
/// source of truth across the language boundary.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class WebhookSubscriptionEventTypeParityComplianceTests
{
    // Mirrors web/src/lib/settings/SettingsWebhooks.svelte's ALL_EVENT_TYPES exactly — see that
    // file's own comment pointing back here.
    private static readonly HashSet<string> ExpectedSubscribableEventTypes = new(StringComparer.Ordinal)
    {
        "package.publish",
        "package.replace",
        "package.import",
        "package.unlist",
        "package.yank",
        "package.vuln",
        "package.blocked",
    };

    [Fact]
    public void ValidEventTypes_MatchesThePinnedSubscribableSet()
    {
        Assert.True(
            ExpectedSubscribableEventTypes.SetEquals(WebhookController.ValidEventTypes),
            "WebhookController.ValidEventTypes has drifted from the pinned subscribable set. "
            + $"Expected: [{string.Join(", ", ExpectedSubscribableEventTypes.OrderBy(t => t, StringComparer.Ordinal))}] "
            + $"Actual: [{string.Join(", ", WebhookController.ValidEventTypes.OrderBy(t => t, StringComparer.Ordinal))}] "
            + "Update this list AND web/src/lib/settings/SettingsWebhooks.svelte's ALL_EVENT_TYPES "
            + "AND its vitest parity spec together.");
    }
}
