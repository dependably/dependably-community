using System.Text.RegularExpressions;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every arm the block gate can refuse on must record why it refused.
///
/// <para>
/// A refusal reaches the client as a status code and a reason token, and reaches the operator as
/// an <c>activity</c> row, a quarantine entry and a webhook event — all of which come from
/// <c>ApplySideEffectsAsync</c>'s switch. An arm added to <see cref="BlockArm"/> and wired into
/// the policy core but <em>not</em> into that switch still refuses the artefact; it just refuses
/// it invisibly. Nothing fails: the switch has no default arm, the build is clean, and the gate
/// tests all pass because they assert the verdict, not its aftermath. Two arms
/// (<c>kev_ransomware</c> and <c>epss_percentile</c>) shipped in exactly that state, which is why
/// this is a gate rather than a convention.
/// </para>
///
/// <para>
/// <see cref="BlockArm.None"/> is not a refusal. <see cref="BlockArm.Manual"/> and
/// <see cref="BlockArm.License"/> are recorded outside the switch — the licence arm on its own
/// evaluation path, which carries the offending expression the switch has no access to — so both
/// are exempted by name here, and each exemption is asserted to still be reachable in the source
/// rather than merely listed.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class BlockArmSideEffectComplianceTests
{
    // Arms whose recording deliberately happens somewhere other than the switch, each paired with
    // the source fragment that proves it still does.
    private static readonly (BlockArm Arm, string Evidence)[] RecordedElsewhere =
    [
        (BlockArm.Manual, "\"blocked_manual\""),
        (BlockArm.License, "QueueForReviewAsync(request, \"license\""),
    ];

    // The ApplySideEffectsAsync body, from its signature to the first closing brace at method
    // indentation.
    [GeneratedRegex(@"private async Task ApplySideEffectsAsync\(.*?\n    \}\n", RegexOptions.Singleline)]
    private static partial Regex SideEffectsMethodBody();

    [Fact]
    public void EveryRefusingArm_RecordsItsBlock()
    {
        string source = File.ReadAllText(Path.Combine(
            SourceRoots.RepoRoot(), "src", "Dependably.Core", "Protocol", "BlockGateService.cs"));

        // The switch body only — a `case BlockArm.X:` anywhere else in the file would otherwise
        // satisfy the gate without dispatching anything.
        var switchBody = SideEffectsMethodBody().Match(source);
        Assert.True(switchBody.Success, "ApplySideEffectsAsync not found — the gate cannot scan it.");

        var exempt = RecordedElsewhere.ToDictionary(e => e.Arm, e => e.Evidence);

        foreach (var (arm, evidence) in RecordedElsewhere)
        {
            Assert.True(
                source.Contains(evidence, StringComparison.Ordinal),
                $"{arm} is exempted from the switch as 'recorded elsewhere', but the evidence for "
                + $"that ({evidence}) is gone from BlockGateService.cs. Either it moved into the "
                + "switch — drop the exemption — or its recording was lost.");
        }

        var unrecorded = Enum.GetValues<BlockArm>()
            .Where(arm => arm != BlockArm.None && !exempt.ContainsKey(arm))
            .Where(arm => !switchBody.Value.Contains($"case BlockArm.{arm}:", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            unrecorded.Count == 0,
            "These block-gate arms refuse artefacts but have no case in ApplySideEffectsAsync, so "
            + "the refusal is recorded nowhere — no activity row, no quarantine entry, no webhook: "
            + string.Join(", ", unrecorded));
    }
}
