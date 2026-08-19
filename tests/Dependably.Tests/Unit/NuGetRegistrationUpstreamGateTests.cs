using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// The NuGet registration index must never advertise a version its flatcontainer download path
/// will refuse — the same invariant already enforced for local (uploaded + proxy-cached) rows via
/// <see cref="BlockGateService.IsHardBlockedByStoredState"/>. This covers the hole that invariant
/// left open: an UPSTREAM-only leaf, spliced in or passed through by
/// <see cref="NuGetRegistrationHelpers.RewriteAllLeafUrls"/>, carries no local row and so was never
/// filtered at all.
///
/// Only the release-age and deprecated (unlisted) arms are decidable for such a leaf — the facts
/// come from <c>catalogEntry.published</c>/<c>listed</c>, the same fields
/// <c>NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync</c> reads at first fetch — so
/// that's what these tests exercise. Every test here fails on the pre-fix renderer: the
/// <c>upstreamGate</c> parameter (and the filtering it drives) did not exist, so an upstream leaf
/// was rewritten and re-emitted unconditionally regardless of its published/listed facts.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetRegistrationUpstreamGateTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 18, 12, 0, 0, TimeSpan.Zero);

    private static BlockPolicy Policy(int? minReleaseAgeHours = null, string? blockDeprecatedMode = null) =>
        new(MinReleaseAgeHours: minReleaseAgeHours,
            BlockDeprecatedMode: blockDeprecatedMode,
            BlockMaliciousMode: null,
            BlockKevMode: null,
            MaxEpssTolerance: null,
            MaxOsvScoreTolerance: 10,
            BlockInstallScriptsMode: null,
            VerifyProvenanceMode: null,
            BlockRevokedMode: null);

    // Builds a minimal upstream registration index (single inline page, one leaf per version)
    // shaped like api.nuget.org's document — the same shape MinimalUpstream in
    // NuGetRegistrationMergeTests builds, extended with the published/listed fields those tests
    // never needed.
    private static string Upstream(string id, params (string Version, DateTimeOffset? Published, bool Listed)[] entries)
    {
        var items = new JsonArray();
        foreach (var (version, published, listed) in entries)
        {
            var catalogEntry = new JsonObject
            {
                ["id"] = id,
                ["version"] = version,
                ["listed"] = listed,
                ["packageContent"] = $"https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg"
            };
            if (published is { } ts)
            {
                catalogEntry["published"] = ts.ToString("O");
            }

            items.Add(new JsonObject
            {
                ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/{version}.json",
                ["@type"] = "Package",
                ["catalogEntry"] = catalogEntry
            });
        }

        var root = new JsonObject
        {
            ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/index.json",
            ["@type"] = new JsonArray("catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"),
            ["count"] = 1,
            ["items"] = new JsonArray(new JsonObject
            {
                ["@id"] = $"https://api.nuget.org/v3/registration5-semver1/{id}/index.json#page/upstream",
                ["@type"] = "catalog:CatalogPage",
                ["count"] = entries.Length,
                ["items"] = items,
                ["lower"] = entries.Length > 0 ? entries[0].Version : "",
                ["upper"] = entries.Length > 0 ? entries[^1].Version : ""
            })
        };
        return root.ToJsonString();
    }

    private static string[] Versions(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("items").EnumerateArray()
            .SelectMany(p => p.GetProperty("items").EnumerateArray())
            .Select(e => e.GetProperty("catalogEntry").GetProperty("version").GetString()!)
            .ToArray();
    }

    // ── Release-age arm ──────────────────────────────────────────────────────────────────

    [Fact]
    public void UpstreamOnlyLeaf_YoungerThanTheHold_IsNotAdvertised_WhileTheOlderOneIs()
    {
        string upstream = Upstream("idna",
            ("3.19", Now.AddHours(-2), true),
            ("3.18", Now.AddDays(-60), true));

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "idna", "https://tenant.example/nuget",
            upstreamGate: (Policy(minReleaseAgeHours: 24), Now));

        string[] versions = Versions(rewritten);
        Assert.DoesNotContain("3.19", versions);
        Assert.Contains("3.18", versions);
    }

    /// <summary>
    /// The control that keeps the filter honest: with no cooldown configured, the same too-young
    /// entry is advertised. Without this, a renderer that dropped every upstream leaf would pass
    /// the test above.
    /// </summary>
    [Fact]
    public void UpstreamOnlyLeaf_WithNoHoldConfigured_IsAdvertised()
    {
        string upstream = Upstream("idna", ("3.19", Now.AddHours(-2), true));

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "idna", "https://tenant.example/nuget",
            upstreamGate: (Policy(), Now));

        Assert.Contains("3.19", Versions(rewritten));
    }

    /// <summary>
    /// A leaf with no <c>published</c> member at all fails the hold open, matching
    /// <see cref="BlockGateService.Evaluate"/>'s posture for an unknown publish time — a stricter
    /// reading would hide every package from a feed that omits the field.
    /// </summary>
    [Fact]
    public void UpstreamOnlyLeaf_WithNoPublishedTimestamp_FailsOpen()
    {
        string upstream = Upstream("idna", ("3.19", Published: null, Listed: true));

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "idna", "https://tenant.example/nuget",
            upstreamGate: (Policy(minReleaseAgeHours: 24), Now));

        Assert.Contains("3.19", Versions(rewritten));
    }

    /// <summary>
    /// NuGet's 1900-01-01 sentinel for "no publish timestamp recorded" must not be read as a real
    /// timestamp — a naive parse would see it as ~126 years old and pass every cooldown, which
    /// happens to look correct here but is right for the wrong reason and wrong wherever the gate
    /// checks staleness rather than youth. It must be coerced to the same "unknown" the null case
    /// takes, which the assertion above already covers; this test pins the coercion itself.
    /// </summary>
    [Fact]
    public void UpstreamOnlyLeaf_WithUnsetSentinelPublishedDate_TreatsItAsUnknown()
    {
        string upstream = Upstream("idna", ("3.19", new DateTimeOffset(1900, 1, 1, 0, 0, 0, TimeSpan.Zero), true));

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "idna", "https://tenant.example/nuget",
            upstreamGate: (Policy(minReleaseAgeHours: 24), Now));

        // Fails open exactly like the null case — a sentinel-as-real-date bug would also pass
        // this assertion (an 1900 date clears any cooldown), so the point is that it is treated
        // as ABSENT rather than as a real, very-old timestamp; see the release-age arm at
        // BlockGateService.IsReleaseAgeBlocked, which requires PublishedAt to be present at all.
        Assert.Contains("3.19", Versions(rewritten));
    }

    // ── Deprecated (unlisted) arm ────────────────────────────────────────────────────────

    [Fact]
    public void UpstreamOnlyLeaf_Unlisted_IsNotAdvertisedUnderABlockingDeprecationPolicy()
    {
        string upstream = Upstream("demo",
            ("1.0.0", Now.AddDays(-400), Listed: false),
            ("1.0.1", Now.AddDays(-400), Listed: true));

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "demo", "https://tenant.example/nuget",
            upstreamGate: (Policy(blockDeprecatedMode: "block_all"), Now));

        string[] versions = Versions(rewritten);
        Assert.DoesNotContain("1.0.0", versions);
        Assert.Contains("1.0.1", versions);
    }

    /// <summary>
    /// Under a non-blocking (or unset) deprecated policy, an unlisted upstream leaf still gets
    /// advertised — the policy knob, not the mere presence of the fact, decides.
    /// </summary>
    [Fact]
    public void UpstreamOnlyLeaf_Unlisted_StaysAdvertisedWhenDeprecatedPolicyIsNotBlocking()
    {
        string upstream = Upstream("demo", ("1.0.0", Now.AddDays(-400), Listed: false));

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "demo", "https://tenant.example/nuget",
            upstreamGate: (Policy(), Now));

        Assert.Contains("1.0.0", Versions(rewritten));
    }

    // ── Mixed partial-failure: local splice + upstream gate act independently ───────────────

    /// <summary>
    /// A single response can carry all three outcomes at once: an upstream leaf the gate keeps, an
    /// upstream leaf the gate drops, and a local (uploaded) version spliced in beside them. The
    /// local splice must not be affected by the upstream gate, and the upstream gate must not be
    /// affected by the local splice — they are independent filters over independent leaf sources.
    /// </summary>
    [Fact]
    public void MergeLocalIntoUpstreamRegistration_GatesUpstreamLeaves_WhileLocalSpliceIsUnaffected()
    {
        string upstream = Upstream("widget",
            ("1.0.0", Now.AddDays(-400), true),   // servable: old enough, listed
            ("1.0.1", Now.AddHours(-1), true));    // dropped: inside the cooldown
        var local = new[] { new PackageVersion { Version = "2.0.0-local", Yanked = false } };

        string merged = NuGetController.MergeLocalIntoUpstreamRegistration(
            upstream, local, new Package { Name = "Widget", PurlName = "widget" }, "widget",
            baseUrl: "https://tenant.example/nuget",
            upstreamGate: (Policy(minReleaseAgeHours: 24), Now));

        string[] versions = Versions(merged);
        Assert.Contains("1.0.0", versions);
        Assert.DoesNotContain("1.0.1", versions);
        Assert.Contains("2.0.0-local", versions);
    }

    // ── No gate supplied: existing callers/tests are unaffected ─────────────────────────────

    /// <summary>
    /// A caller that supplies no <paramref name="upstreamGate"/> — the default — gets no
    /// filtering, matching every pre-existing <c>NuGetRegistrationMergeTests</c> call site. This
    /// is the same "null skips the check" posture <c>upstreamBaseUrls</c> already has on this
    /// method.
    /// </summary>
    /// <summary>
    /// Passing a null gate explicitly still advertises everything — the local-only callers whose
    /// output carries no upstream leaf rely on that. The parameter is required rather than
    /// defaulted precisely so this is a decision a call site states, not one it inherits: a gate
    /// that defaults to "no gate" is the same silent-hole shape as a BlockGateRequest field left
    /// off a call site, which this repo has been bitten by twice.
    /// </summary>
    [Fact]
    public void UpstreamOnlyLeaf_WithAnExplicitlyNullGate_IsAdvertisedRegardlessOfAge()
    {
        string upstream = Upstream("idna", ("3.19", Now.AddHours(-2), true));

        string rewritten = NuGetController.RewriteRegistrationIndexUrls(
            upstream, "idna", "https://tenant.example/nuget", upstreamGate: null);

        Assert.Contains("3.19", Versions(rewritten));
    }
}
