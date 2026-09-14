using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// The counting mode of <see cref="AuthDenialAuditCoalescer"/>. Its whole reason to exist is that
/// repetition is the signal on the seams it serves — a rejected credential retried five hundred
/// times and one retried twice are different security events — so every test here pins a count,
/// not merely that something was recorded. The key-cap tests are the load-bearing ones: the
/// suppress-only map this class started as drops its whole map at the cap, and the key space
/// carries an attacker-controlled partition (an IPv6 <c>/64</c> costs nothing to mint), so a
/// counting map that inherited that behaviour would let an attacker spray keys to the bound and
/// zero every count in it at exactly the moment the counts matter.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuthDenialAuditAccumulatorTests
{
    private const string Action = "auth.token.rejected";

    private static AuthDenialKey Key(
        string partition,
        string? org = "org-1",
        string reason = "invalid",
        string? ecosystem = "npm",
        string route = "/npm/{*path}") =>
        new()
        {
            Action = Action,
            OrgId = org,
            Partition = partition,
            Ecosystem = ecosystem,
            Reason = reason,
            Route = route,
        };

    [Fact]
    public void ACountAlreadyAccumulatedSurvivesAKeySprayPastTheCap()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());
        var victim = Key("2001:db8:1::/64");

        for (int i = 0; i < 5; i++)
        {
            accumulator.Record(victim, sourceIp: "2001:db8:1::5");
        }

        // The attacker's half: a fresh /64 per request, straight past the cap.
        for (int i = 0; i < AuthDenialAuditCoalescer.CountKeyCap * 3; i++)
        {
            accumulator.Record(Key($"2001:db8:ffff:{i:x}::/64"), sourceIp: $"2001:db8:ffff:{i:x}::1");
        }

        var window = accumulator.DrainWindow();
        var tally = Assert.Single(window.Entries, e => e.Key == victim);
        Assert.Equal(5, tally.Count);
        Assert.Equal("2001:db8:1::5", tally.SourceIp);
    }

    [Fact]
    public void EveryRecordedDenialLandsInExactlyOneTallyNoMatterHowManyKeysWereSprayed()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());
        int recorded = 0;

        // Well past both the exact-key cap and the overflow-bucket cap, across several orgs and
        // reasons, with a repeat pass so some keys carry counts above one.
        for (int pass = 0; pass < 2; pass++)
        {
            for (int i = 0; i < (AuthDenialAuditCoalescer.CountKeyCap + AuthDenialAuditCoalescer.OverflowKeyCap) * 2; i++)
            {
                accumulator.Record(Key($"ip-{i}", org: $"org-{i % 400}", reason: i % 2 == 0 ? "invalid" : "tenant_mismatch"));
                recorded++;
            }
        }

        var window = accumulator.DrainWindow();

        Assert.Equal(recorded, window.Entries.Sum(e => e.Count));
    }

    [Fact]
    public void NewKeysPastTheCapFoldIntoACountedOverflowBucketRatherThanBeingDropped()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());

        for (int i = 0; i < AuthDenialAuditCoalescer.CountKeyCap; i++)
        {
            accumulator.Record(Key($"ip-{i}"));
        }

        for (int i = 0; i < 7; i++)
        {
            accumulator.Record(Key($"spray-{i}"));
        }

        var window = accumulator.DrainWindow();
        var overflow = Assert.Single(
            window.Entries,
            e => e.Key.Partition == AuthDenialAuditCoalescer.OverflowPartition && e.Key.OrgId == "org-1");

        Assert.Equal(7, overflow.Count);
        // The bucket keeps everything a rule can act on and collapses only the two dimensions an
        // attacker can mint: the partition and the route.
        Assert.Equal("invalid", overflow.Key.Reason);
        Assert.Equal("npm", overflow.Key.Ecosystem);
        Assert.Equal(Action, overflow.Key.Action);
        Assert.Equal(AuthDenialAuditCoalescer.OverflowPartition, overflow.Key.Route);
    }

    [Fact]
    public void OverflowBucketsStaySeparatePerOrgEcosystemAndReason()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());

        for (int i = 0; i < AuthDenialAuditCoalescer.CountKeyCap; i++)
        {
            accumulator.Record(Key($"ip-{i}"));
        }

        for (int i = 0; i < 3; i++)
        {
            accumulator.Record(Key($"a-{i}", org: "org-a"));
        }

        for (int i = 0; i < 4; i++)
        {
            accumulator.Record(Key($"b-{i}", org: "org-b", reason: "tenant_mismatch"));
        }

        var window = accumulator.DrainWindow();
        var buckets = window.Entries
            .Where(e => e.Key.Partition == AuthDenialAuditCoalescer.OverflowPartition)
            .ToList();

        Assert.Equal(3, Assert.Single(buckets, b => b.Key.OrgId == "org-a").Count);
        Assert.Equal(4, Assert.Single(buckets, b => b.Key.OrgId == "org-b" && b.Key.Reason == "tenant_mismatch").Count);
    }

    [Fact]
    public void PastTheOverflowCapCountsFoldOnceMoreInsteadOfGrowingTheMap()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());
        int recorded = 0;

        for (int i = 0; i < AuthDenialAuditCoalescer.CountKeyCap; i++)
        {
            accumulator.Record(Key($"ip-{i}"));
            recorded++;
        }

        // One distinct org per denial mints one overflow bucket per denial, so this walks past the
        // overflow cap too.
        const int orgSpray = 400;
        for (int i = 0; i < orgSpray; i++)
        {
            accumulator.Record(Key($"spray-{i}", org: $"org-spray-{i}"));
            recorded++;
        }

        var window = accumulator.DrainWindow();

        Assert.Equal(recorded, window.Entries.Sum(e => e.Count));
        Assert.True(
            window.Entries.Count <= AuthDenialAuditCoalescer.CountKeyCap + AuthDenialAuditCoalescer.OverflowKeyCap + 1,
            $"map grew to {window.Entries.Count} tallies, past its declared bound");

        var saturation = Assert.Single(
            window.Entries,
            e => e.Key.Reason == AuthDenialAuditCoalescer.OverflowReason);
        Assert.Null(saturation.Key.OrgId);
        Assert.Equal(orgSpray - AuthDenialAuditCoalescer.OverflowKeyCap, saturation.Count);
    }

    [Fact]
    public void TwoOrgsSharingOnePartitionInOneWindowProduceTwoAttributedTallies()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());

        accumulator.Record(Key("2001:db8::/64", org: "org-a"), sourceIp: "2001:db8::1");
        accumulator.Record(Key("2001:db8::/64", org: "org-a"), sourceIp: "2001:db8::1");
        accumulator.Record(Key("2001:db8::/64", org: "org-b"), sourceIp: "2001:db8::1");

        var window = accumulator.DrainWindow();

        Assert.Equal(2, window.Entries.Count);
        Assert.Equal(2, Assert.Single(window.Entries, e => e.Key.OrgId == "org-a").Count);
        Assert.Equal(1, Assert.Single(window.Entries, e => e.Key.OrgId == "org-b").Count);
    }

    /// <summary>
    /// The window bounds are the wall-clock grid, not the drain schedule. A denial recorded
    /// anywhere inside a minute is labelled with that minute's start and end, whatever instant the
    /// flush happens to run at — including a drain that fires mid-window, which must not relabel
    /// the counts it takes.
    /// </summary>
    [Fact]
    public void WindowBoundsAreTheWallClockGridNotTheDrainInstants()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow.AddSeconds(17));
        var accumulator = new AuthDenialAuditCoalescer(clock);

        accumulator.Record(Key("ip-1"));
        clock.Advance(TimeSpan.FromSeconds(9));
        var first = Assert.Single(accumulator.DrainWindow().Entries);

        clock.Advance(TimeSpan.FromSeconds(4));
        accumulator.Record(Key("ip-1"));
        clock.Advance(TimeSpan.FromSeconds(31));
        var second = Assert.Single(accumulator.DrainWindow().Entries);

        Assert.Equal(TestTime.KnownNow, first.WindowStart);
        Assert.Equal(TestTime.KnownNow.AddMinutes(1), first.WindowEnd);
        Assert.Equal(TestTime.KnownNow, second.WindowStart);
        Assert.Equal(TestTime.KnownNow.AddMinutes(1), second.WindowEnd);
    }

    /// <summary>
    /// The property the documented aggregation recipe rests on: the true count for a key is the
    /// SUM of the rows sharing <c>(org, partition, reason, window_start)</c>, which joins nothing
    /// unless replicas agree on <c>window_start</c> for the same denial. They are separate
    /// processes started at unrelated instants, so a window derived from construction time — or
    /// from a per-process flush schedule — labels one denial two different ways and a SOC
    /// following the recipe silently reads one replica's share as the whole.
    /// </summary>
    [Fact]
    public void ReplicasStartedAtDifferentInstantsLabelTheSameDenialWithTheSameWindow()
    {
        var eventTime = TestTime.KnownNow.AddSeconds(41);

        var clockA = new FakeTimeProvider(TestTime.KnownNow.AddSeconds(3));
        var clockB = new FakeTimeProvider(TestTime.KnownNow.AddSeconds(38));
        var replicaA = new AuthDenialAuditCoalescer(clockA);
        var replicaB = new AuthDenialAuditCoalescer(clockB);

        clockA.SetUtcNow(eventTime);
        clockB.SetUtcNow(eventTime);
        replicaA.Record(Key("ip-1"));
        replicaB.Record(Key("ip-1"));

        // Drains at unrelated instants, as two replicas' timers genuinely are.
        clockA.SetUtcNow(eventTime.AddSeconds(6));
        clockB.SetUtcNow(eventTime.AddSeconds(52));
        var fromA = Assert.Single(replicaA.DrainWindow().Entries);
        var fromB = Assert.Single(replicaB.DrainWindow().Entries);

        Assert.Equal(fromA.WindowStart, fromB.WindowStart);
        Assert.Equal(fromA.WindowEnd, fromB.WindowEnd);
        Assert.Equal(TestTime.KnownNow, fromA.WindowStart);
        Assert.Equal(fromA.Key, fromB.Key);
    }

    /// <summary>
    /// A burst that crosses a minute boundary is two windows, not one averaged over both: the
    /// counts split on the boundary and each half carries its own label. Folding them into one
    /// would attribute denials to a minute they did not happen in, which is the same defect as a
    /// per-process label, just smaller.
    /// </summary>
    [Fact]
    public void ABurstSpanningAWindowBoundarySplitsIntoTwoLabelledWindows()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow.AddSeconds(50));
        var accumulator = new AuthDenialAuditCoalescer(clock);

        accumulator.Record(Key("ip-1"));
        accumulator.Record(Key("ip-1"));
        clock.Advance(TimeSpan.FromSeconds(20));
        accumulator.Record(Key("ip-1"));

        var entries = accumulator.DrainWindow().Entries;

        Assert.Equal(2, entries.Count);
        Assert.Equal(2, Assert.Single(entries, e => e.WindowStart == TestTime.KnownNow).Count);
        Assert.Equal(
            1, Assert.Single(entries, e => e.WindowStart == TestTime.KnownNow.AddMinutes(1)).Count);
        Assert.Equal(3, entries.Sum(e => e.Count));
    }

    [Fact]
    public void DrainingClosesTheWindowSoACountIsNeverWrittenTwice()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());

        accumulator.Record(Key("ip-1"));
        accumulator.Record(Key("ip-1"));

        Assert.Equal(2, accumulator.DrainWindow().Entries.Sum(e => e.Count));
        Assert.Empty(accumulator.DrainWindow().Entries);
        Assert.Equal(0, accumulator.PendingKeyCount);
    }

    [Fact]
    public void SourceIpIsTheFirstAddressThatProducedTheDenialNotTheLast()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());

        accumulator.Record(Key("2001:db8::/64"), sourceIp: "2001:db8::1");
        accumulator.Record(Key("2001:db8::/64"), sourceIp: "2001:db8::2");

        var tally = Assert.Single(accumulator.DrainWindow().Entries);
        Assert.Equal("2001:db8::1", tally.SourceIp);
    }

    /// <summary>
    /// The name has to be in the declared vocabulary, not merely well-formed: an undeclared action
    /// never appears in <c>GET /api/v1/siem/actions</c>, so a collector cannot subscribe to it and
    /// — the part that actually costs events — cannot discover that it is missing one.
    /// </summary>
    [Fact]
    public void AnUndeclaredActionNameIsRefusedBecauseNoCollectorCouldEverDiscoverIt()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());
        var flat = new AuthDenialKey
        {
            Action = "token_rejected",
            OrgId = "org-1",
            Partition = "ip-1",
            Reason = "invalid",
            Route = "/npm/{*path}",
        };

        Assert.Throws<ArgumentException>(() => accumulator.Record(flat));
    }

    [Fact]
    public void RecordingDoesNotDisturbTheSuppressOnlyModeTheOciGateUses()
    {
        var accumulator = new AuthDenialAuditCoalescer(TestTime.Frozen());

        Assert.True(accumulator.ShouldAudit("org-1", "tok-1", "push"));

        for (int i = 0; i < AuthDenialAuditCoalescer.CountKeyCap + 10; i++)
        {
            accumulator.Record(Key($"ip-{i}"));
        }

        Assert.False(accumulator.ShouldAudit("org-1", "tok-1", "push"));
    }
}
