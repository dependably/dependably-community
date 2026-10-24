using Dependably.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class WriteLockBudgetTests
{
    [Fact]
    public void Record_SlowBatch_ShrinksTheNextBatchInProportionToTheOverrun()
    {
        var budget = new WriteLockBudget(2_000, 100, 10_000);
        budget.Record(WriteLockBudget.Target * 4);
        Assert.Equal(500, budget.Rows);
    }

    [Fact]
    public void Record_StarvedBatch_NeverShrinksBelowTheFloor()
    {
        var budget = new WriteLockBudget(2_000, 100, 10_000);
        for (int i = 0; i < 20; i++)
        {
            budget.Record(TimeSpan.FromSeconds(30));
        }

        Assert.Equal(100, budget.Rows);
    }

    [Fact]
    public void Record_QuickBatches_GrowGraduallyUpToTheCeiling()
    {
        var budget = new WriteLockBudget(100, 100, 400);
        budget.Record(TimeSpan.FromMilliseconds(1));
        Assert.Equal(150, budget.Rows);
        for (int i = 0; i < 10; i++)
        {
            budget.Record(TimeSpan.Zero);
        }

        Assert.Equal(400, budget.Rows);
    }

    [Fact]
    public void Record_BatchOnTarget_KeepsTheSize()
    {
        var budget = new WriteLockBudget(1_000, 100, 10_000);
        budget.Record(WriteLockBudget.Target);
        Assert.Equal(1_000, budget.Rows);
    }
}
