using Dependably.Api;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class PaginationHelperTests
{
    [Theory]
    [InlineData(1, 50, 0)]
    [InlineData(2, 50, 50)]
    [InlineData(3, 1, 2)]
    public void ComputeOffset_NormalPages_MatchesPageTimesLimit(int page, int limit, int expected)
    {
        Assert.Equal(expected, PaginationHelper.ComputeOffset(page, limit));
    }

    [Theory]
    [InlineData(0, 50)]
    [InlineData(-5, 50)]
    [InlineData(int.MinValue, 50)]
    public void ComputeOffset_PageBelowOne_ClampedToFirstPage(int page, int limit)
    {
        Assert.Equal(0, PaginationHelper.ComputeOffset(page, limit));
    }

    [Fact]
    public void ComputeOffset_LargePage_DoesNotOverflowOrGoNegative()
    {
        // (99999999 - 1) * 200 = 19,999,999,600, which wraps to a negative value in
        // unchecked 32-bit arithmetic. The guarded computation must never return a
        // negative offset for any non-negative page/limit input.
        int offset = PaginationHelper.ComputeOffset(page: 99_999_999, limit: 200);

        Assert.True(offset >= 0, $"offset must never be negative, got {offset}");
        Assert.True(offset <= 10_000_000, $"offset must stay within the sane bound, got {offset}");
    }

    [Fact]
    public void ComputeOffset_AtInt32Boundary_StaysBounded()
    {
        // page * limit lands exactly on int.MaxValue's neighborhood — the historical
        // unchecked multiplication silently wraps here too.
        int offset = PaginationHelper.ComputeOffset(page: int.MaxValue, limit: int.MaxValue);

        Assert.True(offset >= 0);
        Assert.Equal(10_000_000, offset);
    }

    [Fact]
    public void ComputeOffset_JustUnderMaxOffset_NotClamped()
    {
        // A legitimate deep page that lands just under the bound is returned exactly,
        // not clamped away.
        int offset = PaginationHelper.ComputeOffset(page: 50_000, limit: 200);

        Assert.Equal(9_999_800, offset);
    }
}
