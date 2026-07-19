namespace Dependably.Api;

/// <summary>
/// Computes a safe SQL <c>OFFSET</c> from a 1-based page number and a page size. Every list
/// endpoint clamps <c>limit</c> to its own maximum page size but only lower-bounds <c>page</c>
/// at 1 — an unbounded page multiplied by a plain <c>int limit</c> can overflow 32-bit
/// arithmetic and silently wrap to a small or negative offset. <see cref="ComputeOffset"/>
/// does the multiplication in 64-bit arithmetic and caps the result well under
/// <see cref="int.MaxValue"/>, so an absurdly large page number degrades to a bounded (and in
/// practice empty) trailing page instead of wrapping around to an unintended offset.
/// </summary>
public static class PaginationHelper
{
    /// <summary>
    /// Upper bound on any computed offset. Comfortably below <see cref="int.MaxValue"/> so the
    /// narrowing cast back to <c>int</c> can never overflow, and far beyond any page depth a
    /// real result set reaches — callers past this point are requesting a page number with no
    /// data, not a legitimate deep page.
    /// </summary>
    private const long MaxOffset = 10_000_000;

    /// <summary>
    /// Clamps <paramref name="page"/> to a minimum of 1, then returns
    /// <c>(page - 1) * limit</c> computed in <c>long</c> and capped at <see cref="MaxOffset"/>.
    /// Callers are responsible for clamping <paramref name="limit"/> to their own max page size
    /// before calling this.
    /// </summary>
    public static int ComputeOffset(int page, int limit)
    {
        page = Math.Max(page, 1);
        long offset = (long)(page - 1) * limit;
        return (int)Math.Min(offset, MaxOffset);
    }
}
