namespace Dependably.Infrastructure;

/// <summary>
/// Builds the bound parameter for a substring <c>LIKE</c> search, escaping the wildcards a caller's
/// search term may legitimately contain.
///
/// <para>
/// These searches are parameterized, so this is not an injection concern — the term never becomes
/// SQL. It is a correctness one: <c>%</c> and <c>_</c> are LIKE metacharacters, so an unescaped term
/// silently changes what the query means. <c>_</c> matches any single character, which matters here
/// because PyPI and NuGet names routinely contain it (<c>my_pkg</c> also matches <c>myXpkg</c>), and
/// a bare <c>%</c> as the whole term matches every row — turning a filtered lookup into a full scan
/// over a leading-wildcard predicate no index can serve.
/// </para>
///
/// <para>
/// The escape character is backslash, so every SQL predicate consuming one of these patterns must
/// carry <c>ESCAPE '\'</c>. Without it the backslashes this inserts are matched literally and a term
/// containing <c>_</c> stops matching itself. The pairing is enforced by
/// <c>LikeEscapeComplianceTests</c>, not by convention: the two halves live in different files, and
/// a mismatch fails silently in the direction of a wrong result rather than an error.
/// </para>
/// </summary>
public static class LikePattern
{
    /// <summary>
    /// A <c>%term%</c> pattern with LIKE metacharacters escaped, or <c>null</c> when the term is
    /// null or blank — the shape every call site's <c>(@searchPattern IS NULL OR …)</c> guard expects
    /// for "no search supplied".
    /// </summary>
    public static string? Contains(string? term) =>
        string.IsNullOrWhiteSpace(term) ? null : $"%{Escape(term.Trim())}%";

    /// <summary>
    /// As <see cref="Contains"/>, lowercased — for predicates written <c>lower(col) LIKE @pattern</c>,
    /// where the pattern must be lowercased for the comparison to be case-insensitive rather than
    /// merely lowercasing one side.
    /// </summary>
    public static string? ContainsLower(string? term) =>
        string.IsNullOrWhiteSpace(term) ? null : $"%{Escape(term.Trim().ToLowerInvariant())}%";

    /// <summary>
    /// Escapes the LIKE metacharacters. The backslash must be escaped first, otherwise the
    /// backslashes introduced by the <c>%</c> and <c>_</c> rules would themselves be doubled.
    /// </summary>
    public static string Escape(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}
