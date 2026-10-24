using System.Text.RegularExpressions;
using Dependably.Infrastructure;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Removing an org member is a full account erasure, and it ends in <c>DELETE FROM users</c>. Any
/// column that references <c>users(id)</c> without <c>ON DELETE CASCADE</c> or <c>SET NULL</c>
/// turns that delete into a foreign-key violation (a 500 during routine offboarding) unless
/// <c>OrgRepository.RemoveOrgMemberAsync</c> nulls or deletes the referencing rows first.
/// This gate derives the restrict set from both schema files and asserts the method handles each
/// column, so a new <c>created_by TEXT REFERENCES users(id)</c> cannot land unhandled.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class RemoveOrgMemberRestrictFkComplianceTests
{
    [GeneratedRegex(@"UPDATE\s+(?<t>\w+)\s+SET\s+(?<c>\w+)\s*=\s*NULL", RegexOptions.IgnoreCase)]
    private static partial Regex NullUpdateRegex();

    [GeneratedRegex(@"DELETE\s+FROM\s+(?<t>\w+)\s+WHERE[^""]*?\b(?<c>\w+)\s*=\s*@userId", RegexOptions.IgnoreCase)]
    private static partial Regex DeleteFromRegex();

    [GeneratedRegex(@"REFERENCES\s+""?users""?\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex UsersReferenceRegex();

    [GeneratedRegex(@"ON\s+DELETE\s+(CASCADE|SET\s+NULL)", RegexOptions.IgnoreCase)]
    private static partial Regex CascadeOrSetNullRegex();

    private static string RemoveMemberBody()
    {
        string root = SchemaTestPaths.SourceRoot();
        string src = File.ReadAllText(Path.Combine(root, "Infrastructure", "OrgRepository.cs"));
        int start = src.IndexOf("public async Task RemoveOrgMemberAsync(", StringComparison.Ordinal);
        Assert.True(start >= 0, "RemoveOrgMemberAsync not found in OrgRepository.cs");
        int end = src.IndexOf("_tokenVersions?.Invalidate(userId);", start, StringComparison.Ordinal);
        Assert.True(end > start, "end of RemoveOrgMemberAsync not found");
        return src[start..end];
    }

    private static HashSet<(string Table, string Column)> RestrictUserFks(string schemaSql) =>
        SchemaSqlParser.ParseTableDefinitions(schemaSql)
            .SelectMany(t => t.Value.Columns
                .Where(c => UsersReferenceRegex().IsMatch(c.Declaration)
                    && !CascadeOrSetNullRegex().IsMatch(c.Declaration))
                .Select(c => (t.Key.ToLowerInvariant(), c.Name.ToLowerInvariant())))
            .ToHashSet();

    [Fact]
    public void EveryRestrictFkToUsers_IsNulledOrDeleted_ByRemoveOrgMember()
    {
        string root = SchemaTestPaths.SourceRoot();
        var sqlite = RestrictUserFks(File.ReadAllText(SchemaTestPaths.SqliteSchema(root)));
        var postgres = RestrictUserFks(File.ReadAllText(SchemaTestPaths.PostgresSchema(root)));
        Assert.NotEmpty(sqlite);
        Assert.Equal(sqlite.OrderBy(x => x), postgres.OrderBy(x => x));

        string body = RemoveMemberBody();
        var handled = NullUpdateRegex().Matches(body)
            .Select(m => (m.Groups["t"].Value.ToLowerInvariant(), m.Groups["c"].Value.ToLowerInvariant()))
            .Concat(DeleteFromRegex().Matches(body)
                .Select(m => (m.Groups["t"].Value.ToLowerInvariant(), m.Groups["c"].Value.ToLowerInvariant())))
            .ToHashSet();

        var missing = sqlite.Union(postgres).Except(handled).OrderBy(x => x).ToList();
        Assert.True(
            missing.Count == 0,
            "Columns REFERENCES users(id) with no ON DELETE action that OrgRepository.RemoveOrgMemberAsync "
            + "neither nulls nor deletes (the user delete would violate the FK): "
            + string.Join(", ", missing.Select(m => $"{m.Item1}.{m.Item2}")));
    }

    [Fact]
    public void Gate_OnlyCountsRestrictReferences()
    {
        var fks = RestrictUserFks(
            "CREATE TABLE IF NOT EXISTS widget (id TEXT PRIMARY KEY, created_by TEXT REFERENCES users(id), "
            + "owner_id TEXT REFERENCES users(id) ON DELETE CASCADE, x TEXT REFERENCES users(id) ON DELETE SET NULL);");
        Assert.Equal([("widget", "created_by")], fks.ToList());
    }
}
