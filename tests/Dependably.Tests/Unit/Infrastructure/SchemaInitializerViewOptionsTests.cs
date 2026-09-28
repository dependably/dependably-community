using Dependably.Infrastructure;
using Dependably.Infrastructure.RowLevelSecurity;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The Postgres view DDL declares <c>security_invoker</c> on every server that supports it,
/// whatever the booting node's row-level-security mode, and leaves the statement untouched on a
/// server that would reject the option.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SchemaInitializerViewOptionsTests
{
    private const int Postgres15 = PostgresRowLevelSecurityInstaller.MinimumServerVersionNum;

    public static TheoryData<string> ViewNames()
    {
        var data = new TheoryData<string>();
        foreach ((string name, _) in SchemaInitializer.ViewDefinitions)
        {
            data.Add(name);
        }

        return data;
    }

    private static string BodyOf(string name) =>
        SchemaInitializer.ViewDefinitions.Single(v => v.Name == name).Sql;

    [Fact]
    public void EveryReadModelView_IsCovered()
    {
        Assert.Equal(
            new[] { "artifact_inventory", "artifact_license", "org_billable_storage_bytes", "org_storage_bytes" },
            SchemaInitializer.ViewDefinitions.Select(v => v.Name).OrderBy(n => n, StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(ViewNames))]
    public void SupportingServer_DeclaresSecurityInvoker_AndChangesNothingElse(string name)
    {
        string body = BodyOf(name);
        string plain = $"CREATE VIEW {name} AS";
        string invoker = $"CREATE VIEW {name} WITH (security_invoker = true) AS";

        string rewritten = SchemaInitializer.WithSecurityInvoker(name, body, Postgres15);

        Assert.Equal(1, CountOf(rewritten, invoker));
        Assert.Equal(body, rewritten.Replace(invoker, plain, StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(ViewNames))]
    public void OlderServer_LeavesTheStatementVerbatim(string name)
    {
        string body = BodyOf(name);

        string rewritten = SchemaInitializer.WithSecurityInvoker(name, body, Postgres15 - 1);

        Assert.Equal(body, rewritten);
        Assert.DoesNotContain("security_invoker", rewritten, StringComparison.Ordinal);
    }

    [Fact]
    public void StatementThatDoesNotDeclareTheNamedView_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => SchemaInitializer.WithSecurityInvoker(
            "artifact_inventory", "CREATE VIEW something_else AS SELECT 1", Postgres15));
    }

    private static int CountOf(string haystack, string needle)
    {
        int count = 0;
        for (int i = haystack.IndexOf(needle, StringComparison.Ordinal);
             i >= 0;
             i = haystack.IndexOf(needle, i + needle.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }
}
