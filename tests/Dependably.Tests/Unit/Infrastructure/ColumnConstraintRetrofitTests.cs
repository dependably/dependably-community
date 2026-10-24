using System.Text;
using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The derivation behind <c>SchemaInitializer.ColumnConstraintRetrofit.cs</c>, checked against the
/// real <c>Schema.pg.sql</c>. The retrofit finds a constraint by the name Postgres gives an inline
/// <c>CHECK</c> / <c>REFERENCES</c> on a fresh install, so these tests pin the conditions under which
/// that name is predictable: one inline CHECK per column at most, and no name past Postgres's
/// 63-byte identifier limit.
/// </summary>
[Trait("Category", "Schema")]
public sealed partial class ColumnConstraintRetrofitTests
{
    private static readonly string PostgresSchema =
        File.ReadAllText(SchemaTestPaths.PostgresSchema(SchemaTestPaths.SourceRoot()));

    private static List<SchemaInitializer.DeclaredColumnConstraint> Declared() =>
        SchemaInitializer.DeclaredColumnConstraints(PostgresSchema);

    [Fact]
    public void EveryRepairableVocabularyColumn_HasAVocabularyCheckAndALiteralDefault()
    {
        var declared = Declared();
        foreach (var (table, column) in SchemaInitializer.RepairableVocabularyColumns)
        {
            var check = Assert.Single(declared, c => c.Table == table && c.Column == column
                && c.Kind == SchemaInitializer.ColumnConstraintKind.Check);
            Assert.True(SchemaInitializer.IsVocabularyCheck(check), $"{table}.{column}: {check.Definition}");
            Assert.NotNull(check.DefaultLiteral);
        }
    }

    [Fact]
    public void DefaultLiteral_IsReadFromTheDeclaration_AndIgnoresAnExpressionDefault()
    {
        var declared = Declared();
        Assert.Equal("0", declared.Single(c => c.Name == "project_documents_tool_version_explicit_unknown_check").DefaultLiteral);
        Assert.Equal("'off'", declared.Single(c => c.Name == "org_settings_verify_sbom_signatures_check").DefaultLiteral);
        Assert.All(declared.Where(c => c.Kind == SchemaInitializer.ColumnConstraintKind.ForeignKey),
            c => Assert.Null(c.DefaultLiteral));
    }

    [GeneratedRegex(@"UPDATE\s+(?<t>\w+)\s+SET\s+(?<c>\w+)\s*=\s*NULL", RegexOptions.IgnoreCase)]
    private static partial Regex NullUpdateRegex();

    [Fact]
    public void MemberRemovalAttributionColumns_AreExactlyTheColumnsRemoveOrgMemberNulls()
    {
        string src = File.ReadAllText(Path.Combine(SchemaTestPaths.SourceRoot(), "Infrastructure", "OrgRepository.cs"));
        int start = src.IndexOf("public async Task RemoveOrgMemberAsync(", StringComparison.Ordinal);
        int end = src.IndexOf("_tokenVersions?.Invalidate(userId);", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start, "RemoveOrgMemberAsync not found in OrgRepository.cs");
        var nulled = NullUpdateRegex().Matches(src[start..end])
            .Select(m => (m.Groups["t"].Value, m.Groups["c"].Value))
            .Where(tc => Declared().Any(c => c.Table == tc.Item1 && c.Column == tc.Item2
                && c.Kind == SchemaInitializer.ColumnConstraintKind.ForeignKey
                && c.Definition.Contains("REFERENCES users", StringComparison.Ordinal)))
            .OrderBy(x => x)
            .ToList();

        Assert.NotEmpty(nulled);
        Assert.Equal(nulled, SchemaInitializer.MemberRemovalAttributionColumns.OrderBy(x => x).ToList());
    }

    [Fact]
    public void DerivesBothKinds_FromTheRealSchema()
    {
        var declared = Declared();
        Assert.Contains(declared, c => c.Kind == SchemaInitializer.ColumnConstraintKind.Check);
        Assert.Contains(declared, c => c.Kind == SchemaInitializer.ColumnConstraintKind.ForeignKey);
    }

    [Fact]
    public void EveryDerivedName_IsUniqueAndWithinPostgresIdentifierLimit()
    {
        var declared = Declared();
        var duplicates = declared
            .GroupBy(c => (c.Table, c.Name))
            .Where(g => g.Count() > 1)
            .Select(g => $"{g.Key.Table}.{g.Key.Name}")
            .ToList();
        Assert.True(
            duplicates.Count == 0,
            "A column with two inline CHECKs is named <table>_<column>_check and _check1 by Postgres, "
            + "which the retrofit cannot predict. Split one into a named table constraint: "
            + string.Join(", ", duplicates));

        var tooLong = declared
            .Where(c => Encoding.UTF8.GetByteCount(c.Name) > 63)
            .Select(c => c.Name)
            .ToList();
        Assert.True(
            tooLong.Count == 0,
            "Postgres truncates an auto-generated constraint name past 63 bytes, so the retrofit "
            + "would look for a name that does not exist: " + string.Join(", ", tooLong));
    }

    [Fact]
    public void EveryInlineReferencesClause_BecomesAForeignKey()
    {
        var expected = SchemaSqlParser.ParseTableDefinitions(PostgresSchema)
            .SelectMany(t => t.Value.Columns
                .Where(c => SchemaSqlParser.WithoutCheckExpressions(c.Declaration)
                    .Contains("REFERENCES", StringComparison.OrdinalIgnoreCase))
                .Select(c => $"{t.Key}_{c.Name}_fkey"))
            .Order(StringComparer.Ordinal)
            .ToList();

        var derived = Declared()
            .Where(c => c.Kind == SchemaInitializer.ColumnConstraintKind.ForeignKey)
            .Select(c => c.Name)
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(expected);
        Assert.Equal(expected, derived);
    }

    [Fact]
    public void TemporalChecks_AreLeftToTheTemporalRetrofit()
    {
        var temporal = SchemaInitializer.DeclaredTemporalCheckColumns(PostgresSchema)
            .Select(c => $"{c.Table}_{c.Column}_check")
            .ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(temporal);

        Assert.DoesNotContain(
            Declared().Where(c => c.Kind == SchemaInitializer.ColumnConstraintKind.Check),
            c => temporal.Contains(c.Name));
    }

    [Theory]
    [InlineData("org_settings", "org_settings_verify_sbom_signatures_check",
        "CHECK (verify_sbom_signatures IN ('off', 'warn', 'block'))")]
    [InlineData("license_allowlist", "license_allowlist_disposition_check",
        "CHECK (disposition IN ('allowed','conditional'))")]
    [InlineData("license_allowlist", "license_allowlist_created_by_fkey",
        "FOREIGN KEY (created_by) REFERENCES users(id)")]
    public void DerivesTheFreshInstallDefinition(string table, string name, string definition)
    {
        var constraint = Assert.Single(Declared(), c => c.Table == table && c.Name == name);
        Assert.Equal(definition, constraint.Definition);
    }

    [Fact]
    public void ReferencesClause_KeepsItsActions_AndStopsBeforeTheNextColumnClause()
    {
        const string sql = """
            CREATE TABLE IF NOT EXISTS child (
                id        TEXT PRIMARY KEY,
                parent_id TEXT NOT NULL REFERENCES parent(id) ON DELETE CASCADE ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED CHECK (parent_id <> ''),
                owner_id  TEXT REFERENCES users ON DELETE SET NULL DEFAULT NULL
            );
            """;

        var declared = SchemaInitializer.DeclaredColumnConstraints(sql)
            .ToDictionary(c => c.Name, c => c.Definition, StringComparer.Ordinal);

        Assert.Equal(
            "FOREIGN KEY (parent_id) REFERENCES parent(id) ON DELETE CASCADE ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED",
            declared["child_parent_id_fkey"]);
        Assert.Equal("CHECK (parent_id <> '')", declared["child_parent_id_check"]);
        Assert.Equal("FOREIGN KEY (owner_id) REFERENCES users ON DELETE SET NULL", declared["child_owner_id_fkey"]);
    }
    [Theory]
    [InlineData("FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE", "orgs", "id", 'c')]
    [InlineData("FOREIGN KEY (a) REFERENCES parent(x, y) ON UPDATE CASCADE ON DELETE SET  NULL", "parent", "x,y", 'n')]
    [InlineData("FOREIGN KEY (owner_id) REFERENCES users ON DELETE NO ACTION", "users", null, 'a')]
    [InlineData("FOREIGN KEY (owner_id) REFERENCES users", "users", null, null)]
    public void ParsesTheForeignKeyShape(string definition, string table, string? columns, char? onDelete)
    {
        var shape = SchemaInitializer.ParseForeignKeyShape(definition);

        Assert.Equal(table, shape.ReferencedTable);
        Assert.Equal(columns, shape.ReferencedColumns is null ? null : string.Join(",", shape.ReferencedColumns));
        Assert.Equal(onDelete, shape.OnDelete);
    }

    private static readonly SchemaInitializer.DeclaredColumnConstraint UserTokensOrgFk = new(
        "user_tokens", "org_id", "user_tokens_org_id_fkey", SchemaInitializer.ColumnConstraintKind.ForeignKey,
        "FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE");

    private static SchemaInitializer.CatalogueConstraint Fk(
        string name, bool validated = true, string table = "user_tokens", string column = "org_id",
        string referencedTable = "orgs", string referencedColumn = "id", string onDelete = "c") => new()
        {
            Table = table,
            Name = name,
            Kind = "f",
            Validated = validated,
            Columns = [column],
            ReferencedTable = referencedTable,
            ReferencedColumns = [referencedColumn],
            ReferencedPrimaryKey = ["id"],
            OnDelete = onDelete,
        };

    [Fact]
    public void ForeignKey_UnderARenamedTablesName_IsRecognisedByDefinition()
    {
        var match = SchemaInitializer.FindExistingConstraint(UserTokensOrgFk, [Fk("tokens_org_id_fkey")]);

        Assert.Equal("tokens_org_id_fkey", match?.Name);
    }

    [Fact]
    public void ForeignKey_PrefersAValidatedEquivalent_OverANotValidOne()
    {
        var match = SchemaInitializer.FindExistingConstraint(
            UserTokensOrgFk,
            [Fk("a_not_valid_fkey", validated: false), Fk("tokens_org_id_fkey")]);

        Assert.Equal("tokens_org_id_fkey", match?.Name);
        Assert.True(match!.Validated);
    }

    [Fact]
    public void ForeignKey_WithTheDerivedName_IsThatConstraint()
    {
        var match = SchemaInitializer.FindExistingConstraint(
            UserTokensOrgFk, [Fk("tokens_org_id_fkey"), Fk("user_tokens_org_id_fkey", validated: false)]);

        Assert.Equal("user_tokens_org_id_fkey", match?.Name);
    }

    [Theory]
    [InlineData("service_tokens", "org_id", "orgs", "id", "c")]
    [InlineData("user_tokens", "user_id", "orgs", "id", "c")]
    [InlineData("user_tokens", "org_id", "users", "id", "c")]
    [InlineData("user_tokens", "org_id", "orgs", "slug", "c")]
    [InlineData("user_tokens", "org_id", "orgs", "id", "a")]
    public void ForeignKey_ThatDiffersInAnyPart_IsNotAMatch(
        string table, string column, string referencedTable, string referencedColumn, string onDelete)
    {
        var match = SchemaInitializer.FindExistingConstraint(
            UserTokensOrgFk,
            [Fk("tokens_org_id_fkey", table: table, column: column, referencedTable: referencedTable,
                referencedColumn: referencedColumn, onDelete: onDelete)]);

        Assert.Null(match);
    }

    [Theory]
    [InlineData("orgs", "id", "a")]
    [InlineData("orgs", "id", "n")]
    [InlineData("users", "id", "c")]
    [InlineData("orgs", "slug", "c")]
    public void ForeignKey_WithTheDerivedName_ThatDiffersFromTheDeclaration_IsStaleNotPresent(
        string referencedTable, string referencedColumn, string onDelete)
    {
        var existing = Fk("user_tokens_org_id_fkey", referencedTable: referencedTable,
            referencedColumn: referencedColumn, onDelete: onDelete);

        Assert.Null(SchemaInitializer.FindExistingConstraint(UserTokensOrgFk, [existing]));
    }

    [Theory]
    [InlineData("a", true)]
    [InlineData("r", true)]
    [InlineData("c", false)]
    [InlineData("n", false)]
    public void ForeignKey_DeclaredWithNoOnDelete_MatchesOnlyANoActionOrRestrictKeyOfTheSameName(
        string onDelete, bool matches)
    {
        var declared = UserTokensOrgFk with { Definition = "FOREIGN KEY (org_id) REFERENCES orgs(id)" };

        var match = SchemaInitializer.FindExistingConstraint(
            declared, [Fk("user_tokens_org_id_fkey", onDelete: onDelete)]);

        Assert.Equal(matches, match is not null);
    }

    [Fact]
    public void ForeignKey_WithNoReferencedColumns_MatchesTheTargetsPrimaryKey()
    {
        var declared = UserTokensOrgFk with { Definition = "FOREIGN KEY (org_id) REFERENCES orgs ON DELETE CASCADE" };

        Assert.NotNull(SchemaInitializer.FindExistingConstraint(declared, [Fk("tokens_org_id_fkey")]));
        Assert.Null(SchemaInitializer.FindExistingConstraint(
            declared, [Fk("tokens_org_id_fkey", referencedColumn: "slug")]));
    }

    [Fact]
    public void Check_IsMatchedByNameOnly()
    {
        var declared = new SchemaInitializer.DeclaredColumnConstraint(
            "license_allowlist", "disposition", "license_allowlist_disposition_check",
            SchemaInitializer.ColumnConstraintKind.Check, "CHECK (disposition IN ('allow','deny'))");
        var legacy = new SchemaInitializer.CatalogueConstraint
        {
            Table = "license_allowlist",
            Name = "legacy_disposition_check",
            Kind = "c",
            Validated = true,
            Columns = ["disposition"],
        };

        Assert.Null(SchemaInitializer.FindExistingConstraint(declared, [legacy]));
    }
}
