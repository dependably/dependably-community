using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins the retirement posture of the per-org SMTP transport on <c>alert_settings</c>: the seven
/// columns stay DECLARED and only their stored values are cleared.
///
/// <para>
/// The reason is blue-green, and it is not a sequencing problem a deferral solves. Releases still in
/// the field name all seven columns in both of their alert-settings SELECTs, and a cutover runs one
/// of those releases against the same database as the new one. Removing the columns breaks that
/// slot's <em>entire</em> alert-settings read — the Alerts page and the delivery gate, not merely the
/// transport — and it breaks it for any operator upgrading straight from such a release, which is
/// exactly the jump an operator makes when they skip intermediate versions. Clearing the values
/// achieves the goal the removal was for (no orphaned envelope-encrypted credential at rest) with no
/// ordering constraint at all.
/// </para>
///
/// <para>
/// Three properties make that work, and each is a thing a well-meaning cleanup would undo:
/// the columns are declared in BOTH provider <c>CREATE TABLE</c> blocks; their additive
/// <c>ADD COLUMN</c> migrations survive, so an upgraded database's column set is identical to a
/// fresh install's (which is what lets the scrub be a plain <c>UPDATE</c> with no per-column
/// existence probing, and what keeps <c>SchemaSyncComplianceTests</c> rule 1 satisfied); and no
/// <c>backcompat-ok:</c> waiver names any of them, because nothing is being removed and a waiver for
/// a removal that does not happen misdescribes the schema to the next reader.
/// </para>
/// </summary>
[Trait("Category", "Schema")]
public sealed class AlertSettingsRetiredSmtpTransportComplianceTests
{
    private readonly ITestOutputHelper _output;
    public AlertSettingsRetiredSmtpTransportComplianceTests(ITestOutputHelper output) => _output = output;

    private static readonly string[] RetiredColumns =
    [
        "email_inherit_instance",
        "email_smtp_host",
        "email_smtp_port",
        "email_smtp_security",
        "email_smtp_username",
        "email_smtp_password",
        "email_smtp_from",
    ];

    [Fact]
    public void RetiredSmtpColumns_StayDeclaredInBothProviderSchemaFiles()
    {
        string root = SchemaTestPaths.SourceRoot();
        var violations = new List<string>();

        foreach ((string provider, string path) in new[]
        {
            ("Schema.sql", SchemaTestPaths.SqliteSchema(root)),
            ("Schema.pg.sql", SchemaTestPaths.PostgresSchema(root)),
        })
        {
            var tables = SchemaSqlParser.ParseTables(File.ReadAllText(path));
            if (!tables.TryGetValue("alert_settings", out var columns))
            {
                violations.Add($"{provider}: no CREATE TABLE alert_settings block found");
                continue;
            }

            foreach (string column in RetiredColumns)
            {
                if (!columns.Contains(column, StringComparer.OrdinalIgnoreCase))
                {
                    violations.Add($"{provider}: alert_settings.{column} is no longer declared");
                }
            }
        }

        Assert.True(violations.Count == 0,
            "The retired per-org SMTP transport columns are cleared by value, not dropped, so that a "
            + "release still in the field can keep reading alert_settings across a blue-green cutover. "
            + "Removing a declaration breaks that slot's whole alert-settings read:\n  "
            + string.Join("\n  ", violations));

        _output.WriteLine(
            $"All {RetiredColumns.Length} retired SMTP transport columns stay declared in both provider files.");
    }

    [Fact]
    public void RetiredSmtpColumns_KeepTheirAdditiveMigrations()
    {
        string initializerSource = string.Join(
            "\n", SchemaTestPaths.SchemaInitializerFiles().Select(File.ReadAllText));

        var missing = RetiredColumns
            .Where(column => !initializerSource.Contains(
                $"ALTER TABLE alert_settings ADD COLUMN {column}", StringComparison.Ordinal))
            .ToList();

        Assert.True(missing.Count == 0,
            "An upgraded database reaches the current column set through these additive migrations. "
            + "Without them an upgraded database lacks columns a fresh install has, the value scrub "
            + "would have to probe for each column before writing it, and SchemaSyncComplianceTests "
            + "rule 1 fails on the CREATE TABLE declarations that remain. Missing: "
            + string.Join(", ", missing));
    }

    [Fact]
    public void NoBackcompatWaiver_NamesARetiredSmtpColumn()
    {
        var sources = new List<string>(SchemaTestPaths.SchemaInitializerFiles());
        string root = SchemaTestPaths.SourceRoot();
        sources.Add(SchemaTestPaths.SqliteSchema(root));
        sources.Add(SchemaTestPaths.PostgresSchema(root));

        var violations = new List<string>();
        foreach (string path in sources)
        {
            foreach (string line in File.ReadAllLines(path))
            {
                if (!line.Contains("backcompat-ok:", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (string column in RetiredColumns)
                {
                    if (line.Contains($"alert_settings.{column}", StringComparison.OrdinalIgnoreCase))
                    {
                        violations.Add($"{Path.GetFileName(path)}: {line.Trim()}");
                    }
                }
            }
        }

        Assert.True(violations.Count == 0,
            "Nothing about these columns is removed, so SchemaBackwardCompatibilityComplianceTests has "
            + "nothing to waive. A waiver here would tell the next reader the columns are gone when "
            + "they are declared and read:\n  " + string.Join("\n  ", violations));
    }
}
