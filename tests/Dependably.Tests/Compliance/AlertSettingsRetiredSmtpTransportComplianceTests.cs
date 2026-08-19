using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins the retirement posture of the per-org SMTP transport on <c>alert_settings</c>: the seven
/// columns are DROPPED, by a pass that repeats on every boot.
///
/// <para>
/// The columns previously stayed declared with only their values cleared, because a release still
/// in the field named all seven in both of its alert-settings SELECTs and blue-green runs one of
/// those against the same database during a cutover. That is no longer true of any release the
/// product supports upgrading a live slot from: the readers were removed in v0.6.0, so both v0.6.x
/// and v0.7.x name none of these columns. The scrub was the interim posture for the window in
/// between, and this is the contract step that ends it.
/// </para>
///
/// <para>
/// Three properties make the drop correct, and each is a thing a well-meaning cleanup would undo:
/// the columns are absent from BOTH provider <c>CREATE TABLE</c> blocks; no additive
/// <c>ADD COLUMN</c> migration re-adds them (one would fight the drop on every start, and
/// <c>SchemaSyncComplianceTests</c> rule 1 requires the two to agree); and a
/// <c>backcompat-ok:</c> waiver names every one of them, because a removal the backward-
/// compatibility gate can see must be an explicit, reasoned decision rather than a silent diff.
/// </para>
///
/// <para>
/// The fourth property is the subtle one and has its own test below: <b>the drop must not be
/// ledgered through <c>RunOnceAsync</c></b>. A previous release's own additive list still contains
/// all seven <c>ADD COLUMN</c> entries, so a slot of that release booting against a migrated
/// database re-adds them. A one-shot drop would already be recorded as done and never run again,
/// leaving the live schema permanently diverged from the schema file — invisibly, because the
/// backward-compatibility gate is declarative and never reads a live database. Repeating the drop
/// on every boot is what makes the two converge.
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

    /// <summary>The columns that survive — the delivery channel and its health, which are read.</summary>
    private static readonly string[] SurvivingEmailColumns =
    [
        "email_enabled",
        "email_recipients",
        "email_last_status",
        "email_consecutive_failures",
        "email_failing_since",
    ];

    [Fact]
    public void RetiredSmtpColumns_AreDeclaredInNeitherProviderSchemaFile()
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
                if (columns.Contains(column, StringComparer.OrdinalIgnoreCase))
                {
                    violations.Add($"{provider}: alert_settings.{column} is still declared");
                }
            }

            // The other half of the assertion, and the one that keeps this test honest: a parse
            // that silently found nothing would satisfy the check above for the wrong reason.
            foreach (string column in SurvivingEmailColumns)
            {
                if (!columns.Contains(column, StringComparer.OrdinalIgnoreCase))
                {
                    violations.Add(
                        $"{provider}: alert_settings.{column} is missing — the drop removed a column "
                        + "of the live delivery channel, not just the retired transport");
                }
            }
        }

        Assert.True(violations.Count == 0,
            "SMTP is an instance-level transport; an org owns the delivery channel and nothing about "
            + "how mail is carried. Re-declaring a per-org transport column reintroduces a retired "
            + "concept and a credential at rest:\n  " + string.Join("\n  ", violations));

        _output.WriteLine(
            $"All {RetiredColumns.Length} retired SMTP transport columns are absent from both provider "
            + $"files; all {SurvivingEmailColumns.Length} sampled delivery-channel columns survive.");
    }

    [Fact]
    public void RetiredSmtpColumns_HaveNoAdditiveMigration()
    {
        string initializerSource = string.Join(
            "\n", SchemaTestPaths.SchemaInitializerFiles().Select(File.ReadAllText));

        var resurrected = RetiredColumns
            .Where(column => initializerSource.Contains(
                $"ALTER TABLE alert_settings ADD COLUMN {column}", StringComparison.Ordinal))
            .ToList();

        Assert.True(resurrected.Count == 0,
            "An additive migration re-adding one of these columns would fight the every-boot drop on "
            + "every start, and would contradict the CREATE TABLE blocks that no longer declare it "
            + "(SchemaSyncComplianceTests rule 1). Resurrected: " + string.Join(", ", resurrected));
    }

    [Fact]
    public void EveryRetiredSmtpColumn_CarriesABackcompatWaiver()
    {
        var sources = new List<string>(SchemaTestPaths.SchemaInitializerFiles());
        string root = SchemaTestPaths.SourceRoot();
        sources.Add(SchemaTestPaths.SqliteSchema(root));
        sources.Add(SchemaTestPaths.PostgresSchema(root));

        var waived = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
                    // A marker naming an object but giving no reason is malformed and not honoured
                    // by SchemaBackwardCompatibilityComplianceTests, so it must not count here either.
                    string qualified = $"alert_settings.{column}";
                    int named = line.IndexOf(qualified, StringComparison.OrdinalIgnoreCase);
                    if (named >= 0 && HasReason(line, named + qualified.Length))
                    {
                        waived.Add(column);
                    }
                }
            }
        }

        var unwaived = RetiredColumns.Where(c => !waived.Contains(c)).ToList();

        Assert.True(unwaived.Count == 0,
            "Dropping a column is a change the backward-compatibility gate can see, so each one needs "
            + "a reasoned `backcompat-ok: alert_settings.<column> — <reason>` marker. Without it the "
            + "removal reads as an accident to the next reader and to the gate. Unwaived: "
            + string.Join(", ", unwaived));
    }

    /// <summary>
    /// The drop must repeat on every boot, never be recorded in the one-shot ledger. A previous
    /// release's additive list still re-adds all seven columns, so a ledgered drop loses to any
    /// old-slot boot exactly once and then never runs again — the live schema diverges from the
    /// schema file permanently, and no declarative gate can see it.
    /// </summary>
    [Fact]
    public void TheDrop_IsNotLedgeredAsAOneShotMigration()
    {
        string initializerSource = string.Join(
            "\n", SchemaTestPaths.SchemaInitializerFiles().Select(File.ReadAllText));

        const string dropMethod = "DropAlertSettingsRetiredSmtpColumnsAsync";

        Assert.Contains(dropMethod, initializerSource, StringComparison.Ordinal);

        foreach (string line in initializerSource.Split('\n'))
        {
            if (line.Contains(dropMethod, StringComparison.Ordinal)
                && line.Contains("RunOnceAsync", StringComparison.Ordinal))
            {
                Assert.Fail(
                    "The retired-SMTP-column drop is registered through RunOnceAsync: "
                    + line.Trim()
                    + "\nA ledgered drop runs once and is then recorded as done, so the columns a "
                    + "previous release's additive list re-adds on its next boot are never dropped "
                    + "again. Call it directly from InitializeAsync so it repeats and converges.");
            }
        }
    }

    // True when text follows the named object on a waiver line — an em dash and a reason, rather
    // than a bare name.
    private static bool HasReason(string line, int afterName) =>
        line.Length > afterName && line[afterName..].Trim(' ', '—', '-', ':').Length > 0;
}
