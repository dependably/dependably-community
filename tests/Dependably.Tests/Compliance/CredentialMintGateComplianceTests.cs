using System.Text.RegularExpressions;
using Dependably.Infrastructure;

namespace Dependably.Tests.Compliance;

/// <summary>
/// A tenant lockout (suspension, archive, deletion) ends access by deleting every bearer
/// credential the tenant holds, in <c>OrgRepository.RevokeTenantAccessAsync</c>, and every mint of
/// such a credential re-reads the tenant's status inside its own transaction through
/// <see cref="TenantMintGate"/>, so a mint in flight during the lockout cannot land after the
/// revoke and be revived by the restore. Both halves are lists a new credential table has to be
/// added to by hand, and a table missing from either passes every other test.
///
/// <para>
/// The credential tables are derived from <c>Schema.sql</c>: every table with a
/// <c>token_hash</c> column and a tenant column (<c>org_id</c>/<c>tenant_id</c>). For each one:
/// <list type="number">
///   <item>the revoke deletes from it, in <c>RevokeTenantAccessAsync</c> or an
///         <c>OrgRepository</c> helper it calls;</item>
///   <item>every method under <c>src/</c> holding an <c>INSERT INTO</c> the table also calls
///         <c>TenantMintGate.RequireMintableAsync</c>, directly or through a method of the same
///         file it calls. A deliberate exception (a boot-time seed with no lifecycle plane behind
///         it) carries a <c>// mint-ok: &lt;reason&gt;</c> marker in the five lines above the
///         INSERT.</item>
/// </list>
/// </para>
///
/// <para>
/// Method extents are found textually, not by a parser: a member runs from its declaration line
/// to the next declaration at the same or a shallower indentation. That is exact for the
/// repository code this scans; what it cannot see is a gate call in another file, which is the
/// reason the callee walk is confined to the INSERT's own file.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class CredentialMintGateComplianceTests
{
    private const int MarkerWindow = 5;

    private const string GateCall = "TenantMintGate.RequireMintableAsync(";

    // The tables the derivation is known to produce today. Asserted as a floor so a schema-parse
    // regression that finds nothing cannot turn both checks into vacuous passes.
    private static readonly string[] KnownCredentialTables =
    [
        "user_tokens", "service_tokens", "invites", "password_reset_tokens", "email_change_tokens", "mfa_trusted_devices",
    ];

    [GeneratedRegex(@"^(?<indent>[ \t]*)(?:(?:public|private|internal|protected|static|async|sealed|override|virtual|partial|unsafe|extern|readonly)\s+)+[\w<>\[\],.?()\s]*?\b(?<name>\w+)\s*(?:<[^>]*>)?\s*\((?!.*;\s*$)")]
    private static partial Regex MemberDeclarationRegex();

    // The same declaration shape without the "does not end in ;" condition: it also matches a
    // one-line expression-bodied member, which the extent scan cannot bound.
    [GeneratedRegex(@"^[ \t]*(?:(?:public|private|internal|protected|static|async|sealed|override|virtual|partial|unsafe|extern|readonly)\s+)+[\w<>\[\],.?()\s]*?\b\w+\s*(?:<[^>]*>)?\s*\(")]
    private static partial Regex DeclarationShapeRegex();

    [GeneratedRegex(@"\bINSERT\s+(?:OR\s+\w+\s+)?INTO\s+""?(?<table>\w+)""?", RegexOptions.IgnoreCase)]
    private static partial Regex InsertRegex();

    [GeneratedRegex(@"\bDELETE\s+FROM\s+""?(?<table>\w+)""?", RegexOptions.IgnoreCase)]
    private static partial Regex DeleteRegex();

    [GeneratedRegex(@"//\s*mint-ok:\s*\S")]
    private static partial Regex MarkerRegex();

    [GeneratedRegex(@"\b(?<name>\w+)\s*(?:<[^>()]*>)?\s*\(")]
    private static partial Regex CallRegex();

    [GeneratedRegex(@"^\s*(?://|///|\*)")]
    private static partial Regex CommentLineRegex();

    internal sealed record Member(string Name, int Start, int End);

    /// <summary>Every tenant-scoped table that stores a bearer credential's hash.</summary>
    internal static IReadOnlyList<string> CredentialTables()
    {
        string sql = File.ReadAllText(SchemaTestPaths.SqliteSchema(SchemaTestPaths.SourceRoot()));
        return SchemaSqlParser.ParseTables(sql)
            .Where(t => t.Value.Contains("token_hash", StringComparer.OrdinalIgnoreCase)
                && (t.Value.Contains("org_id", StringComparer.OrdinalIgnoreCase)
                    || t.Value.Contains("tenant_id", StringComparer.OrdinalIgnoreCase)))
            .Select(t => t.Key.ToLowerInvariant())
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();
    }

    internal static IReadOnlyList<Member> Members(string[] lines)
    {
        var starts = new List<(string Name, int Line, int Indent)>();
        for (int i = 0; i < lines.Length; i++)
        {
            var m = MemberDeclarationRegex().Match(lines[i]);
            if (m.Success && !CommentLineRegex().IsMatch(lines[i]))
            {
                starts.Add((m.Groups["name"].Value, i, m.Groups["indent"].Value.Length));
            }
        }

        var members = new List<Member>();
        for (int k = 0; k < starts.Count; k++)
        {
            int end = lines.Length - 1;
            for (int n = k + 1; n < starts.Count; n++)
            {
                if (starts[n].Indent <= starts[k].Indent)
                {
                    end = starts[n].Line - 1;
                    break;
                }
            }

            members.Add(new Member(starts[k].Name, starts[k].Line, end));
        }

        return members;
    }

    // The code lines of a member (comment lines dropped, so prose naming a table or the gate does
    // not count), followed by those of every same-file member it calls, transitively.
    internal static string BodyWithCallees(string[] lines, IReadOnlyList<Member> members, Member root)
    {
        var byName = members.GroupBy(m => m.Name).ToDictionary(g => g.Key, g => g.ToList());
        var seen = new HashSet<Member>();
        var pending = new Stack<Member>();
        pending.Push(root);
        var text = new System.Text.StringBuilder();
        while (pending.Count > 0)
        {
            var member = pending.Pop();
            if (!seen.Add(member))
            {
                continue;
            }

            for (int i = member.Start; i <= member.End; i++)
            {
                if (CommentLineRegex().IsMatch(lines[i]))
                {
                    continue;
                }

                text.AppendLine(lines[i]);
                // The member's own name on its declaration line is the declaration, not a call;
                // counting it would pull in every overload, gated or not.
                bool skipOwnName = i == member.Start;
                foreach (Match call in CallRegex().Matches(lines[i]))
                {
                    string name = call.Groups["name"].Value;
                    if (skipOwnName && name == member.Name)
                    {
                        skipOwnName = false;
                        continue;
                    }

                    if (byName.TryGetValue(name, out var callees))
                    {
                        foreach (var callee in callees)
                        {
                            pending.Push(callee);
                        }
                    }
                }
            }
        }

        return text.ToString();
    }

    internal static IReadOnlyList<string> UngatedInserts(IEnumerable<string> files, IReadOnlyCollection<string> tables)
    {
        var failures = new List<string>();
        foreach (string file in files)
        {
            string[] lines = File.ReadAllText(file).Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
            // Matched over the whole file, not line by line, so a raw-string INSERT that breaks
            // between INTO and the table name is still seen. Each match maps back to its first line.
            string source = string.Join('\n', lines);
            var lineStarts = new List<int> { 0 };
            for (int c = 0; c < source.Length; c++)
            {
                if (source[c] == '\n')
                {
                    lineStarts.Add(c + 1);
                }
            }

            IReadOnlyList<Member>? members = null;
            foreach (Match insert in InsertRegex().Matches(source))
            {
                int i = lineStarts.BinarySearch(insert.Index);
                i = i >= 0 ? i : ~i - 1;
                if (CommentLineRegex().IsMatch(lines[i]))
                {
                    continue;
                }

                string table = insert.Groups["table"].Value.ToLowerInvariant();
                if (!tables.Contains(table))
                {
                    continue;
                }

                bool marked = Enumerable.Range(Math.Max(0, i - MarkerWindow), Math.Min(i, MarkerWindow))
                    .Any(j => MarkerRegex().IsMatch(lines[j]));
                if (marked)
                {
                    continue;
                }

                members ??= Members(lines);
                // An INSERT on a line shaped like a member declaration belongs to a one-line
                // expression-bodied member the extent scan does not bound; crediting it to the
                // member above would let that member's gate cover it, so it fails closed.
                var owner = DeclarationShapeRegex().IsMatch(lines[i]) && !members.Any(m => m.Start == i)
                    ? null
                    : members.LastOrDefault(m => m.Start <= i && i <= m.End);
                bool gated = owner is not null
                    && BodyWithCallees(lines, members, owner).Contains(GateCall, StringComparison.Ordinal);
                if (!gated)
                {
                    string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                    failures.Add($"{rel}:{i + 1} INSERT INTO {table} in {owner?.Name ?? "<no member>"}");
                }
            }
        }

        return failures;
    }

    /// <summary>
    /// Tables <c>RevokeTenantAccessAsync</c> deletes from, directly or through the
    /// <c>OrgRepository</c> helpers it calls.
    /// </summary>
    internal static IReadOnlySet<string> RevokedTables(string orgRepositorySource)
    {
        string[] lines = orgRepositorySource.Split('\n');
        var members = Members(lines);
        var revoke = members.Where(m => m.Name == "RevokeTenantAccessAsync").ToList();
        Assert.True(revoke.Count == 1,
            $"Expected exactly one RevokeTenantAccessAsync in OrgRepository, found {revoke.Count}.");

        return DeleteRegex().Matches(BodyWithCallees(lines, members, revoke[0]))
            .Select(m => m.Groups["table"].Value.ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);
    }

    private static string OrgRepositorySource()
    {
        var files = SourceRoots.AllCSharpFiles()
            .Where(f => Path.GetFileName(f) == "OrgRepository.cs")
            .ToList();
        Assert.True(files.Count == 1, $"Expected exactly one OrgRepository.cs under src/, found {files.Count}.");
        return File.ReadAllText(files[0]);
    }

    [Fact]
    public void CredentialTableDerivation_FindsEveryKnownCredentialTable()
    {
        var derived = CredentialTables();

        var missing = KnownCredentialTables.Where(t => !derived.Contains(t)).ToList();
        Assert.True(missing.Count == 0,
            "The token_hash + tenant-column derivation over Schema.sql no longer finds: " + string.Join(", ", missing));
    }

    [Fact]
    public void EveryCredentialTable_IsDeletedByTheTenantLockoutRevoke()
    {
        var revoked = RevokedTables(OrgRepositorySource());

        var missing = CredentialTables().Where(t => !revoked.Contains(t)).ToList();
        Assert.True(missing.Count == 0,
            "A tenant lockout must delete every credential the tenant holds, or the credential survives the " +
            "suspension and works again on restore. Add a DELETE for each table below to " +
            "OrgRepository.RevokeTenantAccessAsync (or a helper it calls):\n  " + string.Join("\n  ", missing));
    }

    [Fact]
    public void EveryCredentialInsert_RunsTheTenantMintGate()
    {
        var failures = UngatedInserts(SourceRoots.AllCSharpFiles(), [.. CredentialTables()]);

        Assert.True(failures.Count == 0,
            "A credential minted after a suspension's revoke survives it. Call TenantMintGate.RequireMintableAsync " +
            "inside the INSERT's transaction (in the same method, or a same-file method it calls), or put " +
            $"`// mint-ok: <reason>` within {MarkerWindow} lines above the INSERT:\n  " + string.Join("\n  ", failures));
    }

    [Fact]
    public void TheInsertScan_FlagsAnUngatedInsert_AndHonoursTheMarkerAndACalleeGate()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"mint-gate-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            string ungated = Path.Combine(dir, "Ungated.cs");
            File.WriteAllText(ungated, """
                namespace X;

                public sealed class Ungated
                {
                    public async Task MintAsync()
                    {
                        await conn.ExecuteAsync("INSERT INTO invites (id) VALUES (@id)");
                    }
                }
                """);
            string viaCallee = Path.Combine(dir, "ViaCallee.cs");
            File.WriteAllText(viaCallee, """
                namespace X;

                public sealed class ViaCallee
                {
                    public async Task MintAsync()
                    {
                        await InsertGatedAsync("INSERT INTO invites (id) VALUES (@id)");
                    }

                    private async Task InsertGatedAsync(string sql)
                    {
                        await TenantMintGate.RequireMintableAsync(conn, provider, orgId, tx, ct);
                    }
                }
                """);
            string marked = Path.Combine(dir, "Marked.cs");
            File.WriteAllText(marked, """
                namespace X;

                public sealed class Marked
                {
                    public async Task SeedAsync()
                    {
                        // mint-ok: boot-time seed
                        await conn.ExecuteAsync("INSERT INTO invites (id) VALUES (@id)");
                    }
                }
                """);
            string proseOnly = Path.Combine(dir, "ProseOnly.cs");
            File.WriteAllText(proseOnly, """
                namespace X;

                public sealed class ProseOnly
                {
                    public async Task MintAsync()
                    {
                        // TenantMintGate.RequireMintableAsync( is named here only in a comment.
                        await conn.ExecuteAsync("INSERT INTO invites (id) VALUES (@id)");
                    }
                }
                """);

            var failures = UngatedInserts([ungated, viaCallee, marked, proseOnly], ["invites"]);

            Assert.Equal(2, failures.Count);
            Assert.Contains(failures, f => f.Contains("Ungated.cs", StringComparison.Ordinal));
            Assert.Contains(failures, f => f.Contains("ProseOnly.cs", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // Writes one synthetic source file and runs the INSERT scan over it alone.
    private static IReadOnlyList<string> ScanSource(string source)
    {
        string dir = Path.Combine(Path.GetTempPath(), $"mint-gate-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            string file = Path.Combine(dir, "Synthetic.cs");
            File.WriteAllText(file, source);
            return UngatedInserts([file], ["invites"]);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// Overloads share a name, so a method's own declaration line must not count as a call to its
    /// overloads: an ungated overload beside a gated one is still ungated.
    /// </summary>
    [Fact]
    public void TheInsertScan_FlagsAnUngatedOverload_BesideAGatedOne()
    {
        var failures = ScanSource("""
            namespace X;

            public sealed class Repo
            {
                public async Task IssueAsync(string orgId)
                {
                    await TenantMintGate.RequireMintableAsync(conn, provider, orgId, tx, ct);
                    await conn.ExecuteAsync("INSERT INTO invites (id) VALUES (@id)");
                }

                public async Task IssueAsync(string orgId, TimeSpan ttl)
                {
                    await conn.ExecuteAsync("INSERT INTO invites (id) VALUES (@id)");
                }
            }
            """);

        Assert.EndsWith("Synthetic.cs:13 INSERT INTO invites in IssueAsync", Assert.Single(failures), StringComparison.Ordinal);
    }

    /// <summary>A delegating overload that calls the gated one by name still passes.</summary>
    [Fact]
    public void TheInsertScan_AcceptsAnOverloadThatCallsTheGatedOne()
    {
        var failures = ScanSource("""
            namespace X;

            public sealed class Repo
            {
                public async Task IssueAsync(string orgId)
                {
                    await IssueAsync(orgId, "INSERT INTO invites (id) VALUES (@id)");
                }

                private async Task IssueAsync(string orgId, string sql)
                {
                    await TenantMintGate.RequireMintableAsync(conn, provider, orgId, tx, ct);
                    await conn.ExecuteAsync(sql);
                }
            }
            """);

        Assert.Empty(failures);
    }

    /// <summary>An INSERT whose table name sits on the line after <c>INSERT INTO</c> is still seen.</summary>
    [Fact]
    public void TheInsertScan_FlagsAnInsertSplitAcrossLines()
    {
        var failures = ScanSource(""""
            namespace X;

            public sealed class Repo
            {
                public async Task MintAsync()
                {
                    await conn.ExecuteAsync(
                        """
                        INSERT INTO
                            invites (id) VALUES (@id)
                        """);
                }
            }
            """");

        Assert.EndsWith("Synthetic.cs:9 INSERT INTO invites in MintAsync", Assert.Single(failures), StringComparison.Ordinal);
    }

    /// <summary>
    /// A one-line expression-bodied method is not a block the extent scan can bound, so its INSERT
    /// must fail closed rather than be credited to the gated member above it.
    /// </summary>
    [Fact]
    public void TheInsertScan_FlagsAnUngatedOneLineExpressionBodiedMethod_AfterAGatedOne()
    {
        var failures = ScanSource("""
            namespace X;

            public sealed class Repo
            {
                public async Task GatedAsync()
                {
                    await TenantMintGate.RequireMintableAsync(conn, provider, orgId, tx, ct);
                }

                public Task MintAsync() => conn.ExecuteAsync("INSERT INTO invites (id) VALUES (@id)");
            }
            """);

        Assert.Single(failures);
        Assert.Contains("Synthetic.cs:10 INSERT INTO invites in <no member>", failures[0], StringComparison.Ordinal);
    }

    [Fact]
    public void TheRevokeScan_FollowsHelpers_AndMissesATableNoDeleteNames()
    {
        const string source = """
            public sealed class OrgRepository
            {
                private static async Task RevokeTenantAccessAsync(DbConnection conn)
                {
                    await RevokeSessionsAsync(conn);
                    await conn.ExecuteAsync("DELETE FROM invites WHERE org_id = @orgId");
                }

                private static async Task RevokeSessionsAsync(DbConnection conn)
                {
                    await conn.ExecuteAsync("DELETE FROM mfa_trusted_devices WHERE tenant_id = @orgId");
                }

                public async Task UnrelatedAsync()
                {
                    await conn.ExecuteAsync("DELETE FROM user_tokens WHERE org_id = @orgId");
                }
            }
            """;

        var revoked = RevokedTables(source);

        Assert.Contains("invites", revoked);
        Assert.Contains("mfa_trusted_devices", revoked);
        Assert.DoesNotContain("user_tokens", revoked);
    }
}
