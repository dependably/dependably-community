using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Locks the canonical Serilog message-template property names documented in
/// <c>dependably-enterprise/docs/observability/taxonomy.md</c>. Any banned
/// synonym in a <c>{Token}</c> message-template form fails the build with a
/// pointer to the canonical replacement.
///
/// <para>
/// The scan covers every <c>src/Dependably*</c> source root via
/// <see cref="SourceRoots.AllCSharpFiles"/>: the logging code lives in
/// <c>Dependably.Core</c> and <c>Dependably.Management</c>, so a gate anchored on a single
/// project directory would read as comprehensive while scanning almost nothing.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class LogPropertyDriftTests
{
    private static readonly Dictionary<string, string> Banned = new(StringComparer.Ordinal)
    {
        ["tenant_id"] = "TenantId",
        ["Tenant_Id"] = "TenantId",
        ["TenantID"] = "TenantId",
        ["tenantId"] = "TenantId",
        ["tenantid"] = "TenantId",
        ["org_id"] = "OrgId",
        ["Org_Id"] = "OrgId",
        ["OrgID"] = "OrgId",
        ["orgId"] = "OrgId",
        ["orgid"] = "OrgId",
        ["trace_id"] = "TraceId",
        ["TraceID"] = "TraceId",
        ["traceId"] = "TraceId",
        ["span_id"] = "SpanId",
        ["SpanID"] = "SpanId",
        ["spanId"] = "SpanId",
        ["ecosystem_id"] = "Ecosystem",
    };

    [Fact]
    public void NoBannedPropertyNamesInLogTemplates()
    {
        var violations = new List<string>();

        var scanned = SourceRoots.AllCSharpFiles().Where(f =>
            !f.EndsWith(".g.cs", StringComparison.Ordinal)
            && !f.EndsWith(".AssemblyInfo.cs", StringComparison.Ordinal));

        foreach (string file in scanned)
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);

                // Pattern A — message-template tokens like `{tenant_id}` inside a logger call.
                if (IsLoggerCallLine(line))
                {
                    foreach (var (bad, canonical) in Banned)
                    {
                        string token = "{" + bad + "}";
                        if (line.Contains(token, StringComparison.Ordinal))
                        {
                            violations.Add($"{rel}:{i + 1}  uses {token} — use {{{canonical}}} instead");
                        }
                    }
                }

                // Pattern B — LogContext.PushProperty("name", …) calls with a banned name.
                if (line.Contains("PushProperty(\"", StringComparison.Ordinal))
                {
                    foreach (var (bad, canonical) in Banned)
                    {
                        string token = $"PushProperty(\"{bad}\"";
                        if (line.Contains(token, StringComparison.Ordinal))
                        {
                            violations.Add($"{rel}:{i + 1}  pushes \"{bad}\" — use \"{canonical}\" instead");
                        }
                    }
                }
            }
        }

        Assert.True(
            violations.Count == 0,
            "Log-property drift detected. Canonical names live in " +
            "dependably-enterprise/docs/observability/taxonomy.md.\n  " +
            string.Join("\n  ", violations));
    }

    // Heuristic: only flag a banned-token occurrence if the same line looks
    // like a Microsoft.Extensions.Logging or Serilog call. Filters out C#
    // string-interpolation usages like `$"hosted/{orgId}/…"` that happen to
    // share token syntax with Serilog message templates.
    private static bool IsLoggerCallLine(string line)
        => line.Contains("_logger.Log", StringComparison.Ordinal)
        || line.Contains("logger.Log", StringComparison.Ordinal)
        || line.Contains("Log.Information", StringComparison.Ordinal)
        || line.Contains("Log.Warning", StringComparison.Ordinal)
        || line.Contains("Log.Error", StringComparison.Ordinal)
        || line.Contains("Log.Debug", StringComparison.Ordinal)
        || line.Contains("Log.Trace", StringComparison.Ordinal)
        || line.Contains("Log.Critical", StringComparison.Ordinal)
        || line.Contains("Log.Fatal", StringComparison.Ordinal);
}
