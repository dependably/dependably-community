using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the outbound-egress invariant: every HTTP handler this process constructs
/// dials through the SSRF connect gate, follows no redirects, and bypasses any ambient proxy.
///
/// <para>
/// <b>Why the proxy clause is part of the same invariant.</b> <see cref="SocketsHttpHandler.ConnectCallback"/>
/// is the authoritative SSRF gate only while the handler dials the target directly. When a proxy is
/// in effect the handler invokes the callback with the <em>proxy</em>'s endpoint, so
/// <c>SsrfGuard.IsBlockedIp</c> vets the proxy's address, passes it, and the proxy then resolves and
/// fetches the target on this process's behalf — the gate returns "allowed" while the request it was
/// guarding reaches a private host. <c>UseProxy</c> defaults to <see langword="true"/> and a null
/// <c>Proxy</c> falls back to <c>HttpClient.DefaultProxy</c>, which on Unix is built from the ambient
/// <c>HTTP_PROXY</c>/<c>HTTPS_PROXY</c>/<c>ALL_PROXY</c> environment variables. So a handler that sets
/// <c>ConnectCallback</c> but not <c>UseProxy = false</c> is guarded on an operator's laptop and
/// unguarded in any environment that exports one of those variables — the failure is invisible in
/// code review and invisible in tests that do not set the variable. Requiring the pair is what makes
/// the guarantee unconditional.
/// </para>
///
/// <para>
/// A deliberate exception opts out with an <c>// egress-ok: &lt;reason&gt;</c> marker in the 5 lines
/// above the construction (or above the <c>AddHttpClient</c> call), matching the
/// <c>// xtenant:</c> / <c>// rawsql:</c> / <c>// blobkey-ok:</c> convention. A bare marker with no
/// stated reason is malformed and is never honoured. An egress proxy is a legitimate deployment
/// topology — this gate does not forbid one, it forbids acquiring one <em>silently</em> from the
/// ambient environment on a handler whose whole purpose is to constrain where it connects. Supporting
/// a proxy deliberately means validating <c>request.RequestUri</c> per hop in a
/// <c>DelegatingHandler</c> and pinning the proxy authority, then taking the marker.
/// </para>
///
/// <para>
/// <b>Known limitations, stated plainly:</b> this is a source scan, not a semantic one. It matches an
/// object-initializer block by brace counting from <c>new … SocketsHttpHandler</c>, so a handler built
/// field-by-field after construction, returned from a helper factory, or configured through
/// <c>ConfigureHttpMessageHandlerBuilder</c> is invisible to it — as is any brace appearing inside a
/// string literal within an initializer (none exists today). It proves the properties are
/// <em>assigned the required values in source</em>; it cannot prove the <c>ConnectCallback</c> assigned
/// is a real <c>SsrfConnectCallback</c> rather than a permissive test double, which is exactly the
/// substitution <c>DefaultHttpClientSsrfGuardTests</c> relies on. The second test's statement extraction
/// stops at the first <c>;</c> at depth zero, so a registration split across two statements
/// (<c>var b = services.AddHttpClient(…); b.ConfigurePrimaryHttpMessageHandler(…);</c>) would false-flag
/// and need a marker.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class OutboundHttpHandlerComplianceTests
{
    private const string Marker = "egress-ok:";
    private const int MarkerWindow = 5;

    /// <summary>Properties every SSRF-guarded handler must assign, and the value each must carry.</summary>
    private static readonly (string Property, string Required)[] RequiredAssignments =
    [
        ("UseProxy", "false"),
        ("AllowAutoRedirect", "false"),
    ];

    [GeneratedRegex(@"new\s+(?:[\w.]+\.)?SocketsHttpHandler\b")]
    private static partial Regex HandlerCtor();

    [GeneratedRegex(@"new\s+(?:[\w.]+\.)?HttpClientHandler\b")]
    private static partial Regex HttpClientHandlerCtor();

    // AddHttpClient( or AddHttpClient<T>( — deliberately not AddHttpClientInstrumentation, which is
    // OpenTelemetry wiring and registers no handler.
    [GeneratedRegex(@"\.AddHttpClient\s*(?:<[^>]*>\s*)?\(")]
    private static partial Regex AddHttpClientCall();

    private readonly ITestOutputHelper _output;
    public OutboundHttpHandlerComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryOutboundHandlerBypassesAmbientProxyAndIsSsrfGuarded()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string text = File.ReadAllText(file);
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);

            foreach (Match m in HandlerCtor().Matches(text))
            {
                if (HasMarkerAbove(text, m.Index))
                {
                    continue;
                }

                int line = LineOf(text, m.Index);
                string? block = InitializerBlock(text, m.Index + m.Length);

                if (block is null)
                {
                    violations.Add($"{rel}:{line}: SocketsHttpHandler constructed with no object " +
                                   $"initializer — cannot carry the required SSRF/proxy posture.");
                    continue;
                }

                foreach ((string property, string required) in RequiredAssignments)
                {
                    if (!AssignsValue(block, property, required))
                    {
                        violations.Add($"{rel}:{line}: SocketsHttpHandler does not set " +
                                       $"{property} = {required}.");
                    }
                }

                if (!block.Contains("ConnectCallback", StringComparison.Ordinal))
                {
                    violations.Add($"{rel}:{line}: SocketsHttpHandler sets no ConnectCallback — " +
                                   $"the connect-time SSRF gate is absent.");
                }
            }

            // HttpClientHandler cannot carry a ConnectCallback at all, so it can never satisfy the
            // invariant. None exists today; the check keeps it that way.
            foreach (Match m in HttpClientHandlerCtor().Matches(text))
            {
                if (!HasMarkerAbove(text, m.Index))
                {
                    violations.Add($"{rel}:{LineOf(text, m.Index)}: HttpClientHandler cannot carry a " +
                                   $"ConnectCallback — use SocketsHttpHandler so the SSRF gate applies.");
                }
            }
        }

        Assert.True(violations.Count == 0, Report(violations,
            "Outbound HTTP handler(s) missing the required egress posture"));
    }

    [Fact]
    public void EveryAddHttpClientRegistrationConfiguresItsPrimaryHandler()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string text = File.ReadAllText(file);
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);

            foreach (Match m in AddHttpClientCall().Matches(text))
            {
                if (HasMarkerAbove(text, m.Index))
                {
                    continue;
                }

                string statement = StatementFrom(text, m.Index);
                if (!statement.Contains("ConfigurePrimaryHttpMessageHandler", StringComparison.Ordinal))
                {
                    violations.Add($"{rel}:{LineOf(text, m.Index)}: AddHttpClient registration does not " +
                                   $"chain ConfigurePrimaryHttpMessageHandler — its handler would be left " +
                                   $"at framework defaults, with no SSRF connect gate and an ambient proxy.");
                }
            }
        }

        Assert.True(violations.Count == 0, Report(violations,
            "AddHttpClient registration(s) leaving the primary handler unconfigured"));
    }

    [Fact]
    public void EveryEgressOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);
            string[] lines = File.ReadAllLines(file);

            for (int i = 0; i < lines.Length; i++)
            {
                int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
                if (at < 0)
                {
                    continue;
                }

                if (lines[i][(at + Marker.Length)..].Trim().Length == 0)
                {
                    violations.Add($"{rel}:{i + 1}: bare '{Marker}' marker with no stated reason.");
                }
            }
        }

        Assert.True(violations.Count == 0, Report(violations, "Malformed egress-ok marker(s)"));
    }

    /// <summary>Does <paramref name="block"/> assign <paramref name="property"/> exactly <paramref name="required"/>?</summary>
    private static bool AssignsValue(string block, string property, string required) =>
        Regex.IsMatch(block, $@"\b{Regex.Escape(property)}\s*=\s*{Regex.Escape(required)}\s*[,;}}]");

    /// <summary>
    /// The object-initializer block starting at the first <c>{</c> at or after <paramref name="from"/>,
    /// or null when the construction has no initializer. Brace-counted.
    /// </summary>
    private static string? InitializerBlock(string text, int from)
    {
        int open = from;
        while (open < text.Length && char.IsWhiteSpace(text[open]))
        {
            open++;
        }

        if (open >= text.Length || text[open] != '{')
        {
            return null;
        }

        int depth = 0;
        for (int i = open; i < text.Length; i++)
        {
            if (text[i] == '{')
            {
                depth++;
            }
            else if (text[i] == '}' && --depth == 0)
            {
                return text[open..(i + 1)];
            }
        }

        return null;
    }

    /// <summary>The fluent statement beginning at <paramref name="from"/>, up to the first <c>;</c> at depth zero.</summary>
    private static string StatementFrom(string text, int from)
    {
        int depth = 0;
        for (int i = from; i < text.Length; i++)
        {
            char c = text[i];
            if (c is '(' or '{' or '[')
            {
                depth++;
            }
            else if (c is ')' or '}' or ']')
            {
                depth--;
            }
            else if (c == ';' && depth <= 0)
            {
                return text[from..i];
            }
        }

        return text[from..];
    }

    private static bool HasMarkerAbove(string text, int index)
    {
        int line = LineOf(text, index);
        string[] lines = text.Split('\n');
        int first = Math.Max(0, line - 1 - MarkerWindow);

        for (int i = first; i < line && i < lines.Length; i++)
        {
            int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
            if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static int LineOf(string text, int index) => 1 + text.AsSpan(0, index).Count('\n');

    private string Report(List<string> violations, string headline)
    {
        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        return $"{headline} ({violations.Count}):{Environment.NewLine}" +
               string.Join(Environment.NewLine, violations);
    }
}
