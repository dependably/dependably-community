namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Pins what <see cref="CardinalityBudgetTests"/> can see: every attribute-construction form the
/// metrics API accepts is read, an unlisted name in any of them fails, and a key the scan cannot
/// read fails unless a reasoned <c>// cardinality-ok:</c> marker covers it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CardinalityBudgetScanFormTests
{
    // Declarations the fixtures lean on: an instrument field, and a src-style method returning TagList.
    private const string Declarations = """
        static class Meters
        {
            public static readonly Counter<long> Requests = null!;
            public static readonly Histogram<double> Latency = null!;
        }

        sealed class Message
        {
            public TagList MetricTags() => default;
        }
        """;

    public static TheoryData<string, string> UnlistedNameInEachForm => new()
    {
        {
            "TagList.Add on a new TagList",
            """
            var tags = new TagList();
            tags.Add("unlisted", value);
            """
        },
        {
            "TagList.Add on a declared TagList",
            """
            TagList tags = default;
            tags.Add("unlisted", value);
            """
        },
        {
            "TagList.Add with a named key argument",
            """
            var tags = new TagList();
            tags.Add(key: "unlisted", value: value);
            """
        },
        {
            "TagList.Add on a TagList returned by a src method",
            """
            var tags = message.MetricTags();
            tags.Add("unlisted", value);
            """
        },
        {
            "TagList.Add on an alias of a TagList",
            """
            var tags = message.MetricTags();
            var failed = tags;
            failed.Add("unlisted", value);
            """
        },
        {
            "TagList.Add with a target-typed pair",
            """
            var tags = new TagList();
            tags.Add(new("unlisted", value));
            """
        },
        {
            "TagList.Add with an explicit pair",
            """
            var tags = new TagList { new KeyValuePair<string, object?>("scope", scope) };
            tags.Add(new KeyValuePair<string, object?>("unlisted", value));
            """
        },
        {
            "TagList collection initializer, key/value element",
            """
            var tags = new TagList { { "unlisted", value } };
            """
        },
        {
            "TagList collection initializer, target-typed element",
            """
            var tags = new TagList() { new("unlisted", value) };
            """
        },
        {
            "TagList target-typed initializer",
            """
            TagList tags = new() { { "unlisted", value } };
            """
        },
        {
            "TagList collection expression",
            """
            TagList tags = [new("unlisted", value)];
            """
        },
        {
            "explicit KeyValuePair",
            """
            Meters.Requests.Add(1, new KeyValuePair<string, object?>("unlisted", value));
            """
        },
        {
            "explicit KeyValuePair with the key on the next line",
            """
            Meters.Requests.Add(1,
                new KeyValuePair<string, object?>(
                    "unlisted", value));
            """
        },
        {
            "KeyValuePair.Create",
            """
            Meters.Requests.Add(1, KeyValuePair.Create("unlisted", (object?)value));
            """
        },
        {
            "KeyValuePair.Create with type arguments",
            """
            Meters.Requests.Add(1, KeyValuePair.Create<string, object?>("unlisted", value));
            """
        },
        {
            "target-typed pair passed to Counter.Add",
            """
            Meters.Requests.Add(1, new("unlisted", value));
            """
        },
        {
            "target-typed pair passed to Histogram.Record via ?.",
            """
            Meters.Latency?.Record(0.5, new("ecosystem", "npm"), new("unlisted", value));
            """
        },
        {
            "collection expression passed to an instrument",
            """
            Meters.Requests.Add(1, [new("unlisted", value)]);
            """
        },
        {
            "target-typed pair in a Measurement",
            """
            yield return new Measurement<long>(1, new("unlisted", value));
            """
        },
        {
            "target-typed pair passed to DomainTimer.Start",
            """
            using var timer = DomainTimer.Start(Meters.Latency, null, new("unlisted", value));
            """
        },
        {
            "target-typed pair in a KeyValuePair array initializer",
            """
            var tags = new KeyValuePair<string, object?>[] { new("unlisted", value) };
            """
        },
        {
            "target-typed pair in a KeyValuePair array collection expression",
            """
            KeyValuePair<string, object?>[] tags = [new("unlisted", value)];
            """
        },
        {
            "target-typed pair in a List<KeyValuePair> initializer",
            """
            List<KeyValuePair<string, object?>> tags = new() { new("unlisted", value) };
            """
        },
        {
            "target-typed pair in an instrument factory's tags",
            """
            var c = meter.CreateCounter<long>("x", null, null, [new("unlisted", value)]);
            """
        },
    };

    [Theory]
    [MemberData(nameof(UnlistedNameInEachForm))]
    public void UnlistedLiteralName_IsFlagged_InEveryForm(string form, string body)
    {
        var violations = Violations(body);

        Assert.True(
            violations.Count == 1 && violations[0].Contains("\"unlisted\" is not in the allowlist", StringComparison.Ordinal),
            $"{form}: expected exactly one unlisted-name violation, got:\n  {string.Join("\n  ", violations)}");
    }

    [Theory]
    [MemberData(nameof(UnlistedNameInEachForm))]
    public void AllowlistedLiteralName_Passes_InEveryForm(string form, string body)
    {
        var violations = Violations(body.Replace("\"unlisted\"", "\"ecosystem\"", StringComparison.Ordinal));

        Assert.True(violations.Count == 0, $"{form}: unexpected violations:\n  {string.Join("\n  ", violations)}");
    }

    public static TheoryData<string, string> NonLiteralKeys => new()
    {
        { "constant", "tags.Add(AttributeName, value);" },
        { "member access", "tags.Add(Names.Tenant, value);" },
        { "nameof", "tags.Add(nameof(tenantEmail), value);" },
        { "interpolation", "tags.Add($\"{prefix}_id\", value);" },
        { "escaped literal", "tags.Add(\"tenant\\u005femail\", value);" },
        { "pair variable as KeyValuePair key", "Meters.Requests.Add(1, new KeyValuePair<string, object?>(name, value));" },
        { "target-typed pair with variable key", "Meters.Requests.Add(1, new(name, value));" },
    };

    [Theory]
    [MemberData(nameof(NonLiteralKeys))]
    public void NonLiteralKey_WithoutMarker_IsFlagged(string form, string statement)
    {
        var violations = Violations("var tags = new TagList();\n" + statement);

        Assert.True(
            violations.Count == 1 && violations[0].Contains("is not a string literal", StringComparison.Ordinal),
            $"{form}: expected exactly one non-literal violation, got:\n  {string.Join("\n  ", violations)}");
    }

    [Theory]
    [MemberData(nameof(NonLiteralKeys))]
    public void NonLiteralKey_WithReasonedMarker_Passes(string form, string statement)
    {
        var violations = Violations(
            "var tags = new TagList();\n" +
            "// cardinality-ok: the value set is the fixed ecosystem vocabulary\n" +
            statement);

        Assert.True(violations.Count == 0, $"{form}: unexpected violations:\n  {string.Join("\n  ", violations)}");
    }

    [Fact]
    public void BareMarker_WithoutReason_IsNotHonoured()
    {
        var violations = Violations("""
            var tags = new TagList();
            // cardinality-ok:
            tags.Add(AttributeName, value);
            """);

        Assert.Single(violations);
    }

    [Fact]
    public void Marker_MoreThanFiveLinesAbove_IsNotHonoured()
    {
        var violations = Violations("""
            // cardinality-ok: too far away to cover the key below
            var tags = new TagList();
            int a = 1;
            int b = 2;
            int c = 3;
            int d = 4;
            tags.Add(AttributeName, value);
            """);

        Assert.Single(violations);
    }

    [Fact]
    public void Marker_DoesNotAdmitAnUnlistedLiteral()
    {
        var violations = Violations("""
            var tags = new TagList();
            // cardinality-ok: a marker never widens the allowlist
            tags.Add("tenant_email", value);
            """);

        Assert.Single(violations);
    }

    [Fact]
    public void Violation_ReportsTheKeyLine()
    {
        var context = MetricAttributeScanner.BuildContext([Declarations]);
        string source = "class C\n{\n    void M()\n    {\n        var tags = new TagList();\n        tags.Add(\"unlisted\", 1);\n    }\n}\n";

        var violations = CardinalityBudgetTests.FindViolations(source, context);

        Assert.StartsWith("6  ", Assert.Single(violations), StringComparison.Ordinal);
    }

    [Fact]
    public void Constructs_ThatAreNotMetricAttributes_AreNotRead()
    {
        // Claims built target-typed, span tags, Dapper parameters, dictionary adds, and pair
        // constructions that only appear inside a string or a comment.
        var violations = Violations("""
            var claims = new Claim[] { new("sub", userId), new("eml", email) };
            List<Claim> more = [new("tid", tenantId)];
            activity?.SetTag("dependably.tenant_id", tenantId);
            activity?.AddTag("dependably.purl", purl);
            parameters.Add("org_id", orgId);
            var headers = new Dictionary<string, string> { { "x-tenant", tenantId } };
            headers.Add("x-user", userId);
            string doc = "new KeyValuePair<string, object?>(\"tenant_id\", x)";
            // Meters.Requests.Add(1, new KeyValuePair<string, object?>("tenant_id", x));
            /* tags.Add("tenant_id", x); */
            """);

        Assert.True(violations.Count == 0, $"unexpected violations:\n  {string.Join("\n  ", violations)}");
    }

    private static List<string> Violations(string body)
    {
        string source = Declarations + "\nclass Fixture\n{\n    void M()\n    {\n" + body + "\n    }\n}\n";
        var context = MetricAttributeScanner.BuildContext([source]);
        return CardinalityBudgetTests.FindViolations(source, context).ToList();
    }
}
