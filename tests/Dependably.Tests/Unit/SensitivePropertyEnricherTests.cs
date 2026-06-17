using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace Dependably.Tests.Unit;

/// <summary>
/// The enricher rewrites sensitive top-level property values to "[REDACTED]" before
/// Serilog renders them; the destructuring policy does the same for members of
/// destructured objects. Both share the <see cref="SensitiveLogKeys"/> classifier:
/// case-insensitive substring matching over credential keywords, with an allowlist
/// so operational identifiers (blob keys, token ids) stay visible.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SensitivePropertyEnricherTests
{
    private static LogEvent BuildEvent(IReadOnlyDictionary<string, object?> properties)
    {
        var template = new MessageTemplateParser().Parse("test");
        var props = properties.Select(kv =>
            new LogEventProperty(kv.Key, new ScalarValue(kv.Value))).ToArray();
        return new LogEvent(TestTime.KnownNow, LogEventLevel.Information, exception: null,
            template, props);
    }

    private sealed class CapturingFactory : ILogEventPropertyFactory
    {
        public LogEventProperty CreateProperty(string name, object? value, bool destructureObjects = false)
            => new(name, new ScalarValue(value));
    }

    [Theory]
    // Exact keyword names.
    [InlineData("password")]
    [InlineData("token")]
    [InlineData("secret")]
    [InlineData("authorization")]
    [InlineData("cookie")]
    [InlineData("jwt_secret")]
    [InlineData("bearer")]
    [InlineData("credential")]
    // Substring + case-insensitive variants the exact-name matcher misses.
    [InlineData("Link")]
    [InlineData("InviteLink")]
    [InlineData("RawToken")]
    [InlineData("ApiKey")]
    [InlineData("api_key")]
    [InlineData("X-NuGet-ApiKey")]
    [InlineData("ConnectionString")]
    [InlineData("connection_string")]
    [InlineData("BearerToken")]
    [InlineData("UserPassword")]
    [InlineData("ClientSecret")]
    [InlineData("ProxyAuthorization")]
    [InlineData("SetCookie")]
    [InlineData("AwsCredentials")]
    public void Enrich_ReplacesSensitiveValueWithRedacted(string key)
    {
        var evt = BuildEvent(new Dictionary<string, object?> { [key] = "the-real-thing" });
        new SensitivePropertyEnricher().Enrich(evt, new CapturingFactory());

        var actual = evt.Properties[key];
        Assert.Equal("\"[REDACTED]\"", actual.ToString());
    }

    [Theory]
    // Operational identifiers that contain a keyword substring but never carry a
    // credential — deliberately allowlisted so storage/eviction logs stay readable.
    [InlineData("BlobKey")]
    [InlineData("blobKey")]
    [InlineData("Key")]
    [InlineData("key")]
    [InlineData("Keys")]
    [InlineData("versionKey")]
    [InlineData("KeyPrefix")]
    [InlineData("CacheKey")]
    [InlineData("PartitionKey")]
    [InlineData("RowKey")]
    [InlineData("TokenId")]
    [InlineData("TokenCount")]
    // Names with no keyword at all.
    [InlineData("org")]
    [InlineData("user_id")]
    [InlineData("Email")]
    [InlineData("Purl")]
    public void Enrich_LeavesOperationalAndPlainNamesUntouched(string key)
    {
        var evt = BuildEvent(new Dictionary<string, object?> { [key] = "operational-value" });
        new SensitivePropertyEnricher().Enrich(evt, new CapturingFactory());

        Assert.Equal("\"operational-value\"", evt.Properties[key].ToString());
    }

    [Fact]
    public void Enrich_RedactsOnlySensitiveKeysInMixedEvent()
    {
        var evt = BuildEvent(new Dictionary<string, object?>
        {
            ["org"] = "acme",
            ["BlobKey"] = "proxy/sha256/abc",
            ["password"] = "secret-value",
            ["InviteLink"] = "https://example/join?token=raw",
        });
        new SensitivePropertyEnricher().Enrich(evt, new CapturingFactory());

        Assert.Equal("\"acme\"", evt.Properties["org"].ToString());
        Assert.Equal("\"proxy/sha256/abc\"", evt.Properties["BlobKey"].ToString());
        Assert.Equal("\"[REDACTED]\"", evt.Properties["password"].ToString());
        Assert.Equal("\"[REDACTED]\"", evt.Properties["InviteLink"].ToString());
    }

    [Fact]
    public void Enrich_NoSensitiveKeysPresent_NoOp()
    {
        var evt = BuildEvent(new Dictionary<string, object?> { ["foo"] = "bar" });
        new SensitivePropertyEnricher().Enrich(evt, new CapturingFactory());
        Assert.Equal("\"bar\"", evt.Properties["foo"].ToString());
    }

    private sealed record SampleCredentialBag(string OrgId, string RawToken, string BlobKey);

    [Fact]
    public void TryDestructure_RedactsSensitiveMembers_KeepsOperationalOnes()
    {
        var policy = new LogSanitizingDestructuringPolicy();
        var bag = new SampleCredentialBag("org-1", "tok_live_abc", "proxy/sha256/abc");

        bool handled = policy.TryDestructure(bag, new ValueFactory(), out var result);

        Assert.True(handled);
        var structure = Assert.IsType<StructureValue>(result);
        var members = structure.Properties.ToDictionary(p => p.Name, p => p.Value.ToString());
        Assert.Equal("\"org-1\"", members["OrgId"]);
        Assert.Equal("\"[REDACTED]\"", members["RawToken"]);
        Assert.Equal("\"proxy/sha256/abc\"", members["BlobKey"]);
    }

    [Fact]
    public void TryDestructure_RedactsSensitiveMembersOfAnonymousTypes()
    {
        var policy = new LogSanitizingDestructuringPolicy();
        var bag = new { Email = "a@b.c", Password = "hunter2" };

        bool handled = policy.TryDestructure(bag, new ValueFactory(), out var result);

        Assert.True(handled);
        var structure = Assert.IsType<StructureValue>(result);
        var members = structure.Properties.ToDictionary(p => p.Name, p => p.Value.ToString());
        Assert.Equal("\"a@b.c\"", members["Email"]);
        Assert.Equal("\"[REDACTED]\"", members["Password"]);
    }

    [Theory]
    [InlineData("plain string")]
    [InlineData(42)]
    public void TryDestructure_DefersScalarsToSerilog(object value)
    {
        var policy = new LogSanitizingDestructuringPolicy();
        bool handled = policy.TryDestructure(value, new ValueFactory(), out var result);
        Assert.False(handled);
        Assert.Null(result);
    }

    [Fact]
    public void TryDestructure_DefersCollectionsAndFrameworkTypesToSerilog()
    {
        var policy = new LogSanitizingDestructuringPolicy();

        Assert.False(policy.TryDestructure(new[] { "a", "b" }, new ValueFactory(), out _));
        Assert.False(policy.TryDestructure(new Dictionary<string, string> { ["token"] = "x" }, new ValueFactory(), out _));
        Assert.False(policy.TryDestructure(new Uri("https://example.test/"), new ValueFactory(), out _));
    }

    private sealed class ValueFactory : ILogEventPropertyValueFactory
    {
        public LogEventPropertyValue CreatePropertyValue(object? value, bool destructureObjects = false)
            => new ScalarValue(value);
    }
}
