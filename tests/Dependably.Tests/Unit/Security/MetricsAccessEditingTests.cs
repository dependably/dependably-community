using System.Text.Json;
using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The shared <c>/metrics</c> allowlist editing helpers (<see cref="MetricsAccessEditing"/>): the
/// first malformed entry rejects the request, an all addresses entry is accepted with a warning,
/// and the env locked conflict body carries the field and the variable that locks it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetricsAccessEditingTests
{
    [Fact]
    public void Well_formed_entries_return_no_invalid_entry_and_no_warning()
    {
        var warnings = new List<string>();

        string? invalid = MetricsAccessEditing.FindInvalidEntry(["10.0.0.0/8", "192.168.1.0/24", "fd00::/8"], warnings);

        Assert.Null(invalid);
        Assert.Empty(warnings);
    }

    [Fact]
    public void First_malformed_entry_is_returned()
    {
        var warnings = new List<string>();

        string? invalid = MetricsAccessEditing.FindInvalidEntry(["10.0.0.0/8", "not-a-cidr", "also-not-a-cidr"], warnings);

        Assert.Equal("not-a-cidr", invalid);
    }

    [Fact]
    public void All_addresses_entries_are_accepted_with_one_warning_each()
    {
        var warnings = new List<string>();

        string? invalid = MetricsAccessEditing.FindInvalidEntry(["0.0.0.0/0", "10.0.0.0/8", "::/0"], warnings);

        Assert.Null(invalid);
        Assert.Equal(2, warnings.Count);
        Assert.Contains("\"0.0.0.0/0\"", warnings[0], StringComparison.Ordinal);
        Assert.Contains("\"::/0\"", warnings[1], StringComparison.Ordinal);
    }

    [Fact]
    public void Scan_stops_at_the_malformed_entry()
    {
        var warnings = new List<string>();

        string? invalid = MetricsAccessEditing.FindInvalidEntry(["not-a-cidr", "0.0.0.0/0"], warnings);

        Assert.Equal("not-a-cidr", invalid);
        Assert.Empty(warnings);
    }

    [Fact]
    public void Env_locked_conflict_body_names_the_field_and_the_variable()
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(
            MetricsAccessEditing.EnvLockedConflictBody("metrics_allowed_cidrs", "DEPENDABLY_METRICS_ALLOWED_CIDRS")));
        var root = doc.RootElement;

        Assert.Equal("/problems/env-var-locked", root.GetProperty("type").GetString());
        Assert.Equal("metrics_allowed_cidrs is locked by env var", root.GetProperty("title").GetString());
        Assert.Equal(
            "DEPENDABLY_METRICS_ALLOWED_CIDRS is set; unset the env var to manage via UI.",
            root.GetProperty("detail").GetString());
    }
}
