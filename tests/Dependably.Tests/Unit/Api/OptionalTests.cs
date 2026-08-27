using System.Text.Json;
using Dependably.Api;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pins the tri-state <see cref="Optional{T}"/> contract end to end through System.Text.Json,
/// because the whole type exists for one distinction a plain nullable cannot make: a field the
/// client never mentioned versus a field the client explicitly cleared.
///
/// <para>That distinction is load-bearing on <c>PUT /api/v1/proxy-settings</c>, where
/// <c>min_release_age_hours</c> and <c>max_epss_tolerance</c> have SQL NULL as a real domain value
/// meaning "gate off". Collapsing the two states there would make an unrelated PUT silently
/// disable a gate, so these assertions are about the security posture, not the serializer.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class OptionalTests
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private sealed record Body(Optional<int?> Hours, Optional<double?> Score, Optional<string> Name);

    [Fact]
    public void AnAbsentFieldDeserializesAsAbsent()
    {
        var body = JsonSerializer.Deserialize<Body>("""{}""", Web)!;

        Assert.False(body.Hours.IsPresent);
        Assert.False(body.Score.IsPresent);
        Assert.False(body.Name.IsPresent);
    }

    [Fact]
    public void AnExplicitNullIsPresentWithANullValue()
    {
        // This is the arm that matters: "clear the gate" arrives as an explicit null and must NOT
        // read the same as an omitted field, which means leave-unchanged.
        var body = JsonSerializer.Deserialize<Body>("""{"hours":null,"score":null}""", Web)!;

        Assert.True(body.Hours.IsPresent);
        Assert.Null(body.Hours.Value);
        Assert.True(body.Score.IsPresent);
        Assert.Null(body.Score.Value);
        Assert.False(body.Name.IsPresent);
    }

    [Fact]
    public void AValueIsPresentWithThatValue()
    {
        var body = JsonSerializer.Deserialize<Body>("""{"hours":24,"score":0.5,"name":"x"}""", Web)!;

        Assert.True(body.Hours.IsPresent);
        Assert.Equal(24, body.Hours.Value);
        Assert.Equal(0.5, body.Score.Value);
        Assert.Equal("x", body.Name.Value);
    }

    [Fact]
    public void ZeroIsAValue_NotAnAbsence()
    {
        // A truthiness-based implementation would lose this: 0 hours is a real setting.
        var body = JsonSerializer.Deserialize<Body>("""{"hours":0}""", Web)!;

        Assert.True(body.Hours.IsPresent);
        Assert.Equal(0, body.Hours.Value);
    }

    [Fact]
    public void AbsentAndOfBuildTheSameStatesTheWireProduces()
    {
        Assert.False(Optional<int?>.Absent.IsPresent);
        Assert.Null(Optional<int?>.Absent.Value);

        var explicitNull = Optional<int?>.Of(null);
        Assert.True(explicitNull.IsPresent);
        Assert.Null(explicitNull.Value);

        var withValue = Optional<int?>.Of(12);
        Assert.True(withValue.IsPresent);
        Assert.Equal(12, withValue.Value);
    }

    [Fact]
    public void DefaultIsAbsent()
    {
        // System.Text.Json never invokes the converter for a missing key, so the default-constructed
        // struct IS the absent state. If that stopped being true, every omitted field would start
        // reading as an explicit clear.
        Optional<string> uninitialized = default;

        Assert.False(uninitialized.IsPresent);
    }

    [Fact]
    public void SerializesPresentValuesAndWritesNullForAbsent()
    {
        string json = JsonSerializer.Serialize(
            new Body(Optional<int?>.Of(3), Optional<double?>.Absent, Optional<string>.Of(null)), Web);

        using var doc = JsonDocument.Parse(json);
        Assert.Equal(3, doc.RootElement.GetProperty("hours").GetInt32());
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("score").ValueKind);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("name").ValueKind);
    }

    [Fact]
    public void TheFactoryConvertsOptionalAndNothingElse()
    {
        var factory = new OptionalJsonConverterFactory();

        Assert.True(factory.CanConvert(typeof(Optional<int>)));
        Assert.True(factory.CanConvert(typeof(Optional<string>)));
        Assert.False(factory.CanConvert(typeof(int)));
        Assert.False(factory.CanConvert(typeof(string)));
        Assert.False(factory.CanConvert(typeof(Nullable<int>)));
        Assert.False(factory.CanConvert(typeof(List<int>)));

        Assert.NotNull(factory.CreateConverter(typeof(Optional<int>), Web));
    }

    [Fact]
    public void RoundTripsThroughTheFactoryForSeveralValueTypes()
    {
        Assert.Equal(5, JsonSerializer.Deserialize<Optional<int>>("5", Web).Value);
        Assert.Equal("s", JsonSerializer.Deserialize<Optional<string>>("\"s\"", Web).Value);
        Assert.True(JsonSerializer.Deserialize<Optional<bool>>("true", Web).Value);
    }
}
