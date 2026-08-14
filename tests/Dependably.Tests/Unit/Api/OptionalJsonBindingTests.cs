using System.Text.Json;
using Dependably.Api;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proves the tri-state JSON contract <see cref="Optional{T}"/> exists for — absent / explicit
/// null / explicit value — through real <see cref="JsonSerializer"/> deserialization rather than
/// hand-constructed instances, since the whole point of the type is what happens at the JSON
/// binder boundary. Exercised on <see cref="UpdateProxySettingsRequest"/> (the shipping
/// consumer) using <c>JsonSerializerDefaults.Web</c> — the same casing convention ASP.NET Core's
/// MVC input formatter uses for this DTO.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OptionalJsonBindingTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public void AbsentField_DeserializesToNotPresent()
    {
        var req = JsonSerializer.Deserialize<UpdateProxySettingsRequest>("{}", WebJson)!;

        Assert.False(req.MinReleaseAgeHours.IsPresent);
        Assert.False(req.MaxEpssTolerance.IsPresent);
    }

    [Fact]
    public void ExplicitNullField_DeserializesToPresentWithNullValue()
    {
        var req = JsonSerializer.Deserialize<UpdateProxySettingsRequest>(
            """{"minReleaseAgeHours":null,"maxEpssTolerance":null}""", WebJson)!;

        Assert.True(req.MinReleaseAgeHours.IsPresent);
        Assert.Null(req.MinReleaseAgeHours.Value);
        Assert.True(req.MaxEpssTolerance.IsPresent);
        Assert.Null(req.MaxEpssTolerance.Value);
    }

    [Fact]
    public void ExplicitValueField_DeserializesToPresentWithValue()
    {
        var req = JsonSerializer.Deserialize<UpdateProxySettingsRequest>(
            """{"minReleaseAgeHours":48,"maxEpssTolerance":0.3}""", WebJson)!;

        Assert.True(req.MinReleaseAgeHours.IsPresent);
        Assert.Equal(48, req.MinReleaseAgeHours.Value);
        Assert.True(req.MaxEpssTolerance.IsPresent);
        Assert.Equal(0.3, req.MaxEpssTolerance.Value);
    }

    [Fact]
    public void MixedPayload_OneAbsentOneExplicitNullOneValue_EachStateIndependent()
    {
        // Models a real-world partial PUT: a caller that mentions some fields and not others on
        // the same request. Each field's presence state is independent of the others.
        var req = JsonSerializer.Deserialize<UpdateProxySettingsRequest>(
            """{"blockKev":"block","maxEpssTolerance":null}""", WebJson)!;

        Assert.False(req.MinReleaseAgeHours.IsPresent);
        Assert.True(req.MaxEpssTolerance.IsPresent);
        Assert.Null(req.MaxEpssTolerance.Value);
        Assert.Equal("block", req.BlockKev);
    }
}
