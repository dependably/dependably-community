using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Resolves SharedResource strings through the real ResourceManagerStringLocalizer
/// (not a test stub) so a mismatch between the marker type's namespace, the
/// ResourcesPath option, and the embedded .resx base name fails loudly. When that
/// wiring is wrong the localizer silently returns raw keys like
/// "error.validation.title" to API clients.
/// </summary>
public class SharedResourceLocalizationTests
{
    [Theory]
    [InlineData("en", "error.validation.title", "Validation Error")]
    [InlineData("fr", "error.validation.title", "Erreur de validation")]
    [InlineData("en", "error.token.nameRequired", "Name is required.")]
    [InlineData("fr", "error.token.nameRequired", "Le nom est obligatoire.")]
    public void Localizer_resolves_resource_backed_values(string culture, string key, string expected)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        using var provider = services.BuildServiceProvider();
        var localizer = provider.GetRequiredService<IStringLocalizer<SharedResource>>();

        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = new CultureInfo(culture);
            var value = localizer[key];
            Assert.False(value.ResourceNotFound, $"resource lookup failed for '{key}' ({culture})");
            Assert.Equal(expected, value.Value);
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }
}
