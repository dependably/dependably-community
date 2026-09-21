using System.Globalization;
using Dependably.Api;
using Microsoft.Extensions.Localization;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// A <see cref="ProblemResults"/> over a localizer that echoes the resource key back as the
/// message, so a test can assert which key a handler chose without pinning the English copy.
///
/// Shared rather than re-declared per fixture: several suites had grown their own private
/// EchoLocalizer, and the guard now needs one at every construction site.
/// </summary>
internal static class TestProblems
{
    public static ProblemResults Create() => new(new EchoLocalizer());

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);

        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);

        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
