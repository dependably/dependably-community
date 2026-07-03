namespace Dependably.Protocol;

public static class NpmRouteHelper
{
    // ASP.NET decodes %40→@ but keeps %2F encoded to prevent path splitting.
    public static string DecodeRouteName(string name) =>
        name.Replace("%2F", "/", StringComparison.OrdinalIgnoreCase)
            .Replace("%40", "@", StringComparison.OrdinalIgnoreCase);
}
