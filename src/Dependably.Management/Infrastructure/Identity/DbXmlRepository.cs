using System.Xml.Linq;
using Dapper;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Persists the DataProtection key ring to the <c>data_protection_keys</c> table so the ring
/// survives application restarts. Instance-global, like <c>instance_settings</c>: the table is
/// never tenant-scoped and requires no <c>org_id</c> filter.
///
/// The ASP.NET Core DataProtection runtime calls <see cref="GetAllElements"/> on startup and
/// <see cref="StoreElement"/> when a new key is generated or refreshed. The ring is then cached
/// in-memory by <c>KeyRingProvider</c>, so the DB is read rarely (once per app lifetime) and
/// written only on key rotation.
///
/// Both methods use sync-over-async (GetAwaiter().GetResult()) because the
/// <see cref="IXmlRepository"/> contract is synchronous and the DataProtection runtime invokes
/// it from non-async context at startup. This matches the existing pattern in
/// <c>IdentityStartupExtensions</c> and <c>MfaEncryptionKeyProvider</c>.
/// </summary>
internal sealed class DbXmlRepository : IXmlRepository
{
    private readonly IMetadataStore _db;
    private readonly ILogger<DbXmlRepository> _logger;

    public DbXmlRepository(IMetadataStore db, ILogger<DbXmlRepository> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        // xtenant: instance-global DataProtection key ring, no tenant scoping (mirrors instance_settings)
        const string sql = "SELECT friendly_name AS FriendlyName, xml AS Xml FROM data_protection_keys";
        using var conn = _db.OpenAsync().GetAwaiter().GetResult();
        var rows = conn.Query<(string FriendlyName, string Xml)>(sql);
        var elements = new List<XElement>();
        foreach (var (friendlyName, xml) in rows)
        {
            try
            {
                elements.Add(XElement.Parse(xml));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "DataProtection key {FriendlyName} could not be parsed; skipping",
                    friendlyName);
            }
        }

        return elements.AsReadOnly();
    }

    /// <inheritdoc/>
    public void StoreElement(XElement element, string friendlyName)
    {
        string name = string.IsNullOrEmpty(friendlyName)
            ? Guid.NewGuid().ToString()
            : friendlyName;
        string xml = element.ToString(SaveOptions.DisableFormatting);

        // xtenant: instance-global DataProtection key ring, no tenant scoping (mirrors instance_settings)
        const string sql =
            """
            INSERT INTO data_protection_keys (friendly_name, xml)
            VALUES (@name, @xml)
            ON CONFLICT(friendly_name) DO UPDATE SET xml = excluded.xml
            """;
        using var conn = _db.OpenAsync().GetAwaiter().GetResult();
        conn.Execute(sql, new { name, xml });
        _logger.LogInformation("DataProtection key stored: {FriendlyName}", name);
    }
}
