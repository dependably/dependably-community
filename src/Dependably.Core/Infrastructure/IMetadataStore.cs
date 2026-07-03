using System.Data.Common;

namespace Dependably.Infrastructure;

public enum DbProvider { Sqlite, Postgres }

public interface IMetadataStore
{
    DbProvider Provider { get; }

    /// <summary>Returns an open connection. Caller is responsible for disposing.</summary>
    Task<DbConnection> OpenAsync(CancellationToken ct = default);
}
