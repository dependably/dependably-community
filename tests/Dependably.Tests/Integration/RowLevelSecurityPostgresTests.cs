using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.RowLevelSecurity;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves the Postgres row-level security backstop against a live server, on a database owned by
/// a non-superuser <c>CREATEROLE</c> role — the shape of an RDS/Aurora master user. Running as the
/// superuser <c>TEST_POSTGRES_CONNECTION</c> names would prove nothing: superusers skip RLS
/// entirely, so every assertion below would pass for the wrong reason.
///
/// <para>Each test gets its own database, owner role and RLS role, and runs the real
/// <see cref="SchemaInitializer"/> with enforcement on — which also exercises the boot-time
/// apply, verification and tenant-session probe against the full production schema.</para>
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class RowLevelSecurityPostgresTests
{
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    [Fact]
    public async Task Boot_CoversEveryTenantTable_AndLeavesNoProblem()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();

        await using var owner = await db.Store().OpenCrossTenantAsync("test: catalogue inspection");
        Assert.Empty(await PostgresRowLevelSecurityInstaller.FindProblemsAsync(owner, db.Options));

        long tenantTables = await owner.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(DISTINCT c.oid) FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname IN ('org_id', 'tenant_id') AND NOT a.attisdropped
            WHERE n.nspname = current_schema() AND c.relkind = 'r'
            """);
        long covered = await owner.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM pg_class c
            JOIN pg_policy p ON p.polrelid = c.oid AND p.polname = @policy
            WHERE c.relrowsecurity
            """,
            new { policy = PostgresRowLevelSecurityInstaller.PolicyName });
        Assert.True(tenantTables > 50, $"expected the production schema's tenant tables, found {tenantTables}");
        Assert.Equal(tenantTables + PostgresRowLevelSecurityInstaller.ParentScopedTables.Count, covered);

        // Global tables stay unrestricted: tenant resolution reads orgs before any tenant is known.
        Assert.False(await owner.ExecuteScalarAsync<bool>(
            "SELECT relrowsecurity FROM pg_class WHERE relname = 'orgs'"));
    }

    [Fact]
    public async Task TenantConnection_UnfilteredSelect_ReturnsOnlyItsOwnRows()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();

        await using (var conn = await db.Store().OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgA)))
        {
            var orgs = (await conn.QueryAsync<string>("SELECT org_id FROM packages")).ToList();
            Assert.Equal(2, orgs.Count);
            Assert.All(orgs, o => Assert.Equal(OrgA, o));
        }

        // The request path: a plain OpenAsync bound through the ambient (host-resolved) tenant.
        await using (var conn = await db.Store(new FixedAmbient(AmbientTenantKind.Tenant, OrgB)).OpenAsync())
        {
            var orgs = (await conn.QueryAsync<string>("SELECT org_id FROM packages")).ToList();
            Assert.Equal(2, orgs.Count);
            Assert.All(orgs, o => Assert.Equal(OrgB, o));
        }
    }

    // A job's declared scope decides the binding even where an ambient request tenant exists, so
    // a helper that is cross-tenant or per-org by design is not silently re-bound to the caller.
    [Fact]
    public async Task DeclaredScope_WinsOverTheAmbientRequestTenant()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        var store = db.Store(new FixedAmbient(AmbientTenantKind.Tenant, OrgA));

        using (DbScope.ForOrg(OrgB))
        {
            await using var conn = await store.OpenAsync();
            Assert.Equal(new[] { OrgB }, (await conn.QueryAsync<string>("SELECT DISTINCT org_id FROM packages")).ToArray());
        }

        using (DbScope.CrossTenant("test: declared sweep"))
        {
            await using var conn = await store.OpenAsync();
            Assert.Equal(4, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM packages"));
        }
    }

    // Tenant data with no tenant column is covered through its parent: a version id taken from
    // a route cannot reach another tenant's version or its child rows, while the global proxy
    // plane's rows in the same child tables stay readable to every tenant.
    [Fact]
    public async Task VersionScopedRows_FollowTheirParentsTenant()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        await using (var owner = await db.Store().OpenCrossTenantAsync("test: seed versions"))
        {
            await owner.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, origin)
                VALUES ('pv-a', 'pa-1', '1.0.0', 'pkg:npm/left-pad@1.0.0#a', 'hosted/a', 1, 'c', 'uploaded'),
                       ('pv-b', 'pb-1', '1.0.0', 'pkg:npm/left-pad@1.0.0#b', 'hosted/b', 1, 'c', 'uploaded');
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES ('ca-shared', 'npm', 'shared', '1.0.0', 'shared-1.0.0.tgz', 'k', 'h');
                INSERT INTO package_version_licenses (id, package_version_id, license_spdx, source, owner_kind)
                VALUES ('lic-a', 'pv-a', 'MIT', 'upstream', 'package_version'),
                       ('lic-b', 'pv-b', 'MIT', 'upstream', 'package_version');
                INSERT INTO package_version_licenses (id, cache_artifact_id, license_spdx, source, owner_kind)
                VALUES ('lic-ca', 'ca-shared', 'MIT', 'upstream', 'cache_artifact');
                """);
        }

        await using var conn = await db.Store().OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgA));
        Assert.Null(await conn.ExecuteScalarAsync<string?>("SELECT id FROM package_versions WHERE id = 'pv-b'"));
        Assert.Equal("pv-a", await conn.ExecuteScalarAsync<string?>("SELECT id FROM package_versions WHERE id = 'pv-a'"));
        Assert.Equal(
            new[] { "lic-a", "lic-ca" },
            (await conn.QueryAsync<string>("SELECT id FROM package_version_licenses ORDER BY id")).ToArray());

        var write = await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
            "INSERT INTO package_version_licenses (id, package_version_id, license_spdx, source, owner_kind) VALUES ('lic-x', 'pv-b', 'MIT', 'upstream', 'package_version')"));
        Assert.Equal("policy_violation", RowLevelSecurityViolations.Classify(write));

        await using var none = await db.Store(new FixedAmbient(AmbientTenantKind.None, null)).OpenAsync();
        var ex = await Assert.ThrowsAsync<PostgresException>(() => none.QueryAsync<string>("SELECT id FROM package_versions"));
        Assert.Equal(PostgresRowLevelSecurityInstaller.NoTenantContextSqlState, ex.SqlState);
    }

    [Fact]
    public async Task NoTenantContext_Raises_RatherThanReturningZeroRows()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();

        await using var conn = await db.Store(new FixedAmbient(AmbientTenantKind.None, null)).OpenAsync();
        var ex = await Assert.ThrowsAsync<PostgresException>(() => conn.QueryAsync<string>("SELECT id FROM packages"));

        Assert.Equal(PostgresRowLevelSecurityInstaller.NoTenantContextSqlState, ex.SqlState);
        Assert.Equal("no_tenant_context", RowLevelSecurityViolations.Classify(ex));
    }

    [Fact]
    public async Task WithCheck_RejectsWritesNamingAnotherTenant()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        await using var conn = await db.Store().OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgA));

        var insert = await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES ('p-x', @org, 'npm', 'x', 'x')",
            new { org = OrgB }));
        Assert.Equal("policy_violation", RowLevelSecurityViolations.Classify(insert));

        var move = await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
            "UPDATE packages SET org_id = @org WHERE id = 'pa-1'", new { org = OrgB }));
        Assert.Equal("policy_violation", RowLevelSecurityViolations.Classify(move));

        // Another tenant's row is invisible to UPDATE/DELETE keyed by its primary key alone.
        Assert.Equal(0, await conn.ExecuteAsync("UPDATE packages SET description = 'x' WHERE id = 'pb-1'"));
        Assert.Equal(0, await conn.ExecuteAsync("DELETE FROM packages WHERE id = 'pb-1'"));

        // An upsert whose conflict target is another tenant's row errors instead of overwriting it.
        await Assert.ThrowsAsync<PostgresException>(() => conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES ('pb-1', @org, 'npm', 'hijack', 'hijack')
            ON CONFLICT (id) DO UPDATE SET description = 'hijacked'
            """,
            new { org = OrgA }));

        await using var owner = await db.Store().OpenCrossTenantAsync("test: verify untouched");
        Assert.Null(await owner.ExecuteScalarAsync<string?>("SELECT description FROM packages WHERE id = 'pb-1'"));
        Assert.Equal(OrgA, await owner.ExecuteScalarAsync<string>("SELECT org_id FROM packages WHERE id = 'pa-1'"));
    }

    // No Reset On Close skips Npgsql's DISCARD ALL between leases, so that row proves the store's
    // own rebinding on every open is what isolates leases, not the pool's reset.
    [Theory]
    [InlineData(0, false)]
    [InlineData(20, false)]
    [InlineData(0, true)]
    public async Task PooledConnectionReuse_NeverCarriesTheTenantIntoTheNextLease(int maxAutoPrepare, bool noResetOnClose)
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        string singleBackend = new NpgsqlConnectionStringBuilder(db.OwnerConnectionString)
        {
            MaxPoolSize = 1,
            MaxAutoPrepare = maxAutoPrepare,
            AutoPrepareMinUsages = 1,
            NoResetOnClose = noResetOnClose,
        }.ConnectionString;

        int pidA;
        await using (var a = await db.Store(connectionString: singleBackend).OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgA)))
        {
            pidA = await a.ExecuteScalarAsync<int>("SELECT pg_backend_pid()");
            for (int i = 0; i < 3; i++)
            {
                Assert.Equal(2, await a.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM packages"));
            }
        }

        await using (var none = await db.Store(new FixedAmbient(AmbientTenantKind.None, null), singleBackend).OpenAsync())
        {
            Assert.Equal(pidA, await none.ExecuteScalarAsync<int>("SELECT pg_backend_pid()"));
            var ex = await Assert.ThrowsAsync<PostgresException>(
                () => none.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM packages"));
            Assert.Equal(PostgresRowLevelSecurityInstaller.NoTenantContextSqlState, ex.SqlState);
        }

        await using var b = await db.Store(connectionString: singleBackend).OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgB));
        Assert.Equal(pidA, await b.ExecuteScalarAsync<int>("SELECT pg_backend_pid()"));
        Assert.Equal(new[] { OrgB }, (await b.QueryAsync<string>("SELECT DISTINCT org_id FROM packages")).ToArray());
    }

    [Fact]
    public async Task TenantSettingFromAnotherSession_Raises()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        await using var conn = await db.Store().OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgA));

        // What a transaction-mode pooler produces: a tenant value written on one backend, read on another.
        await conn.ExecuteAsync("SELECT set_config('dependably.org_id', '1:' || @org, false)", new { org = OrgB });
        var ex = await Assert.ThrowsAsync<PostgresException>(() => conn.QueryAsync<string>("SELECT id FROM packages"));

        Assert.Equal(PostgresRowLevelSecurityInstaller.SessionMismatchSqlState, ex.SqlState);
    }

    [Fact]
    public async Task ReadThroughView_IsFilteredToTheReadersTenant()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        await using (var owner = await db.Store().OpenCrossTenantAsync("test: seed"))
        {
            await owner.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key)
                VALUES ('sha256:a', @a, 'application/octet-stream', 10, 'k-a'),
                       ('sha256:b', @b, 'application/octet-stream', 20, 'k-b')
                """,
                new { a = OrgA, b = OrgB });
        }

        await using var conn = await db.Store().OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgA));
        var rows = (await conn.QueryAsync<(string OrgId, long Total)>(
            "SELECT org_id, total_bytes::bigint FROM org_storage_bytes")).ToList();

        Assert.Equal(new[] { (OrgA, 10L) }, rows);
    }

    [Fact]
    public async Task CrossTenantAndApexConnections_SeeEveryTenant_AndCanCopy()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();

        await using (var apex = await db.Store(new FixedAmbient(AmbientTenantKind.Apex, null)).OpenAsync())
        {
            Assert.Equal(4, await apex.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM packages"));
        }

        // COPY FROM is rejected on any table RLS applies to; the migrator's bulk load relies on the
        // owner path, which is exactly why the owner is exempt by role rather than by FORCE.
        await using (var owner = (NpgsqlConnection)await db.Store().OpenCrossTenantAsync("test: bulk load"))
        {
            await using (var import = await owner.BeginBinaryImportAsync(
                "COPY packages (id, org_id, ecosystem, name, purl_name) FROM STDIN (FORMAT BINARY)"))
            {
                await import.StartRowAsync();
                await import.WriteAsync("pb-copy");
                await import.WriteAsync(OrgB);
                await import.WriteAsync("npm");
                await import.WriteAsync("copied");
                await import.WriteAsync("copied");
                await import.CompleteAsync();
            }

            Assert.Equal(5, await owner.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM packages"));
        }

        await using var tenant = (NpgsqlConnection)await db.Store().OpenForTenantAsync(TenantDbScope.ForOrgIteration(OrgA));
        await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await using var import = await tenant.BeginBinaryImportAsync(
                "COPY packages (id, org_id, ecosystem, name, purl_name) FROM STDIN (FORMAT BINARY)");
        });
    }

    [Fact]
    public async Task EnforcementOff_LeavesEveryConnectionAsTheOwner()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();

        var off = new NpgsqlMetadataStore(
            db.OwnerConnectionString, RowLevelSecurityOptions.Disabled, new FixedAmbient(AmbientTenantKind.None, null));
        await using var conn = await off.OpenAsync();

        Assert.Equal(4, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM packages"));
    }

    [Fact]
    public async Task TableLeftWithoutRls_IsReported_AndReboot_ReCoversIt()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await using (var owner = await db.Store().OpenCrossTenantAsync("test: simulate a reshape"))
        {
            await owner.ExecuteAsync("ALTER TABLE packages DISABLE ROW LEVEL SECURITY");
            await owner.ExecuteAsync("DROP POLICY dependably_tenant_isolation_v1 ON blocklist");

            var problems = await PostgresRowLevelSecurityInstaller.FindProblemsAsync(owner, db.Options);
            Assert.Contains(problems, p => p.Contains("'packages'", StringComparison.Ordinal));
            Assert.Contains(problems, p => p.Contains("'blocklist'", StringComparison.Ordinal));
        }

        await new SchemaInitializer(db.Store()).InitializeAsync();

        await using var reowned = await db.Store().OpenCrossTenantAsync("test: catalogue inspection");
        Assert.Empty(await PostgresRowLevelSecurityInstaller.FindProblemsAsync(reowned, db.Options));
    }

    [Fact]
    public async Task RoleThatBypassesRls_FailsBoot()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.AsSuperuserAsync("ALTER ROLE {rls} BYPASSRLS");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new SchemaInitializer(db.Store()).InitializeAsync());

        Assert.Contains("BYPASSRLS", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RoleThatInheritsTheOwner_IsReported()
    {
        // Postgres refuses the circular grant while the owner is a member of the RLS role, so the
        // reverse membership is only reachable after that grant is gone — e.g. a superuser owner,
        // which never needs it. Build that state directly.
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.AsSuperuserAsync("REVOKE {rls} FROM {owner} CASCADE; GRANT {owner} TO {rls}");

        await using var owner = await db.Store().OpenCrossTenantAsync("test: catalogue inspection");
        var problems = await PostgresRowLevelSecurityInstaller.FindProblemsAsync(owner, db.Options);

        Assert.Contains(problems, p => p.Contains("member of the owner role", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ViewWithoutSecurityInvoker_IsReported()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await using var owner = await db.Store().OpenCrossTenantAsync("test: simulate a plain view");
        await owner.ExecuteAsync("ALTER VIEW org_storage_bytes RESET (security_invoker)");

        var problems = await PostgresRowLevelSecurityInstaller.FindProblemsAsync(owner, db.Options);

        Assert.Contains(problems, p => p.Contains("'org_storage_bytes'", StringComparison.Ordinal));
    }

    // A shared-blob reference count run from a tenant request must still see every tenant's
    // references. Under a tenant binding it would count only the caller's (already removed) row,
    // report the blob unreferenced, and delete bytes another tenant still serves.
    [Fact]
    public async Task OciBlobRefcount_FromATenantScope_StillSeesOtherTenantsReferences()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        string blobKey = BlobKeys.OciBlob("sha256", new string('a', 64));
        await using (var owner = await db.Store().OpenCrossTenantAsync("test: seed shared blob"))
        {
            await owner.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key)
                VALUES ('sha256:shared', @b, 'application/octet-stream', 1, @key)
                """,
                new { b = OrgB, key = blobKey });
        }

        var registry = new InMemoryBlobStore();
        await registry.PutAsync(blobKey, new MemoryStream([1]));
        var deleter = new OciOrphanBlobDeleter(db.Store(), new TieredBlobStorage(registry, registry), new OciBlobKeyLock());

        bool deleted;
        using (DbScope.ForOrg(OrgA))
        {
            deleted = await deleter.DeleteIfUnreferencedAsync(blobKey);
        }

        Assert.False(deleted);
        Assert.True(await registry.ExistsAsync(blobKey));
    }

    [Fact]
    public async Task CacheArtifactRefcount_FromATenantScope_CountsEveryTenantsAccess()
    {
        await using var db = await RlsDatabase.CreateInitializedAsync();
        await db.SeedTwoTenantsAsync();
        await using (var owner = await db.Store().OpenCrossTenantAsync("test: seed shared cache artifact"))
        {
            await owner.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES ('ca-1', 'npm', 'left-pad', '1.0.0', 'left-pad-1.0.0.tgz', 'k-ca', 'h');
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@b, 'ca-1');
                """,
                new { b = OrgB });
        }

        int remaining;
        using (DbScope.ForOrg(OrgA))
        {
            remaining = await new TenantArtifactAccessRepository(db.Store()).CountRemainingAsync("ca-1");
        }

        Assert.Equal(1, remaining);
    }

    // The default must never make a deployment unbootable: a defaulted enforce on a database the
    // backstop cannot run on (here, an owner role without CREATEROLE) boots with it off instead.
    [Fact]
    public async Task DefaultedEnforce_OnADatabaseThatCannotHostIt_BootsWithRlsOff()
    {
        await using var db = await RlsDatabase.CreateAsync(ownerCanCreateRoles: false, explicitEnforce: false);
        var store = db.Store();

        await new SchemaInitializer(store).InitializeAsync();

        Assert.False(store.RowLevelSecurity.Enforced);
        Assert.NotNull(store.RowLevelSecurityFallbackReason);
        await using var conn = await store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM packages"));
    }

    // Its twin: an operator who explicitly asked for the backstop does not get a node without it.
    [Fact]
    public async Task ExplicitEnforce_OnADatabaseThatCannotHostIt_FailsBoot()
    {
        await using var db = await RlsDatabase.CreateAsync(ownerCanCreateRoles: false, explicitEnforce: true);

        await Assert.ThrowsAnyAsync<Exception>(() => new SchemaInitializer(db.Store()).InitializeAsync());
    }

    private sealed class FixedAmbient(AmbientTenantKind kind, string? orgId) : IAmbientTenantScope
    {
        public AmbientTenant Current { get; } = new(kind, orgId);
    }

    /// <summary>
    /// One throwaway database owned by a non-superuser CREATEROLE role, plus a uniquely named RLS
    /// role, created and dropped through the superuser connection.
    /// </summary>
    private sealed class RlsDatabase : IAsyncDisposable
    {
        private const string OwnerPassword = "rls_owner_pw";

        private readonly string _superuser;
        private readonly string _admin;
        private readonly string _database;
        private readonly string _ownerRole;

        private RlsDatabase(string superuser, string suffix, bool explicitEnforce)
        {
            _superuser = superuser;
            // CREATE/DROP DATABASE get the harness's admin timeout, not the 30 s default: DROP
            // DATABASE runs an immediate checkpoint that fsyncs every file the run has dirtied, and
            // the first one of a schema-integrity run follows dozens of full-schema resets. Only
            // these harness statements get it; the owner connection the boot runs on keeps 30 s.
            _admin = new NpgsqlConnectionStringBuilder(superuser)
            {
                CommandTimeout = PostgresTestDatabase.AdminCommandTimeoutSeconds,
            }.ConnectionString;
            _database = "rls_db_" + suffix;
            _ownerRole = "rls_owner_" + suffix;
            Options = new RowLevelSecurityOptions(RowLevelSecurityMode.Enforce, "rls_role_" + suffix)
            {
                Explicit = explicitEnforce,
            };
            OwnerConnectionString = new NpgsqlConnectionStringBuilder(superuser)
            {
                Database = _database,
                Username = _ownerRole,
                Password = OwnerPassword,
            }.ConnectionString;
        }

        public RowLevelSecurityOptions Options { get; }

        public string OwnerConnectionString { get; }

        public static async Task<RlsDatabase> CreateInitializedAsync()
        {
            var db = await CreateAsync(ownerCanCreateRoles: true, explicitEnforce: true);
            try
            {
                await new SchemaInitializer(db.Store()).InitializeAsync();
                return db;
            }
            catch
            {
                // A boot the test expects to succeed can still fail; the database and roles must
                // not outlive it, since the caller never receives the handle that would drop them.
                await db.DisposeAsync();
                throw;
            }
        }

        /// <summary>A database that has not been booted yet, so a test can boot it itself.</summary>
        public static async Task<RlsDatabase> CreateAsync(bool ownerCanCreateRoles, bool explicitEnforce)
        {
            string superuser = Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
                ?? throw new InvalidOperationException(
                    "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests.");

            var db = new RlsDatabase(superuser, Guid.NewGuid().ToString("N")[..12], explicitEnforce);
            string createRole = ownerCanCreateRoles ? " CREATEROLE" : "";
            await using (var conn = new NpgsqlConnection(db._admin))
            {
                await conn.OpenAsync();
                // rawsql: identifiers are fixed prefixes plus a Guid suffix; the password is a constant.
                await conn.ExecuteAsync($"CREATE ROLE {db._ownerRole} LOGIN{createRole} PASSWORD '{OwnerPassword}'");
                // rawsql: identifiers are fixed prefixes plus a Guid suffix.
                await conn.ExecuteAsync($"CREATE DATABASE {db._database} OWNER {db._ownerRole}");
            }

            try
            {
                await db.AsSuperuserAsync("ALTER SCHEMA public OWNER TO {owner}");
                return db;
            }
            catch
            {
                await db.DisposeAsync();
                throw;
            }
        }

        public NpgsqlMetadataStore Store(IAmbientTenantScope? ambient = null, string? connectionString = null) =>
            new(connectionString ?? OwnerConnectionString, Options, ambient ?? new FixedAmbient(AmbientTenantKind.None, null));

        public async Task SeedTwoTenantsAsync()
        {
            await using var owner = await Store().OpenCrossTenantAsync("test: seed two tenants");
            await owner.ExecuteAsync(
                """
                INSERT INTO orgs (id, slug) VALUES (@a, 'tenant-a'), (@b, 'tenant-b');
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES
                    ('pa-1', @a, 'npm', 'left-pad', 'left-pad'),
                    ('pa-2', @a, 'pypi', 'requests', 'requests'),
                    ('pb-1', @b, 'npm', 'left-pad', 'left-pad'),
                    ('pb-2', @b, 'npm', 'lodash', 'lodash');
                """,
                new { a = OrgA, b = OrgB });
        }

        /// <summary>Runs <paramref name="sql"/> as the superuser inside this database, with
        /// <c>{owner}</c>/<c>{rls}</c> replaced by this fixture's role names.</summary>
        public async Task AsSuperuserAsync(string sql)
        {
            string statement = sql.Replace("{owner}", _ownerRole, StringComparison.Ordinal)
                .Replace("{rls}", Options.RoleName, StringComparison.Ordinal);
            await using var conn = new NpgsqlConnection(
                new NpgsqlConnectionStringBuilder(_superuser) { Database = _database, Pooling = false }.ConnectionString);
            await conn.OpenAsync();
            await conn.ExecuteAsync(statement);
        }

        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var conn = new NpgsqlConnection(_admin);
            await conn.OpenAsync();
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"DROP DATABASE IF EXISTS {_database} WITH (FORCE)");
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"DROP ROLE IF EXISTS {Options.RoleName}");
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"DROP ROLE IF EXISTS {_ownerRole}");
        }
    }
}
