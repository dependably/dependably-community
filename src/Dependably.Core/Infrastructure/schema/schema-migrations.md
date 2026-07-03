# Schema Migration Rules

Dependably applies its schema on startup via `SchemaInitializer` (`src/Dependably/Infrastructure/SchemaInitializer.cs`), in three layers:

1. **Base schema** — the embedded `Schema.sql` / `Schema.pg.sql` is applied with `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`, so re-running is a safe no-op.
2. **Additive columns** — `ALTER TABLE ... ADD COLUMN` statements in `RunAdditiveMigrationsAsync`. SQLite has no `IF NOT EXISTS` for column adds, so `MigrateSqliteAsync` swallows only the "duplicate column" error (code 1); Postgres rewrites to `ADD COLUMN IF NOT EXISTS`.
3. **One-time migrations** — destructive DDL (`DROP COLUMN`, table rebuilds) and data backfills that are **not** idempotent on their own. These run through `RunOnceAsync`, which records each by name in the `_applied_migrations` ledger table so it runs exactly once per database.

So there *is* a migration history table (`_applied_migrations`) — it exists precisely because the layer-3 migrations are not idempotent.

Because blue-green deploys run both the old (blue) and new (green) version against the same database during the cutover window, schema changes must be backward-compatible with the previous release.

## Rules

### Schema.sql is the authoritative complete schema

`Schema.sql` (and `Schema.pg.sql`) must always reflect the full current database structure. When adding a new column via `ALTER TABLE` in `SchemaInitializer`, also add it to the corresponding `CREATE TABLE` block in the schema file. The `ALTER TABLE` handles existing installs; the `CREATE TABLE` block makes the schema self-documenting for fresh installs and for anyone reading the file.

### New columns

New columns on existing tables **must** either have a `DEFAULT` value or allow `NULL`:

```sql
-- OK: nullable column, old code ignores it
ALTER TABLE packages ADD COLUMN description TEXT;

-- OK: column with default, old code sees the default
ALTER TABLE packages ADD COLUMN is_featured INTEGER NOT NULL DEFAULT 0;

-- NEVER: non-null column without default — old rows have no value
ALTER TABLE packages ADD COLUMN required_field TEXT NOT NULL;  -- breaks old code
```

Adding a column requires **two** edits, both enforced by `SchemaSyncComplianceTests`:

1. Append an `ALTER TABLE ... ADD COLUMN` to the `migrations` array in `SchemaInitializer.RunAdditiveMigrationsAsync`. This upgrades existing databases; re-runs are made safe by `MigrateSqliteAsync` (swallows the "duplicate column" error on SQLite) and by the `ADD COLUMN IF NOT EXISTS` rewrite on Postgres.
2. Add the same column to the `CREATE TABLE` block in **both** `Schema.sql` and `Schema.pg.sql`. This is what fresh installs get, and keeps the two providers in parity.

Do not skip (2): a column that lives only in the `ALTER` array means a fresh install gets it solely from the upgrade path, and the two provider schemas can silently drift. `SchemaSyncComplianceTests` fails the build if an additive column is absent from either `CREATE TABLE` block.

### Renaming columns or tables

Rename = three separate releases:

1. **Release N**: Add the new column/table. Backfill existing rows.
2. **Release N+1**: Write to both old and new. Read from new.
3. **Release N+2**: Drop the old column/table.

Never rename in a single release — the old slot still reads the old name during cutover.

This sequencing (and the drop sequencing below) is reviewer-enforced; the compliance tests in [CI check](#ci-check) catch structural mistakes (missing defaults, schema-file drift) but cannot know which release a statement belongs to.

### Dropping columns or tables

Only drop in a release where no application code reads or writes that column/table. Ensure the previous release removed all references first.

Destructive drops live in `SchemaInitializer` as a `RunOnceAsync(...)` call so the migration ledger guarantees they run exactly once per database. SQLite ≥ 3.35 and Postgres both support `ALTER TABLE ... DROP COLUMN` natively. Examples: `drop_legacy_token_scope_column` retires the `user_tokens.scope` / `service_tokens.scope` columns now that capabilities is the single source of truth; `drop_package_versions_sbom_column` retires the orphaned per-version SBOM blob (the only producer wrapped coordinate fields in CycloneDX JSON; the read endpoint was removed in the API cleanup pass). The `RunOnceAsync` helper emits an info-level log on apply and on skip so operators can confirm the migration state from startup logs.

### Widening a CHECK constraint (enum-style columns)

Several columns constrain their values with `CHECK (col IN (...))` (e.g. `users.role`,
`org_settings.block_deprecated`). Adding a new allowed value needs work on **both** the fresh-install
and the upgrade path, because the two paths produce different on-disk shapes:

- **Fresh installs** get the constraint from the `CREATE TABLE` block — so widen the `IN (...)` list
  in both `Schema.sql` and `Schema.pg.sql`.
- **Existing databases** need the stored constraint rewritten via a `RunOnceAsync(..., transactional: false)`
  one-shot. Postgres drops + re-adds the auto-named `<table>_<col>_check` constraint (`IF EXISTS` covers
  installs that never had one); SQLite rewrites the stored `CREATE TABLE` text through the
  `PRAGMA writable_schema` pattern, then bumps `PRAGMA schema_version` and runs `integrity_check`.
  Both branches are idempotent, which is why they opt out of the enclosing transaction.
- **Columns added by a later `ALTER ADD COLUMN`** (rather than the original `CREATE TABLE`) carry **no**
  CHECK on upgraded databases, so those installs rely on controller-side validation — the rewrite simply
  no-ops on them.

Precedents: `expand_role_check_with_auditor` (adds `'auditor'` to `users.role` / `invites.role`) and
`expand_block_deprecated_check` (widens `org_settings.block_deprecated` to `'block_new'`/`'block_all'`).
When the new value also supersedes an old one, follow the CHECK widen with a normal transactional data
migration to rewrite legacy rows — e.g. `migrate_block_deprecated_to_block_all` rewrites the retired
`'block'` value to `'block_all'`, ordered *after* the CHECK widen so the new value is permitted.

### Index changes

Adding or removing indexes is always safe — they don't affect data visible to running code.

### Destructive DDL

Never pair a destructive statement (`DROP COLUMN`, `DROP TABLE`) with a statement that depends on the new structure in the same release.

## Schema.sql conventions

- All tables use `CREATE TABLE IF NOT EXISTS` — idempotent, never fails on re-run.
- All indexes use `CREATE INDEX IF NOT EXISTS`.
- Columns added to existing tables go in the `RunAdditiveMigrationsAsync` array in `SchemaInitializer.cs` (duplicate-column-safe) **and** in the `CREATE TABLE` block of both schema files — see "New columns" above.
- Foreign key constraints use `ON DELETE CASCADE` so parent deletes propagate cleanly.
- All timestamps are ISO 8601 UTC strings (`TEXT`), defaulting to `strftime('%Y-%m-%dT%H:%M:%SZ','now')`.

## Existing schema review

There is no hand-maintained per-table compatibility snapshot — it would drift from `Schema.sql` immediately. Blue-green compatibility of the current schema is asserted continuously by the `Category=Schema` compliance tests described below; `Schema.sql` / `Schema.pg.sql` are the authoritative listing of what exists.

## CI check

The `schema-integrity` CI job (xUnit tests tagged `Category=Schema`) enforces these rules on every pipeline:

- **`SchemaSyncComplianceTests`** — fails if an additive `ALTER TABLE ... ADD COLUMN` adds a `NOT NULL` column without a `DEFAULT`; if an additive column is missing from the `CREATE TABLE` block of either `Schema.sql` or `Schema.pg.sql` (the "authoritative complete schema" rule above); or if an object name is declared twice in a file.
- **`SchemaParityComplianceTests`** — fails if `Schema.sql` and `Schema.pg.sql` declare different tables, or different column names for the same table.
- **`SchemaIntegrityTests`** — applies the full schema to a fresh SQLite database and asserts structural soundness (no duplicate columns, every table has a primary key, foreign keys resolve, `PRAGMA integrity_check` is `ok`) and that re-running `SchemaInitializer` is a stable no-op.

This prevents incompatible migrations from reaching main.
