# Schema Migration Rules

Dependably applies its schema on startup via `SchemaInitializer`, which executes the embedded `Schema.sql` using `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`. There is no migration history table — every statement is idempotent.

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

Since `Schema.sql` is applied idempotently via `CREATE TABLE IF NOT EXISTS`, adding a column to an existing table requires a separate `ALTER TABLE` statement, not a change to the `CREATE TABLE` block. Place new `ALTER TABLE` statements after all `CREATE TABLE` blocks, guarded with a conditional:

```sql
-- Add description column if it doesn't exist yet (SQLite doesn't support IF NOT EXISTS on ALTER TABLE)
INSERT OR IGNORE INTO _schema_migrations(statement) VALUES ('add_packages_description');
```

The simplest guard: attempt the `ALTER TABLE` and ignore the `duplicate column` error in `SchemaInitializer.cs`.

### Renaming columns or tables

Rename = three separate releases:

1. **Release N**: Add the new column/table. Backfill existing rows.
2. **Release N+1**: Write to both old and new. Read from new.
3. **Release N+2**: Drop the old column/table.

Never rename in a single release — the old slot still reads the old name during cutover.

### Dropping columns or tables

Only drop in a release where no application code reads or writes that column/table. Ensure the previous release removed all references first.

Destructive drops live in `SchemaInitializer` as a `RunOnceAsync(...)` call so the migration ledger guarantees they run exactly once per database. SQLite ≥ 3.35 and Postgres both support `ALTER TABLE ... DROP COLUMN` natively. Examples: `drop_legacy_token_scope_column` retires the `tokens.scope` / `cicd_tokens.scope` columns now that capabilities is the single source of truth; `drop_package_versions_sbom_column` retires the orphaned per-version SBOM blob (the only producer wrapped coordinate fields in CycloneDX JSON; the read endpoint was removed in the API cleanup pass). The `RunOnceAsync` helper emits an info-level log on apply and on skip so operators can confirm the migration state from startup logs.

### Index changes

Adding or removing indexes is always safe — they don't affect data visible to running code.

### Destructive DDL

Never pair a destructive statement (`DROP COLUMN`, `DROP TABLE`) with a statement that depends on the new structure in the same release.

## Schema.sql conventions

- All tables use `CREATE TABLE IF NOT EXISTS` — idempotent, never fails on re-run.
- All indexes use `CREATE INDEX IF NOT EXISTS`.
- Columns added to existing tables go in `ALTER TABLE` statements at the bottom of the file, wrapped in the `SchemaInitializer` idempotency guard.
- Foreign key constraints use `ON DELETE CASCADE` so parent deletes propagate cleanly.
- All timestamps are ISO 8601 UTC strings (`TEXT`), defaulting to `strftime('%Y-%m-%dT%H:%M:%SZ','now')`.

## Existing schema review

The current `Schema.sql` is fully blue-green compatible:

| Table | Verdict | Notes |
|---|---|---|
| `orgs` | ✓ | All columns have defaults or are primary key |
| `org_settings` | ✓ | Optional columns are nullable |
| `instance_settings` | ✓ | Key-value store, additive |
| `users` | ✓ | All non-null columns have defaults |
| `org_members` | ✓ | Role has a default (`'member'`) |
| `packages` | ✓ | All non-null columns have defaults |
| `package_versions` | ✓ | Optional fields nullable; booleans default to 0 |
| `tokens` | ✓ | `expires_at` nullable |
| `cicd_tokens` | ✓ | `expires_at` nullable |
| `invites` | ✓ | `accepted_at` nullable |
| `allowlist` | ✓ | Unique constraint is additive |
| `audit_log` | ✓ | All optional columns nullable |
| `activity` | ✓ | `detail` nullable |
| `vulnerabilities` | ✓ | Optional fields nullable |
| `package_version_vulns` | ✓ | Join table, additive |
| `login_attempts` | ✓ | All columns have defaults |

All current schema statements satisfy the blue-green compatibility rules.

## CI check

`scripts/schema-lint.sh` fails if a new `ALTER TABLE ... ADD COLUMN` statement adds a `NOT NULL` column without a `DEFAULT`. This prevents incompatible migrations from reaching main.
