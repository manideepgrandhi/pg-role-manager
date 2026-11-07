# Provision application access

These examples assume an existing database named `application_db`, application schemas named `app` and `reporting`, and creator roles named `migration_owner` and `etl_owner`. Replace those names. Run as a trusted DBA with the authority described in [README.md](README.md).

## Install in one database

```bash
psql -X -v ON_ERROR_STOP=1 --dbname=application_db --file=/workspace/pg-role-manager/sql/pg_role_manager.sql
```

## Authorize another DBA to invoke the procedure

Run as the installer. These grants do not supply `CREATEROLE`, creator membership, or object grant authority.

```sql
GRANT USAGE ON SCHEMA role_manager TO provisioning_dba;
GRANT EXECUTE ON PROCEDURE role_manager.provision(text, text, text[], text[], boolean, boolean)
    TO provisioning_dba;
```

## Preview reader access

```sql
CALL role_manager.provision(
    p_role => 'application_reader',
    p_profile => 'reader',
    p_schemas => ARRAY['app', 'reporting'],
    p_creators => ARRAY['migration_owner', 'etl_owner']
);
```

Review every `PREVIEW` statement and any warning. Preview does not create the role or change grants. It still requires the same authority as apply.

## Apply reader and writer access together

Use separate group names. The outer transaction makes both calls commit together. Use psql with `ON_ERROR_STOP` enabled.

```sql
BEGIN;
CALL role_manager.provision(
    'application_reader', 'reader',
    ARRAY['app', 'reporting'], ARRAY['migration_owner', 'etl_owner'],
    p_apply => true
);
CALL role_manager.provision(
    'application_writer', 'writer',
    ARRAY['app'], ARRAY['migration_owner', 'etl_owner'],
    p_apply => true
);
COMMIT;
```

## Configure only future objects

Existing database and schema access is still granted. Existing table and sequence ACLs are not changed.

```sql
CALL role_manager.provision(
    'application_future_reader', 'reader',
    ARRAY['app'], ARRAY['migration_owner'],
    p_apply => true,
    p_existing => false
);
```

## Assign existing login accounts separately

Run only after reviewing the requested membership. Use an account with authority to grant the group. This is intentionally not part of the wrapper.

```sql
GRANT application_reader TO analyst_login;
GRANT application_writer TO application_login;
```

Membership inheritance and `SET ROLE` options depend on your PostgreSQL version and existing role configuration. The procedure does not change those settings. Do not grant application logins membership in the migration owner merely to fix table access.

## Create future objects as the declared creator

Use an authorized deployment login that can `SET ROLE` to the owner. The wrapper does not create the owner role, assign membership, transfer ownership, or grant deployment privileges.

```sql
SET ROLE migration_owner;
CREATE TABLE app.role_manager_demo (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    description text
);
RESET ROLE;
```

A table created by the login without `SET ROLE` uses that login's defaults, not `migration_owner`'s defaults. Include that login in `p_creators` instead if that is your intended operating model.

## Save preview or apply output

In psql, notices are normally written to stderr. Capture both streams and preserve the exit status.

```bash
set -o pipefail
psql -X -v ON_ERROR_STOP=1 --dbname=application_db --file=/absolute/path/to/approved_calls.sql 2>&1 | tee /absolute/path/to/provisioning.log
```

Keep logs private because they contain role, database, schema, and object names. A printed `APPLY` statement does not prove a transaction committed.
