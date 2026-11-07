# pg-role-manager

A PostgreSQL `SECURITY INVOKER` procedure that provisions reader and writer `NOLOGIN` groups for explicit application schemas. It grants access to existing objects and sets default privileges for future objects created by named roles.

This is additive provisioning, not an effective-access auditor. A reader group does not make its members globally read-only.

## Install

Use a trusted DBA account in each target database. The `role_manager` schema must be new or already owned and controlled by that DBA. Do not install into an untrusted schema.

```bash
psql -X -v ON_ERROR_STOP=1 --dbname=application_db --file=/workspace/pg-role-manager/sql/pg_role_manager.sql
```

The installation creates `role_manager` if needed. It removes `PUBLIC` schema `CREATE` and `PUBLIC` execution on this procedure, including when reinstalling. It does not revoke permissions from other named roles. Existing explicit procedure grants survive replacement. The file uses psql's `\set` directive.

Only the installer can call the procedure initially. To authorize another DBA, the installer grants that DBA schema `USAGE` and execution on the exact procedure signature. See [EXAMPLES.md](EXAMPLES.md). Authorization to call does not supply authority to create roles or grant object privileges.

## Preview and apply

Replace the sample names with your database-scoped group names, existing schemas, and actual creator roles. No login accounts are created. Application membership assignment is a separate DBA action.

```sql
-- Preview is the default. It performs the same preflight checks as apply.
CALL role_manager.provision(
    'application_reader', 'reader',
    ARRAY['app'], ARRAY['migration_owner']
);

-- Explicitly apply writer access to existing and future objects.
CALL role_manager.provision(
    'application_writer', 'writer',
    ARRAY['app'], ARRAY['migration_owner'],
    p_apply => true
);
```

Preview prints `PREVIEW` statements without creating roles, granting access, changing default ACLs, or taking the procedure's advisory lock. Apply prints `APPLY` statements. Save client output if you need a durable audit record. The procedure does not maintain audit or configuration tables.

## Procedure reference

`role_manager.provision(p_role text, p_profile text, p_schemas text[], p_creators text[], p_apply boolean DEFAULT false, p_existing boolean DEFAULT true)`

| Input | Meaning |
|---|---|
| `p_role` | One group role. Use different names for reader and writer, preferably prefixed with the database or application name. |
| `p_profile` | Exactly `reader` or `writer`. |
| `p_schemas` | Nonempty, one-dimensional list of existing application schemas. System schemas and duplicates are rejected. |
| `p_creators` | Nonempty, one-dimensional list of existing roles that actually create future objects. Duplicates and the target group are rejected. |
| `p_apply` | `false` previews. `true` executes after preflight. NULL is rejected. |
| `p_existing` | `true` grants on current objects too. `false` changes only schema/database access and future defaults. NULL is rejected. |

Names are exact, case-sensitive identifier values, not SQL fragments. The procedure quotes identifiers. Names longer than 63 bytes are rejected rather than silently truncated. Group names beginning with `pg_`, and `public` or `none` in any letter case, are rejected.

| Permission | Reader | Writer |
|---|---|---|
| Current database | `CONNECT` | `CONNECT` |
| Named schemas | `USAGE` | `USAGE` |
| Tables, views, materialized views, foreign tables, and partitioned tables | `SELECT` | `SELECT, INSERT, UPDATE, DELETE` |
| Sequences | None | `USAGE` |

Grants on object kinds that cannot perform an operation do not make that operation possible. Writer permissions can permit writes through updatable views. Foreign tables may require additional server permissions and user mappings. The procedure does not configure those.

Neither profile grants schema `CREATE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`, object ownership, role administration, grant options, sequence `UPDATE`, or function execution. Sequence `USAGE` supports `nextval` and `currval`, not `setval`. Identity and serial insert behavior is covered by the tests. Functions called by defaults or expressions may need separately reviewed execution grants.

## Caller authority and role conflicts

The procedure runs as `current_user`. Its fixed search path is `pg_catalog, pg_temp`. There is no elevated `SECURITY DEFINER` helper.

Preflight requires:

- `CREATEROLE` on the current role, or superuser status, if the target group does not exist.
- Authority to grant database `CONNECT` and schema `USAGE`.
- Grant options for every requested privilege on each existing object, when `p_existing` is true.
- Usable privileges of every creator role, checked with `pg_has_role(..., 'USAGE')`. Membership without inheritance is not enough for this wrapper. Invoke as an authorized role with usable creator privileges.

New groups explicitly use `NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`. PostgreSQL 16+ automatically gives a non-superuser role creator administrative membership in the newly created role. This wrapper does not remove that PostgreSQL-managed membership or explicitly assign application logins.

Existing groups must have those attributes. The procedure rejects any parent role membership, even a membership with inheritance disabled. Members assigned *to* the group are allowed. The procedure also rejects ownership of shared objects or objects in the current database. It does not inspect ownership inside other databases.

On every existing-group reuse, it warns that this is not a complete ACL audit. It preserves direct grants, existing defaults, and existing user memberships. It does not certify the group as least-privileged. Applying writer and then reader to the same group does **not** remove writer access.

## Existing and future access

Roles are cluster-wide. Object grants and default ACLs belong to individual databases, so install and run in each database that needs access. This procedure does not connect to other databases.

Existing-object grants cover all supported objects currently in each named schema, regardless of creator. Future grants cover only objects created by each named creator in each named schema. Default privileges follow the role actually creating an object, not simply the schema owner or a parent role. Membership in `migration_owner` does not apply that owner's defaults unless the deployment actually creates objects as `migration_owner`, for example after an authorized `SET ROLE`.

New creator roles and new schemas require another run. Schema-wide defaults cannot implement per-table exceptions. There is no event trigger or background reconciler. Coordinate provisioning with migrations: concurrent DDL can create an object between the existing-object scan and the default-ACL update.

## Security limits

- Privileges are additive. `PUBLIC`, direct grants, other group memberships, ownership, and grants in other databases can provide additional access. Existing `PUBLIC` database `TEMPORARY` access is not removed, so reader members may still create and write temporary tables.
- PostgreSQL normally grants routine `EXECUTE` to `PUBLIC`. This wrapper neither adds routine execution nor removes existing public access. A readable view or executable function can expose data or have side effects beyond the profile's direct grants.
- View access can use the view owner's underlying privileges and RLS context unless the view uses applicable invoker-security options. Review views, their functions, and their owners before including their schema.
- RLS policies remain unchanged. The groups do not get `BYPASSRLS` or ownership. Grants alone do not guarantee that rows are visible or writable. Owners and superusers have different RLS behavior.
- Preflight checks run before mutations. Apply uses one transaction and never commits internally. An error rolls back the call's changes. Within an explicit caller transaction, changes remain uncommitted until the caller commits.
- Repeated grants converge without accumulating duplicate ACL entries. Existing grants are reasserted rather than removed. Per-role transaction advisory locks serialize cooperating apply calls in the same database. They do not serialize other tools or calls in different databases. Concurrent role creation may fail safely and require a retry.
- Notices describe attempted operations, not committed transactions. Retain the client's final success or failure alongside notices.

## Versions and Aurora PostgreSQL

Validated locally on **PostgreSQL 17.11 (Debian 17.11-0+deb13u1), x86-64**. No Aurora or RDS database was contacted. Other PostgreSQL major versions are not certified by this repository. The implementation avoids version-specific role-membership option syntax, but the tests include PostgreSQL 16+ membership options.

Aurora administrator roles are not ordinary PostgreSQL superusers. Verify your engine version, role-creation authority, usable creator memberships, object ownership, and grant options in a nonproduction cluster. The procedure supplies no missing authority. Owning the database alone does not authorize grants on every table owned by other roles.

## Run the tests

Use a non-root OS account with PostgreSQL server binaries, psql, Bash, and Python 3 installed. There are no Python package dependencies.

```bash
/workspace/pg-role-manager/tests/run.sh
# If server binaries are not on the pg_config path:
PG_BINDIR=/usr/lib/postgresql/17/bin /workspace/pg-role-manager/tests/run.sh
```

The script starts a fresh, private Unix-socket-only cluster, runs 32 behavioral tests, stops the cluster, and removes its temporary data. It never uses an existing database. Fixture setup uses a local bootstrap superuser. Normal provisioning calls use a non-superuser administrator with `CREATEROLE`, usable creator memberships, and the required grant authority. Reader and writer operations use separate login sessions.

Tests cover current and future objects, multiple creators and schemas, serial and identity inserts, denied operations, RLS, invalid inputs, existing-role conflicts, preview, reruns, transaction rollback, invoker authority, and split grant-option sources.

## PostgreSQL references

- [Database roles](https://www.postgresql.org/docs/17/database-roles.html)
- [GRANT](https://www.postgresql.org/docs/17/sql-grant.html)
- [ALTER DEFAULT PRIVILEGES](https://www.postgresql.org/docs/17/sql-alterdefaultprivileges.html)
- [Row security](https://www.postgresql.org/docs/17/ddl-rowsecurity.html)
- [CREATE PROCEDURE security mode](https://www.postgresql.org/docs/17/sql-createprocedure.html)
- [CREATE VIEW security behavior](https://www.postgresql.org/docs/17/sql-createview.html)

Licensed under the [MIT License](LICENSE).
