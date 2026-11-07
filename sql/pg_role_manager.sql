\set ON_ERROR_STOP on
BEGIN;
-- Install as a trusted DBA. Keep this schema unwritable by application users.
CREATE SCHEMA IF NOT EXISTS role_manager;
REVOKE CREATE ON SCHEMA role_manager FROM PUBLIC;

CREATE OR REPLACE PROCEDURE role_manager.provision(
    p_role text,
    p_profile text,
    p_schemas text[],
    p_creators text[],
    p_apply boolean DEFAULT false,
    p_existing boolean DEFAULT true
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $procedure$
DECLARE
    actor record;
    target record;
    creator text;
    schema_name text;
    item record;
    permission text;
    permissions text[];
    commands text[] := ARRAY[]::text[];
    command text;
    db_oid oid;
BEGIN
    IF p_role IS NULL OR p_role = '' OR octet_length(p_role) > 63
       OR p_role ~ '^pg_' OR lower(p_role) IN ('public', 'none') THEN
        RAISE EXCEPTION 'Invalid group role name (nonempty, at most 63 bytes, not pg_*, public, or none)';
    END IF;
    IF p_profile IS NULL OR p_profile NOT IN ('reader', 'writer') THEN
        RAISE EXCEPTION 'Profile must be reader or writer';
    END IF;
    IF p_apply IS NULL OR p_existing IS NULL THEN
        RAISE EXCEPTION 'Mode flags must not be NULL';
    END IF;
    IF p_schemas IS NULL OR cardinality(p_schemas) = 0
       OR array_ndims(p_schemas) <> 1
       OR p_creators IS NULL OR cardinality(p_creators) = 0
       OR array_ndims(p_creators) <> 1 THEN
        RAISE EXCEPTION 'Supply nonempty one-dimensional schema and creator arrays';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p_schemas) s(name)
               WHERE name IS NULL OR name = '' OR octet_length(name) > 63
                  OR name ~ '^pg_' OR name = 'information_schema')
       OR EXISTS (SELECT 1 FROM unnest(p_creators) c(name)
                  WHERE name IS NULL OR name = '' OR octet_length(name) > 63
                     OR name = p_role)
       OR cardinality(p_schemas) <> (SELECT count(DISTINCT name) FROM unnest(p_schemas) s(name))
       OR cardinality(p_creators) <> (SELECT count(DISTINCT name) FROM unnest(p_creators) c(name)) THEN
        RAISE EXCEPTION 'Invalid, duplicate, or system schema/creator names; target cannot be a creator';
    END IF;

    -- Serialize cooperating calls in this database. Never acquire locks in preview.
    IF p_apply THEN
        PERFORM pg_advisory_xact_lock(hashtext('role_manager.provision'), hashtext(p_role));
    END IF;
    SELECT * INTO actor FROM pg_roles WHERE rolname = current_user;
    SELECT oid INTO db_oid FROM pg_database WHERE datname = current_database();
    SELECT * INTO target FROM pg_roles WHERE rolname = p_role;
    IF FOUND THEN
        IF target.rolcanlogin OR target.rolsuper OR target.rolcreaterole
           OR target.rolcreatedb OR target.rolreplication OR target.rolbypassrls
           OR NOT target.rolinherit THEN
            RAISE EXCEPTION 'Existing role % has incompatible attributes', p_role;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = target.oid) THEN
            RAISE EXCEPTION 'Existing role % inherits or can SET ROLE to another role; refusing reuse', p_role;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_shdepend
                   WHERE refclassid = 'pg_authid'::regclass AND refobjid = target.oid
                     AND deptype = 'o' AND dbid IN (0, db_oid)) THEN
            RAISE EXCEPTION 'Existing role % owns shared or current-database objects; refusing reuse', p_role;
        END IF;
        RAISE WARNING 'Reusing %: attributes, parent memberships and local/shared ownership checked, not a complete ACL audit. Existing direct grants, PUBLIC access and other databases may add privileges.', p_role;
    ELSE
        IF NOT (actor.rolsuper OR actor.rolcreaterole) THEN
            RAISE EXCEPTION 'Caller % needs CREATEROLE to create %', current_user, p_role;
        END IF;
        commands := array_append(commands, format(
            'CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', p_role));
    END IF;

    IF NOT has_database_privilege(current_user, db_oid, 'CONNECT WITH GRANT OPTION') THEN
        RAISE EXCEPTION 'Caller % cannot grant CONNECT on current database', current_user;
    END IF;
    commands := array_append(commands, format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), p_role));
    permissions := CASE p_profile WHEN 'reader' THEN ARRAY['SELECT']
                   ELSE ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] END;

    FOREACH creator IN ARRAY p_creators LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = creator) THEN
            RAISE EXCEPTION 'Creator role % does not exist', creator;
        END IF;
        -- Deliberately require usable creator privileges, not just membership.
        IF NOT pg_has_role(current_user, creator, 'USAGE') THEN
            RAISE EXCEPTION 'Caller % must have usable privileges of creator % (or invoke as that creator)', current_user, creator;
        END IF;
    END LOOP;

    FOREACH schema_name IN ARRAY p_schemas LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = schema_name) THEN
            RAISE EXCEPTION 'Schema % does not exist', schema_name;
        END IF;
        IF NOT has_schema_privilege(current_user, schema_name, 'USAGE WITH GRANT OPTION') THEN
            RAISE EXCEPTION 'Caller % cannot grant USAGE on schema %', current_user, schema_name;
        END IF;
        commands := array_append(commands, format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, p_role));
        IF p_existing THEN
            FOR item IN SELECT c.oid, c.relname, c.relkind
                        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = schema_name AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                        ORDER BY c.oid LOOP
                IF item.relkind = 'S' THEN
                    IF p_profile = 'writer' THEN
                        IF NOT has_sequence_privilege(current_user, item.oid, 'USAGE WITH GRANT OPTION') THEN
                            RAISE EXCEPTION 'Caller % cannot grant sequence USAGE on %.%', current_user, schema_name, item.relname;
                        END IF;
                        commands := array_append(commands, format('GRANT USAGE ON SEQUENCE %I.%I TO %I', schema_name, item.relname, p_role));
                    END IF;
                ELSE
                    FOREACH permission IN ARRAY permissions LOOP
                        IF NOT has_table_privilege(current_user, item.oid, permission || ' WITH GRANT OPTION') THEN
                            RAISE EXCEPTION 'Caller % cannot grant % on %.%', current_user, permission, schema_name, item.relname;
                        END IF;
                        -- Separate grants can select different authorized grantor roles.
                        commands := array_append(commands, format('GRANT %s ON TABLE %I.%I TO %I', permission, schema_name, item.relname, p_role));
                    END LOOP;
                END IF;
            END LOOP;
        END IF;
        FOREACH creator IN ARRAY p_creators LOOP
            commands := array_append(commands, format(
                'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT %s ON TABLES TO %I',
                creator, schema_name, array_to_string(permissions, ', '), p_role));
            IF p_profile = 'writer' THEN
                commands := array_append(commands, format(
                    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT USAGE ON SEQUENCES TO %I',
                    creator, schema_name, p_role));
            END IF;
        END LOOP;
    END LOOP;

    FOREACH command IN ARRAY commands LOOP
        RAISE NOTICE '%: %;', CASE WHEN p_apply THEN 'APPLY' ELSE 'PREVIEW' END, command;
        IF p_apply THEN
            EXECUTE command;
        END IF;
    END LOOP;
    RAISE NOTICE '% complete: % statements, database %, profile %. Existing extra privileges are not revoked.',
        CASE WHEN p_apply THEN 'Apply' ELSE 'Preview' END, cardinality(commands), current_database(), p_profile;
END;
$procedure$;
REVOKE ALL ON PROCEDURE role_manager.provision(text, text, text[], text[], boolean, boolean) FROM PUBLIC;
COMMIT;
