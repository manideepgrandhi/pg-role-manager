"""Behavioral tests. Run through run.sh, never against an existing cluster."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
if os.environ.get('RM_ISOLATED_TEST_CLUSTER') != '1':
    raise SystemExit('Run tests/run.sh to create a disposable cluster')


def sql(statement, user='rm_admin', db='rm_suite', ok=True):
    result = subprocess.run(
        ['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose', '-U', user, '-d', db, '-c', statement],
        text=True, capture_output=True, check=False,
    )
    if ok and result.returncode:
        raise AssertionError(f'{statement}\n{result.stderr}')
    if not ok and not result.returncode:
        raise AssertionError(f'Expected failure: {statement}\n{result.stdout}')
    return result


def provision(role, profile='reader', schemas="ARRAY['app']", creators="ARRAY['creator_a','creator_b']", apply='true', existing='true'):
    # Values here are controlled test fixtures, not an application SQL builder.
    return f"CALL role_manager.provision('{role}', '{profile}', {schemas}, {creators}, {apply}, {existing})"


class ProvisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sql('CREATE ROLE rm_admin LOGIN CREATEROLE; CREATE ROLE creator_a; CREATE ROLE creator_b; '
            'CREATE ROLE outsider; CREATE ROLE rm_reader_login LOGIN; CREATE ROLE rm_writer_login LOGIN; '
            'CREATE ROLE limited LOGIN', user='rm_bootstrap', db='postgres')
        sql('CREATE DATABASE rm_suite OWNER rm_admin', user='rm_bootstrap', db='postgres')
        sql('GRANT creator_a, creator_b TO rm_admin', user='rm_bootstrap')
        subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'rm_admin', '-d', 'rm_suite',
                        '-f', str(ROOT / 'sql/pg_role_manager.sql')], check=True, capture_output=True)
        sql('GRANT USAGE ON SCHEMA role_manager TO limited; '
            'GRANT EXECUTE ON PROCEDURE role_manager.provision(text,text,text[],text[],boolean,boolean) TO limited; '
            'CREATE SCHEMA app AUTHORIZATION creator_a; GRANT CREATE, USAGE ON SCHEMA app TO creator_b; '
            'SET ROLE creator_a; CREATE TABLE app.items (id serial PRIMARY KEY, value text); '
            "INSERT INTO app.items(value) VALUES ('before'); "
            'CREATE TABLE app.identity_items (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, value text); '
            'CREATE VIEW app.item_view AS SELECT * FROM app.items; RESET ROLE')
        sql(provision('app_reader'))
        sql(provision('app_writer', 'writer'))
        sql('GRANT app_reader TO rm_reader_login; GRANT app_writer TO rm_writer_login', user='rm_bootstrap')

    def assertDenied(self, statement, user):
        result = sql(statement, user=user, ok=False)
        self.assertIn('42501', result.stderr)

    def test_01_reader_select_existing_table_and_view(self):
        self.assertEqual(sql('SELECT count(*) FROM app.items', user='rm_reader_login').stdout.strip(), '1')
        self.assertEqual(sql('SELECT count(*) FROM app.item_view', user='rm_reader_login').stdout.strip(), '1')

    def test_02_reader_cannot_write_or_use_sequence(self):
        for command in ["INSERT INTO app.items(value) VALUES ('no')", "UPDATE app.items SET value='no'",
                        'DELETE FROM app.items', "SELECT nextval('app.items_id_seq')"]:
            with self.subTest(command=command):
                self.assertDenied(command, 'rm_reader_login')

    def test_03_writer_dml_and_serial_identity(self):
        sql("INSERT INTO app.items(value) VALUES ('writer'); UPDATE app.items SET value='changed' WHERE value='writer'; "
            "DELETE FROM app.items WHERE value='changed'; INSERT INTO app.identity_items(value) VALUES ('identity')", user='rm_writer_login')
        self.assertEqual(sql('SELECT count(*) FROM app.identity_items', user='rm_writer_login').stdout.strip(), '1')

    def test_04_writer_cannot_setval_truncate_create_or_drop(self):
        for command in ["SELECT setval('app.items_id_seq',999)", 'TRUNCATE app.items',
                        'CREATE TABLE app.forbidden(id int)', 'DROP TABLE app.items', 'CREATE ROLE forbidden']:
            with self.subTest(command=command):
                self.assertDenied(command, 'rm_writer_login')

    def test_05_future_objects_multiple_creators(self):
        for creator in ['creator_a', 'creator_b']:
            sql(f'SET ROLE {creator}; CREATE TABLE app.future_{creator}(id serial, value text); '
                f"INSERT INTO app.future_{creator}(value) VALUES ('future'); "
                f'CREATE TABLE app.future_identity_{creator}(id bigint GENERATED ALWAYS AS IDENTITY, value text)')
            sql(f'SELECT * FROM app.future_{creator}', user='rm_reader_login')
            sql(f"INSERT INTO app.future_{creator}(value) VALUES ('writer')", user='rm_writer_login')
            self.assertDenied(f'DELETE FROM app.future_{creator}', 'rm_reader_login')
            sql(f"INSERT INTO app.future_identity_{creator}(value) VALUES ('identity')", user='rm_writer_login')

    def test_06_unlisted_creator_not_covered(self):
        sql('GRANT CREATE, USAGE ON SCHEMA app TO outsider', user='rm_bootstrap')
        sql('SET ROLE outsider; CREATE TABLE app.outsider_table(id int)', user='rm_bootstrap')
        self.assertDenied('SELECT * FROM app.outsider_table', 'rm_reader_login')
        sql('DROP TABLE app.outsider_table', user='rm_bootstrap')

    def test_07_rerun_converges_without_acl_changes(self):
        query = "SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (" \
                "SELECT oid::text || coalesce(relacl::text,'') AS x FROM pg_class WHERE relnamespace='app'::regnamespace " \
                "UNION ALL SELECT oid::text || defaclacl::text FROM pg_default_acl) q"
        before = sql(query).stdout
        sql(provision('app_reader'))
        sql(provision('app_writer', 'writer'))
        self.assertEqual(before, sql(query).stdout)

    def test_08_preview_has_no_side_effects(self):
        before = sql("SELECT count(*) FROM pg_default_acl").stdout
        result = sql(provision('preview_group', apply='false'))
        self.assertIn('PREVIEW: CREATE ROLE', result.stderr)
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='preview_group'").stdout.strip(), '0')
        self.assertEqual(before, sql("SELECT count(*) FROM pg_default_acl").stdout)

    def test_09_invalid_arguments(self):
        calls = [provision('bad', 'admin'), provision('x'*64), provision('pg_forbidden'),
                 provision('PUBLIC'), provision(''), provision('bad', schemas="ARRAY['missing']"),
                 provision('bad', schemas="ARRAY['pg_catalog']"), provision('bad', schemas="ARRAY['information_schema']"),
                 provision('bad', schemas='ARRAY[]::text[]'), provision('bad', creators='NULL'),
                 provision('bad', creators="ARRAY['creator_a',NULL]"), provision('bad', schemas="ARRAY['app','app']"),
                 provision('bad', creators="ARRAY['creator_a','creator_a']"), provision('bad', creators="ARRAY['bad']"),
                 provision('bad', apply='NULL'), provision('bad', schemas="ARRAY[['app'],['app']]"),
                 provision('bad', creators="ARRAY['missing']")]
        for command in calls:
            with self.subTest(command=command):
                sql(command, ok=False)
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='bad'").stdout.strip(), '0')

    def test_10_incompatible_attributes_rejected(self):
        for attribute in ['LOGIN', 'CREATEROLE', 'CREATEDB', 'REPLICATION', 'BYPASSRLS', 'SUPERUSER', 'NOINHERIT']:
            name = 'conflict_' + attribute.lower()
            sql(f'CREATE ROLE {name} {attribute}', user='rm_bootstrap')
            self.assertIn('incompatible attributes', sql(provision(name), ok=False).stderr)

    def test_11_parent_membership_rejected_even_without_inheritance(self):
        sql('CREATE ROLE nested_group; GRANT app_writer TO nested_group WITH INHERIT FALSE', user='rm_bootstrap')
        self.assertIn('refusing reuse', sql(provision('nested_group'), ok=False).stderr)

    def test_12_owner_role_rejected(self):
        sql('CREATE ROLE owner_group; CREATE SCHEMA owned AUTHORIZATION owner_group', user='rm_bootstrap')
        self.assertIn('owns shared or current-database objects', sql(provision('owner_group'), ok=False).stderr)

    def test_13_invoker_cannot_create_role(self):
        self.assertIn('needs CREATEROLE', sql(provision('limited_new'), user='limited', ok=False).stderr)
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='limited_new'").stdout.strip(), '0')

    def test_14_creator_authority_preflight(self):
        self.assertIn('usable privileges of creator', sql(provision('no_creator', creators="ARRAY['outsider']"), ok=False).stderr)
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='no_creator'").stdout.strip(), '0')

    def test_15_existing_object_grant_authority_preflight(self):
        sql('SET ROLE outsider; CREATE TABLE app.blocked(id int)', user='rm_bootstrap')
        try:
            self.assertIn('cannot grant SELECT', sql(provision('no_table_authority'), ok=False).stderr)
            self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='no_table_authority'").stdout.strip(), '0')
        finally:
            sql('DROP TABLE app.blocked', user='rm_bootstrap')

    def test_16_schema_grant_authority_preflight(self):
        sql('CREATE SCHEMA outsider_schema AUTHORIZATION outsider', user='rm_bootstrap')
        self.assertIn('cannot grant USAGE', sql(provision('no_schema_authority', schemas="ARRAY['outsider_schema']"), ok=False).stderr)

    def test_17_transaction_rollback_removes_every_change(self):
        sql('BEGIN; ' + provision('rolled_back') + '; ROLLBACK')
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='rolled_back'").stdout.strip(), '0')
        sql('BEGIN; ' + provision('failed_transaction') + '; SELECT 1/0; COMMIT', ok=False)
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='failed_transaction'").stdout.strip(), '0')

    def test_18_future_only_mode(self):
        sql(provision('future_only', existing='false'))
        self.assertDenied('SET ROLE future_only; SELECT * FROM app.items', 'rm_bootstrap')
        sql('SET ROLE creator_a; CREATE TABLE app.future_only_table(id int)')
        sql('SET ROLE future_only; SELECT * FROM app.future_only_table', user='rm_bootstrap')

    def test_19_identifiers_are_quoted_not_executed(self):
        sql('CREATE SCHEMA "Mixed schema;" AUTHORIZATION creator_a; '
            'SET ROLE creator_a; CREATE TABLE "Mixed schema;"."Odd table"(id int)')
        sql(provision('group; "quoted', schemas='ARRAY[\'Mixed schema;\']', creators="ARRAY['creator_a']"))
        sql('SET ROLE "group; ""quoted"; SELECT * FROM "Mixed schema;"."Odd table"', user='rm_bootstrap')
        sql(provision("quote''role", schemas="ARRAY['app']", existing='false'))
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='quote''role'").stdout.strip(), '1')

    def test_20_no_function_execute_added(self):
        sql("SET ROLE creator_a; CREATE FUNCTION app.restricted() RETURNS int LANGUAGE sql AS 'SELECT 1'; "
            'REVOKE EXECUTE ON FUNCTION app.restricted() FROM PUBLIC')
        self.assertDenied('SELECT app.restricted()', 'rm_reader_login')
        self.assertDenied('SELECT app.restricted()', 'rm_writer_login')

    def test_21_rls_is_not_bypassed(self):
        sql('SET ROLE creator_a; CREATE TABLE app.rls_items(id int); INSERT INTO app.rls_items VALUES (1); '
            'ALTER TABLE app.rls_items ENABLE ROW LEVEL SECURITY')
        self.assertEqual(sql('SELECT count(*) FROM app.rls_items', user='rm_reader_login').stdout.strip(), '0')
        self.assertDenied('INSERT INTO app.rls_items VALUES(2)', 'rm_writer_login')

    def test_22_extra_direct_grants_not_silently_revoked(self):
        sql('CREATE ROLE extra_group; GRANT CREATE ON SCHEMA app TO extra_group', user='rm_bootstrap')
        result = sql(provision('extra_group'))
        self.assertIn('not a complete ACL audit', result.stderr)
        self.assertEqual(sql("SELECT has_schema_privilege('extra_group','app','CREATE')").stdout.strip(), 't')

    def test_23_unlisted_schema_not_covered(self):
        sql('CREATE SCHEMA later_schema AUTHORIZATION creator_a; SET ROLE creator_a; CREATE TABLE later_schema.t(id int)')
        self.assertDenied('SELECT * FROM later_schema.t', 'rm_reader_login')

    def test_24_database_connect_grant_authority(self):
        sql('CREATE ROLE connection_limited LOGIN CREATEROLE; '
            'GRANT USAGE ON SCHEMA role_manager TO connection_limited; '
            'GRANT EXECUTE ON PROCEDURE role_manager.provision(text,text,text[],text[],boolean,boolean) TO connection_limited', user='rm_bootstrap')
        self.assertIn('cannot grant CONNECT', sql(provision('no_connect_authority'), user='connection_limited', ok=False).stderr)
        self.assertEqual(sql("SELECT count(*) FROM pg_roles WHERE rolname='no_connect_authority'").stdout.strip(), '0')

    def test_25_sequence_grant_authority(self):
        sql('SET ROLE outsider; CREATE SEQUENCE app.blocked_seq', user='rm_bootstrap')
        try:
            self.assertIn('cannot grant sequence USAGE', sql(provision('no_sequence_authority', 'writer'), ok=False).stderr)
        finally:
            sql('DROP SEQUENCE app.blocked_seq', user='rm_bootstrap')

    def test_26_defaults_follow_actual_creator_not_membership(self):
        sql('CREATE ROLE indirect_creator; GRANT creator_a TO indirect_creator; '
            'SET ROLE indirect_creator; CREATE TABLE app.indirect_table(id int)', user='rm_bootstrap')
        self.assertDenied('SELECT * FROM app.indirect_table', 'rm_reader_login')
        sql('DROP TABLE app.indirect_table', user='rm_bootstrap')

    def test_27_no_public_execute_on_wrapper(self):
        self.assertEqual(sql("SELECT has_function_privilege('rm_reader_login',"
                             "'role_manager.provision(text,text,text[],text[],boolean,boolean)','EXECUTE')").stdout.strip(), 'f')
        self.assertEqual(sql("SELECT rolsuper FROM pg_roles WHERE rolname=current_user").stdout.strip(), 'f')

    def test_28_grant_options_split_across_parent_roles(self):
        sql('CREATE ROLE select_grantor; CREATE ROLE dml_grantor; '
            'GRANT select_grantor, dml_grantor TO rm_admin; '
            'CREATE SCHEMA split AUTHORIZATION creator_a; GRANT CREATE, USAGE ON SCHEMA split TO outsider; '
            'SET ROLE outsider; CREATE TABLE split.t(id int); RESET ROLE; '
            'GRANT SELECT ON split.t TO select_grantor WITH GRANT OPTION; '
            'GRANT INSERT, UPDATE, DELETE ON split.t TO dml_grantor WITH GRANT OPTION', user='rm_bootstrap')
        result = sql(provision('split_writer', 'writer', schemas="ARRAY['split']", creators="ARRAY['creator_a']"))
        self.assertNotIn('not all privileges were granted', result.stderr)
        sql('SET ROLE split_writer; INSERT INTO split.t VALUES(1); SELECT * FROM split.t; '
            'UPDATE split.t SET id=2; DELETE FROM split.t', user='rm_bootstrap')

    def test_29_reserved_role_names_rejected_in_preview(self):
        for name in ['public', 'none', 'PUBLIC', 'NONE']:
            with self.subTest(name=name):
                sql(provision(name, apply='false'), ok=False)

    def test_30_multiple_schemas_existing_and_future(self):
        sql('CREATE SCHEMA second_app AUTHORIZATION creator_b; '
            'SET ROLE creator_b; CREATE TABLE second_app.existing(id serial)')
        sql(provision('multi_writer', 'writer', schemas="ARRAY['app','second_app']"))
        sql('SET ROLE creator_b; CREATE TABLE second_app.future(id serial)')
        sql('SET ROLE multi_writer; INSERT INTO second_app.existing DEFAULT VALUES; '
            'INSERT INTO second_app.future DEFAULT VALUES; SELECT * FROM app.items', user='rm_bootstrap')

    def test_31_groups_have_no_grant_options_or_privileged_attributes(self):
        self.assertEqual(sql("SELECT rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls "
                             "FROM pg_roles WHERE rolname='app_writer'").stdout.strip(), 'f')
        self.assertEqual(sql("SELECT has_table_privilege('app_writer','app.items','SELECT WITH GRANT OPTION')").stdout.strip(), 'f')
        self.assertEqual(sql("SELECT has_sequence_privilege('app_writer','app.items_id_seq','UPDATE')").stdout.strip(), 'f')
        self.assertDenied('GRANT app_writer TO limited', 'rm_writer_login')

    def test_32_existing_role_preview_changes_no_acls(self):
        query = "SELECT defaclacl::text FROM pg_default_acl ORDER BY oid"
        before = sql(query).stdout
        sql(provision('app_reader', apply='false'))
        self.assertEqual(before, sql(query).stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
