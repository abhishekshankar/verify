-- NEW PRIVATE TARGET ONLY, after restoring the exact schema and target runtime grants.
-- Run as the target administrator. Every synthetic row is rolled back.
-- This checks the runtime role's actual row-lock, insert and key-rotation abilities.
\set ON_ERROR_STOP on
\if :{?expected_database}
\else
  \set expected_database verify
\endif
BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '5s';
SELECT set_config('verify.expected_database', :'expected_database', true);
SET LOCAL ROLE verify_runtime;
DO $$
DECLARE
  test_tenant text := '__migration_preflight_' || md5(random()::text || clock_timestamp()::text);
  tab text;
BEGIN
  IF current_database() <> current_setting('verify.expected_database') OR current_setting('server_version_num')::int / 10000 <> 16 THEN
    RAISE EXCEPTION 'Unexpected target identity';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication)) THEN
    RAISE EXCEPTION 'Runtime role is overprivileged';
  END IF;
  FOREACH tab IN ARRAY ARRAY['tenant','event','event_payload','tombstone','run','verdict','access_log'] LOOP
    IF NOT has_table_privilege(current_user, 'public.' || tab, 'SELECT')
       OR NOT has_table_privilege(current_user, 'public.' || tab, 'INSERT') THEN
      RAISE EXCEPTION 'Runtime role lacks a required table privilege';
    END IF;
    IF has_table_privilege(current_user, 'public.' || tab, 'DELETE')
       OR has_table_privilege(current_user, 'public.' || tab, 'TRUNCATE') THEN
      RAISE EXCEPTION 'Runtime role can delete or truncate ledger data';
    END IF;
  END LOOP;
  INSERT INTO public.tenant VALUES (test_tenant, md5(test_tenant), '2000-01-01T00:00:00Z');
  PERFORM 1 FROM public.tenant WHERE id=test_tenant FOR UPDATE;
  UPDATE public.tenant SET api_key_sha256=md5(test_tenant || 'rotated') WHERE id=test_tenant;
  IF has_column_privilege(current_user, 'public.tenant', 'id', 'UPDATE') THEN
    RAISE EXCEPTION 'Runtime role can alter immutable tenant identifiers';
  END IF;
  INSERT INTO public.event VALUES (test_tenant, 1, 'migration-rehearsal', 'action_claimed',
      '2000-01-01T00:00:00Z', 'system', md5('{}'), NULL, '', md5(test_tenant));
  INSERT INTO public.event_payload VALUES (test_tenant, 1, '{}');
  INSERT INTO public.access_log VALUES (test_tenant, '2000-01-01T00:00:00Z', 'GET', '/v1/verify-chain', 200);
END $$;
SELECT 'RUNTIME_ROLE_PREFLIGHT_PASSED_ROLLED_BACK' AS status;
ROLLBACK;
