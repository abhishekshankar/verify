-- READ ONLY: psql service=verify_source -X -A -t -f source_preflight.sql > source.json
-- Use a private service/passfile with sslmode=verify-full; never put credentials in argv.
\set ON_ERROR_STOP on
BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '30s';
SELECT json_build_object(
  'capturedAtUtc', to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'database', current_database(),
  'serverVersionNum', current_setting('server_version_num'),
  'serverEncoding', current_setting('server_encoding'),
  'sslConnection', (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()),
  'rdsLogicalReplication', current_setting('rds.logical_replication', true),
  'walLevel', current_setting('wal_level'),
  'replicationRole', COALESCE((SELECT pg_has_role(current_user, oid, 'MEMBER') FROM pg_roles WHERE rolname = 'rds_replication'), false),
  'freeReplicationSlots', current_setting('max_replication_slots')::int - (SELECT count(*) FROM pg_replication_slots),
  'maxWalSenders', current_setting('max_wal_senders')::int,
  'largeObjects', (SELECT count(*) FROM pg_largeobject_metadata),
  'sequences', (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema')),
  'extensions', (SELECT json_agg(extname ORDER BY extname) FROM pg_extension),
  'otherUserRelations', (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' AND c.relkind IN ('v','m','f','p')),
  'databaseBytes', pg_database_size(current_database()),
  'tables', (SELECT json_agg(json_build_object(
      'schema', n.nspname, 'name', c.relname, 'rls', c.relrowsecurity,
      'bytes', pg_total_relation_size(c.oid), 'selectPrivilege', has_table_privilege(current_user, c.oid, 'SELECT'),
      'primaryKey', EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype='p'),
      'replicaOrAlwaysTriggers', EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal AND t.tgenabled IN ('R','A')),
      'blocksUpdateDelete', EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
          WHERE t.tgrelid=c.oid AND t.tgenabled='O' AND (t.tgtype::int & 24)=24 AND p.proname='verify_append_only'),
      'blocksTruncate', EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
          WHERE t.tgrelid=c.oid AND t.tgenabled='O' AND (t.tgtype::int & 32)=32 AND p.proname='verify_append_only')
    ) ORDER BY n.nspname, c.relname)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind='r' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema')
);
ROLLBACK;
