-- Verify hosted ledger v0, Postgres (RDS us-east-2). Apply as the migration/owner role, then run the app as verify_app.
-- Append-only: triggers raise on UPDATE/DELETE, and the app role has UPDATE/DELETE revoked.
-- Payloads may be deleted only by the retention role, and only after a tombstone row exists (Trust Pack s.5).

CREATE TABLE IF NOT EXISTS tenant(id TEXT PRIMARY KEY, api_key_sha256 TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS access_log(tenant_id TEXT NOT NULL REFERENCES tenant(id), at TEXT NOT NULL, method TEXT NOT NULL,
  path TEXT NOT NULL, status INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS event(tenant_id TEXT NOT NULL REFERENCES tenant(id), seq BIGINT NOT NULL, run_id TEXT NOT NULL,
  type TEXT NOT NULL, at TEXT NOT NULL, clock_source TEXT NOT NULL, payload_sha256 TEXT NOT NULL, evidence_hash TEXT,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(tenant_id, seq));
CREATE TABLE IF NOT EXISTS event_payload(tenant_id TEXT NOT NULL, seq BIGINT NOT NULL, payload_json TEXT NOT NULL,
  PRIMARY KEY(tenant_id, seq), FOREIGN KEY(tenant_id, seq) REFERENCES event(tenant_id, seq));
CREATE TABLE IF NOT EXISTS tombstone(tenant_id TEXT NOT NULL, seq BIGINT NOT NULL, purged_at TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY(tenant_id, seq), FOREIGN KEY(tenant_id, seq) REFERENCES event(tenant_id, seq));
CREATE TABLE IF NOT EXISTS run(tenant_id TEXT NOT NULL REFERENCES tenant(id), run_id TEXT NOT NULL, contract_id TEXT NOT NULL,
  contract_version TEXT NOT NULL, subject_ref TEXT NOT NULL, actor TEXT NOT NULL, started_at TEXT NOT NULL,
  PRIMARY KEY(tenant_id, run_id));
CREATE TABLE IF NOT EXISTS verdict(tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, verdict TEXT NOT NULL
  CHECK (verdict IN ('pass','fail','inapplicable','not_observed','blocked')), level_reached TEXT NOT NULL,
  independence TEXT NOT NULL, reasons_json TEXT NOT NULL, final_event_seq BIGINT NOT NULL, at TEXT NOT NULL,
  PRIMARY KEY(tenant_id, run_id), FOREIGN KEY(tenant_id, final_event_seq) REFERENCES event(tenant_id, seq));
CREATE INDEX IF NOT EXISTS verdict_at ON verdict(tenant_id, at);
CREATE INDEX IF NOT EXISTS event_run ON event(tenant_id, run_id);

CREATE OR REPLACE FUNCTION verify_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'append-only: % on % is not allowed', TG_OP, TG_TABLE_NAME; END $$;

CREATE OR REPLACE FUNCTION verify_payload_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN RAISE EXCEPTION 'append-only: UPDATE on event_payload is not allowed'; END IF;
  IF NOT EXISTS (SELECT 1 FROM tombstone t WHERE t.tenant_id = OLD.tenant_id AND t.seq = OLD.seq) THEN
    RAISE EXCEPTION 'payload delete requires tombstone (tenant %, seq %)', OLD.tenant_id, OLD.seq;
  END IF;
  RETURN OLD;
END $$;

DO $$ DECLARE t TEXT; BEGIN
  FOREACH t IN ARRAY ARRAY['event','tombstone','run','verdict','access_log'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %1$s_append_only ON %1$I', t);
    EXECUTE format('CREATE TRIGGER %1$s_append_only BEFORE UPDATE OR DELETE ON %1$I FOR EACH ROW EXECUTE FUNCTION verify_append_only()', t);
    -- TRUNCATE bypasses row triggers; block it too
    EXECUTE format('DROP TRIGGER IF EXISTS %1$s_no_truncate ON %1$I', t);
    EXECUTE format('CREATE TRIGGER %1$s_no_truncate BEFORE TRUNCATE ON %1$I EXECUTE FUNCTION verify_append_only()', t);
  END LOOP;
END $$;
DROP TRIGGER IF EXISTS event_payload_guard ON event_payload;
CREATE TRIGGER event_payload_guard BEFORE UPDATE OR DELETE ON event_payload FOR EACH ROW EXECUTE FUNCTION verify_payload_guard();

-- Roles (create once; passwords set out of band via Secrets Manager):
--   CREATE ROLE verify_app LOGIN;  CREATE ROLE verify_retention LOGIN;
GRANT SELECT, INSERT ON tenant, event, event_payload, tombstone, run, verdict, access_log TO verify_app;
REVOKE UPDATE, DELETE, TRUNCATE ON tenant, event, event_payload, tombstone, run, verdict, access_log FROM verify_app;
GRANT SELECT, INSERT ON event, tombstone TO verify_retention;
GRANT SELECT, DELETE ON event_payload TO verify_retention;
REVOKE UPDATE, TRUNCATE ON tenant, event, event_payload, tombstone, run, verdict, access_log FROM verify_retention;
