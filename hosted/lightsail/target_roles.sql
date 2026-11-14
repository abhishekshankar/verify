-- NEW EMPTY TARGET ONLY; run as its local postgres administrator.
-- Intentionally errors if a role already exists. Inspect existing state instead of overwriting.
\set ON_ERROR_STOP on
BEGIN;
CREATE ROLE verify_owner NOLOGIN;
CREATE ROLE verify_app NOLOGIN;
CREATE ROLE verify_retention NOLOGIN;
CREATE ROLE verify_runtime LOGIN INHERIT IN ROLE verify_app;
CREATE ROLE verify_maintenance LOGIN INHERIT IN ROLE verify_owner, verify_retention;
COMMIT;
-- Set the two new login passwords privately with psql's \password command.
-- Restore actual source schema ownership/ACLs before using either login.
