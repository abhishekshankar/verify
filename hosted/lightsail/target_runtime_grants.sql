-- NEW TARGET ONLY, after the exact reviewed source schema and ACLs are restored.
-- Runtime currently serializes tenant appends with SELECT ... FOR UPDATE.
-- PostgreSQL requires UPDATE privilege on at least one column to acquire that lock.
-- api_key_sha256 is already mutable through the documented rotate-key admin CLI.
-- Do not grant UPDATE on immutable tenant IDs or append-only ledger records.
\set ON_ERROR_STOP on
BEGIN;
GRANT UPDATE (api_key_sha256) ON public.tenant TO verify_app;
COMMIT;
