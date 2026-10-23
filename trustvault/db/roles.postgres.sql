-- Optional hardening for PostgreSQL: run the application as a role that cannot
-- change or remove audit evidence even if the application is compromised.
-- Run as the database owner AFTER `python -m trustvault init-db`.

CREATE ROLE trustvault_app LOGIN PASSWORD 'change-me';

GRANT CONNECT ON DATABASE trustvault TO trustvault_app;
GRANT USAGE ON SCHEMA public TO trustvault_app;

-- Ordinary tables: full data access, no DDL.
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, documents, document_versions, blobs, grants TO trustvault_app;

-- Evidence tables: append and read only. Together with the triggers this means even
-- the application's own credentials cannot rewrite history.
GRANT SELECT, INSERT ON audit_events, audit_checkpoints TO trustvault_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, audit_checkpoints FROM trustvault_app;

-- Then set TV_DATABASE_URL to connect as trustvault_app, and keep the owner
-- credentials (needed only for init-db/migrations) out of the running service.
