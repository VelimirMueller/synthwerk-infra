-- Roles, schemas and databases for the Synthwerk services. Run by the one-shot
-- service database-init on every `docker compose up`, so it is idempotent:
-- a second run changes nothing except the passwords (a rotated .env applies).
--
-- psql variables (set with -v, never written here):
--   identity_password, llm_password, zitadel_password
--
-- Layout:
--   database synthwerk: schema identity (role identity), schema llm (role llm)
--   database zitadel:   owned by role zitadel (Zitadel creates its own schemas)

\set ON_ERROR_STOP on

-- Roles. CREATE ROLE has no IF NOT EXISTS: build it with \gexec.
SELECT format('CREATE ROLE %I LOGIN', r)
FROM unnest(ARRAY['identity', 'llm', 'zitadel']) AS r
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r)
\gexec

ALTER ROLE identity WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'identity_password';
ALTER ROLE llm      WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'llm_password';
ALTER ROLE zitadel  WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'zitadel_password';

-- Each service sees only its own schema.
ALTER ROLE identity SET search_path = identity;
ALTER ROLE llm      SET search_path = llm;

-- Database zitadel. CREATE DATABASE cannot run in a transaction or DO block.
SELECT 'CREATE DATABASE zitadel OWNER zitadel'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'zitadel')
\gexec

-- Connect rights: only the owner role reaches each database.
-- The superuser (pulse, admin work) is not affected by these grants.
REVOKE CONNECT, TEMPORARY ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT, TEMPORARY ON DATABASE zitadel FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE zitadel TO zitadel;
SELECT format('REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database())
\gexec
-- CREATE as well: the service migrations start with CREATE SCHEMA IF NOT EXISTS,
-- and Postgres checks the CREATE right before it checks that the schema exists.
-- A role can make new schemas of its own, but it gets no rights on the others.
SELECT format('GRANT CONNECT, CREATE ON DATABASE %I TO identity, llm', current_database())
\gexec

-- Schemas in the current database (synthwerk).
CREATE SCHEMA IF NOT EXISTS identity AUTHORIZATION identity;
CREATE SCHEMA IF NOT EXISTS llm      AUTHORIZATION llm;
ALTER SCHEMA identity OWNER TO identity;
ALTER SCHEMA llm      OWNER TO llm;

-- No rights in the public schema (Postgres 15+ gives PUBLIC only USAGE there).
REVOKE ALL ON SCHEMA public FROM PUBLIC;
