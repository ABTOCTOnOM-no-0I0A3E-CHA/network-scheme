#!/bin/sh
# Runs once on first start of the postgres container (as the bootstrap superuser,
# against $POSTGRES_DB). Passwords are read by psql itself from docker secrets
# files, so they never appear in argv or in a shell-built SQL string; the SQL
# quotes them with format('%L').
set -eu

secrets=/run/secrets
db="${POSTGRES_DB:?POSTGRES_DB must be set}"

for name in db_migrator_password db_api_password db_cli_password; do
	[ -s "$secrets/$name" ] || { echo "missing or empty secret: $name" >&2; exit 1; }
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" -v db="$db" <<'SQL'
\set migrator_pw `cat /run/secrets/db_migrator_password`
\set api_pw `cat /run/secrets/db_api_password`
\set cli_pw `cat /run/secrets/db_cli_password`

SELECT format('CREATE ROLE nms_migrator LOGIN PASSWORD %L', :'migrator_pw') \gexec
SELECT format('CREATE ROLE nms_api LOGIN PASSWORD %L', :'api_pw') \gexec
SELECT format('CREATE ROLE nms_cli LOGIN PASSWORD %L', :'cli_pw') \gexec

SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \gexec
-- The application roles reach no other database (template0 refuses connections already).
REVOKE ALL ON DATABASE postgres, template1 FROM PUBLIC;
SELECT format('GRANT CONNECT ON DATABASE %I TO nms_migrator, nms_api, nms_cli', :'db') \gexec
SELECT format('GRANT CREATE ON DATABASE %I TO nms_migrator', :'db') \gexec

REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA core AUTHORIZATION nms_migrator;
CREATE SCHEMA audit AUTHORIZATION nms_migrator;
SQL
