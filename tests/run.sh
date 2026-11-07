#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PG_BINDIR=${PG_BINDIR:-$(pg_config --bindir)}
for tool in initdb pg_ctl; do
    [[ -x "$PG_BINDIR/$tool" ]] || { echo "Missing $PG_BINDIR/$tool; install PostgreSQL server or set PG_BINDIR" >&2; exit 1; }
done
command -v psql >/dev/null
command -v python3 >/dev/null
TMP=$(mktemp -d "${TMPDIR:-/tmp}/pg-role-manager.XXXXXXXX")
cleanup() {
    "$PG_BINDIR/pg_ctl" -D "$TMP/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf -- "$TMP"
}
trap cleanup EXIT
"$PG_BINDIR/initdb" -D "$TMP/data" -U rm_bootstrap --no-locale --encoding=UTF8 --auth-local=trust --auth-host=reject >"$TMP/init.log"
"$PG_BINDIR/pg_ctl" -D "$TMP/data" -l "$TMP/server.log" -o "-k '$TMP' -p 55439 -c listen_addresses=''" -w start >/dev/null
export PGHOST="$TMP" PGPORT=55439 PGUSER=rm_bootstrap PGDATABASE=postgres
export RM_ISOLATED_TEST_CLUSTER=1
unset PGHOSTADDR PGSERVICE PGSERVICEFILE PGOPTIONS
psql -X -At -c 'SELECT version()'
python3 "$ROOT/tests/test_provision.py"
