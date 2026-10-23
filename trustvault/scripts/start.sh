#!/bin/sh
# Container entry point: prepare the schema, optionally seed demo data, then serve.
set -eu
python -m trustvault init-db
if [ "${TV_SEED_DEMO:-false}" = "true" ]; then
  python -m trustvault seed-demo
fi
exec gunicorn -c gunicorn.conf.py trustvault.wsgi:app
