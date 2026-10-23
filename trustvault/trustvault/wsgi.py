"""WSGI entry point for gunicorn. The schema is created once by `python -m trustvault init-db`
in the start script, not by every worker, so concurrent workers never race on DDL."""
from . import create_app

app = create_app(create_tables=False)
