"""
db.py - the one place that knows which database we are using.

  No DATABASE_URL (your laptop, the tests): a SQLite file, certificates.db.
  DATABASE_URL set (Render):                PostgreSQL on Neon.

Every query in the app goes through here, written with :named parameters,
so the same SQL runs on both. The tables themselves are created and changed
only by migrations in migrations/versions/ - never by hand.
"""

import os

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

HERE = os.path.dirname(os.path.abspath(__file__))
SQLITE_FILE = "certificates.db"


def database_url():
    """DATABASE_URL in the form SQLAlchemy + psycopg expect, or local SQLite."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        return f"sqlite:///{SQLITE_FILE}"
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def _make_engine():
    """Build the connection pool once, at import."""
    url = database_url()
    if url.startswith("sqlite"):
        # NullPool = never hold the file open, so Windows can delete it in tests.
        return create_engine(url, poolclass=NullPool)
    # pre_ping: Neon sleeps after 5 idle minutes, so test a connection before use.
    return create_engine(url, pool_pre_ping=True, pool_size=3, max_overflow=2)


engine = _make_engine()


def fetch_all(sql, **params):
    """Run a SELECT. Rows work as row[0], row.name, or dict(row._mapping)."""
    with engine.connect() as conn:
        return conn.execute(text(sql), params).fetchall()


def fetch_one(sql, **params):
    """First row of a SELECT, or None."""
    rows = fetch_all(sql, **params)
    return rows[0] if rows else None


def run(sql, **params):
    """Run one INSERT / UPDATE / DELETE in its own transaction."""
    with engine.begin() as conn:
        conn.execute(text(sql), params)


def upgrade_to_latest():
    """Apply any migration not yet applied. Safe to call on every start."""
    from alembic import command
    from alembic.config import Config
    cfg = Config()
    cfg.set_main_option("script_location", os.path.join(HERE, "migrations"))
    command.upgrade(cfg, "head")
