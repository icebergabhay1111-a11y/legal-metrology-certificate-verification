"""Alembic entry point. Uses the same engine as the app - no second config."""
from alembic import context

import db


def run_migrations_online():
    """Open one connection and apply the pending migrations inside it."""
    with db.engine.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
