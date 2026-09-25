"""The five tables as they stood on 25 September 2026.

Revision ID: 0001
Revises:
Each table is created only if missing, so a laptop that already has an
old certificates.db from before migrations existed upgrades cleanly.
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _create_if_missing(name, *columns):
    """Create a table unless an older version of the app already made it."""
    if not sa.inspect(op.get_bind()).has_table(name):
        # sqlite_autoincrement: an id is never reused, so a printed CERT-0005
        # can never later point at a different certificate.
        op.create_table(name, sa.Column("id", sa.Integer, primary_key=True), *columns,
                        sqlite_autoincrement=True)


def upgrade():
    _create_if_missing(
        "certificates",
        sa.Column("serial_number", sa.Text, nullable=False),
        sa.Column("owner_name", sa.Text, nullable=False),
        sa.Column("instrument_type", sa.Text, nullable=False),
        sa.Column("verification_date", sa.Text, nullable=False),
        sa.Column("expiry_date", sa.Text, nullable=False),
        sa.Column("instrument_class", sa.Text),
        sa.Column("max_permissible_error", sa.Text),
        sa.Column("reverification_months", sa.Integer),
        sa.Column("officer_id", sa.Integer),
        sa.Column("officer_name", sa.Text),
        sa.Column("signature", sa.Text),
        sa.Column("state_code", sa.Text),
    )
    _create_if_missing(
        "fraud_alerts",
        sa.Column("at", sa.Text, nullable=False),
        sa.Column("certificate_code", sa.Text),
        sa.Column("serial_number", sa.Text),
        sa.Column("officer_name", sa.Text),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="open"),
    )
    _create_if_missing(
        "users",
        sa.Column("username", sa.Text, nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("full_name", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("state_code", sa.Text),
        sa.Column("jurisdiction", sa.Text),
    )
    _create_if_missing(
        "audit",
        sa.Column("at", sa.Text, nullable=False),
        sa.Column("actor_id", sa.Integer),
        sa.Column("actor_name", sa.Text, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("target", sa.Text),
        sa.Column("detail", sa.Text),
    )
    _create_if_missing(
        "reports",
        sa.Column("at", sa.Text, nullable=False),
        sa.Column("serial_number", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="open"),
    )


def downgrade():
    for name in ("reports", "audit", "users", "fraud_alerts", "certificates"):
        op.drop_table(name)
