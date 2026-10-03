"""Traders linked to their firm; verification applications; reports by State.

Revision ID: 0005
Revises: 0004

A trader account names the firm it acts for, so the trader can see that
firm's certificates. An application is a trader's request to have an
instrument verified; an officer turns it into a certificate or declines it.
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as t:
        t.add_column(sa.Column("firm_name", sa.Text))
    op.create_table(
        "applications",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("reference", sa.Text, nullable=False, unique=True),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("trader_id", sa.Integer, nullable=False),
        sa.Column("firm_name", sa.Text, nullable=False),
        sa.Column("serial_number", sa.Text, nullable=False),
        sa.Column("instrument_type", sa.Text, nullable=False),
        sa.Column("state_code", sa.Text, nullable=False),
        sa.Column("jurisdiction", sa.Text),
        sa.Column("address", sa.Text),
        sa.Column("note", sa.Text),
        sa.Column("status", sa.Text, nullable=False, server_default="submitted"),
        sa.Column("certificate_code", sa.Text),
        sa.Column("decided_by", sa.Text),
        sa.Column("decided_at", sa.Text),
        sa.Column("decision_note", sa.Text),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_applications_state_status", "applications", ["state_code", "status"])
    with op.batch_alter_table("reports") as t:
        t.add_column(sa.Column("state_code", sa.Text))
        t.add_column(sa.Column("closed_by", sa.Text))
        t.add_column(sa.Column("closed_at", sa.Text))
        t.add_column(sa.Column("outcome", sa.Text))
    op.get_bind().execute(sa.text(
        "UPDATE users SET firm_name = 'Sharma Weighbridge Co. (sample)' WHERE username = 'trader1'"))


def downgrade():
    with op.batch_alter_table("reports") as t:
        for col in ("outcome", "closed_at", "closed_by", "state_code"):
            t.drop_column(col)
    op.drop_index("ix_applications_state_status", "applications")
    op.drop_table("applications")
    with op.batch_alter_table("users") as t:
        t.drop_column("firm_name")
