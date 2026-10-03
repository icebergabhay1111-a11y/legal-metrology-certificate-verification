"""Hash chain on the audit log.

Revision ID: 0003
Revises: 0002

Rows written before this migration have no hash and are skipped by the
check; every row after it is chained to the one before.
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("audit") as t:
        t.add_column(sa.Column("prev_hash", sa.Text))
        t.add_column(sa.Column("row_hash", sa.Text))


def downgrade():
    with op.batch_alter_table("audit") as t:
        t.drop_column("row_hash")
        t.drop_column("prev_hash")
