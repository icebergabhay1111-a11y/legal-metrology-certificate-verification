"""admin1 covers the whole State, not a district called "State HQ".

Revision ID: 0004
Revises: 0003

Databases created before 2 October 2026 gave admin1 the jurisdiction
"State HQ". The district fraud check (LM-202) would then flag every
certificate admin1 issues. An empty jurisdiction means the whole State.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().execute(sa.text(
        "UPDATE users SET jurisdiction = '' WHERE username = 'admin1' AND jurisdiction = 'State HQ'"))


def downgrade():
    pass    # nothing to undo: the old value was wrong
