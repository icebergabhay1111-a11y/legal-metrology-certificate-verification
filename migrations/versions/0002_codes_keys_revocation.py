"""Public codes, signing key ids, jurisdiction, revocation, alert codes, report references.

Revision ID: 0002
Revises: 0001

Existing certificates keep their old public code (CERT-0001 style), so
anything already printed still works. New certificates get a random code.
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("certificates") as t:
        t.add_column(sa.Column("code", sa.Text))
        t.add_column(sa.Column("key_id", sa.Text))
        t.add_column(sa.Column("jurisdiction", sa.Text))
        t.add_column(sa.Column("revoked_at", sa.Text))
        t.add_column(sa.Column("revoked_by", sa.Text))
        t.add_column(sa.Column("revoke_reason", sa.Text))
    bind = op.get_bind()
    # Give every existing certificate the code it was already printed with.
    for (cert_id,) in bind.execute(sa.text("SELECT id FROM certificates")).fetchall():
        bind.execute(sa.text("UPDATE certificates SET code = :c WHERE id = :i"),
                     {"c": f"CERT-{cert_id:04d}", "i": cert_id})
    op.create_index("ix_certificates_code", "certificates", ["code"], unique=True)
    op.create_index("ix_certificates_serial", "certificates", ["serial_number"])

    with op.batch_alter_table("fraud_alerts") as t:
        t.add_column(sa.Column("code", sa.Text))
    with op.batch_alter_table("reports") as t:
        t.add_column(sa.Column("reference", sa.Text))


def downgrade():
    with op.batch_alter_table("reports") as t:
        t.drop_column("reference")
    with op.batch_alter_table("fraud_alerts") as t:
        t.drop_column("code")
    op.drop_index("ix_certificates_serial", "certificates")
    op.drop_index("ix_certificates_code", "certificates")
    with op.batch_alter_table("certificates") as t:
        for col in ("revoke_reason", "revoked_by", "revoked_at", "jurisdiction", "key_id", "code"):
            t.drop_column(col)
