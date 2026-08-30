"""add group membership roles

Revision ID: 6d3d7e9a2f41
Revises: 3f6b1aa19db2
Create Date: 2026-07-14 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6d3d7e9a2f41'
down_revision = '3f6b1aa19db2'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'accounts_groups',
        sa.Column('role', sa.String(length=20), nullable=False, server_default='member')
    )


def downgrade():
    op.drop_column('accounts_groups', 'role')
