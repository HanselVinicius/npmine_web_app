"""add compound group association

Revision ID: 3f6b1aa19db2
Revises: 8c1c6e7f0c2a
Create Date: 2026-05-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3f6b1aa19db2'
down_revision = '8c1c6e7f0c2a'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'compound_group',
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('compound_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['compound_id'], ['compounds.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('group_id', 'compound_id')
    )


def downgrade():
    op.drop_table('compound_group')
