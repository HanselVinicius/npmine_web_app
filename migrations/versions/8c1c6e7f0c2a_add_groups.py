"""add groups

Revision ID: 8c1c6e7f0c2a
Revises: b9b0f7c3d1aa
Create Date: 2026-05-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8c1c6e7f0c2a'
down_revision = 'b9b0f7c3d1aa'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'groups',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['accounts.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'accounts_groups',
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('account_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('group_id', 'account_id')
    )


def downgrade():
    op.drop_table('accounts_groups')
    op.drop_table('groups')
