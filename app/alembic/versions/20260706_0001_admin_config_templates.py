"""create admin config template tables

Revision ID: 20260706_0001
Revises:
Create Date: 2026-07-06
"""

from alembic import op
import sqlalchemy as sa


revision = "20260706_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_config_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("sort_order", sa.Integer(), server_default="100", nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_admin_config_templates_active_order",
        "admin_config_templates",
        ["is_active", "sort_order", "id"],
    )

    op.create_table(
        "admin_config_rotation_state",
        sa.Column("key", sa.String(length=100), primary_key=True),
        sa.Column("last_index", sa.Integer(), server_default="-1", nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("admin_config_rotation_state")
    op.drop_index(
        "ix_admin_config_templates_active_order",
        table_name="admin_config_templates",
    )
    op.drop_table("admin_config_templates")
