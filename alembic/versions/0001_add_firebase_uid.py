"""add firebase_uid to users

Revision ID: 0001_add_firebase_uid
Create Date: 2026-09-23
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0001_add_firebase_uid'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """أضف عمود firebase_uid إلى جدول users (nullable، unique، indexed)."""
    op.add_column(
        'users',
        sa.Column(
            'firebase_uid',
            sa.String(length=128),
            nullable=True,
        ),
    )
    op.create_index(
        'ix_users_firebase_uid',
        'users',
        ['firebase_uid'],
        unique=True,
    )

    # اجعل password_hash nullable لأن مستخدمي Firebase ليس لديهم كلمة مرور
    op.alter_column(
        'users',
        'password_hash',
        existing_type=sa.String(length=255),
        nullable=True,
    )


def downgrade() -> None:
    """ارجع التررحيل."""
    op.alter_column(
        'users',
        'password_hash',
        existing_type=sa.String(length=255),
        nullable=False,
    )
    op.drop_index('ix_users_firebase_uid', table_name='users')
    op.drop_column('users', 'firebase_uid')
