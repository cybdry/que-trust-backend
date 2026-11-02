"""${message}"""
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}


def upgrade() -> None: ...


def downgrade() -> None: ...
