"""Phase 1 hardening: signing_keys is append-only for the app role, e-mails are stored lower-case,
and the migrating role is a member of the app role.

- ``signing_keys`` is only a published copy of public keys (custody verification trusts keys from
  outside the database), but the app role must still not be able to rewrite or delete it:
  SELECT and INSERT only.
- ``users.email`` values are lower-cased and a CHECK keeps them that way, so the application's
  lower-case lookups and the citext UNIQUE constraint agree.
- ``GRANT dfirbench_app TO CURRENT_USER`` lets a non-superuser owner login use
  ``SET ROLE dfirbench_app`` (``DATABASE_APP_ROLE``).

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-28 16:10:00+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
EMAIL_CHECK = "ck_users_email_lowercase"


def upgrade() -> None:
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON signing_keys FROM {APP_ROLE}")
    op.execute(
        "UPDATE users SET email = lower(email::text) WHERE email::text <> lower(email::text)"
    )
    op.create_check_constraint(
        EMAIL_CHECK.removeprefix("ck_users_"), "users", "email::text = lower(email::text)"
    )
    op.execute(f"GRANT {APP_ROLE} TO CURRENT_USER")


def downgrade() -> None:
    op.execute(f"REVOKE {APP_ROLE} FROM CURRENT_USER")
    op.drop_constraint(op.f(EMAIL_CHECK), "users", type_="check")
    op.execute(f"GRANT UPDATE, DELETE ON signing_keys TO {APP_ROLE}")
