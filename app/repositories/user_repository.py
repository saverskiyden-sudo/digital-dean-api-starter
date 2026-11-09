"""Persistent account operations on separate short connections (practice 5).

Every operation opens its own connection (open_database) and closes it; there
is no shared connection between threads. All external values are bound as SQL
parameters. The KDF runs before the write transaction to keep it short.
"""
from pathlib import Path
import sqlite3

from app.db.connection import open_database, write_transaction
from app.schemas.user_account import UserCreate, UserPublic
from app.security.passwords import (
    RECORD_PREFIX, make_password_record, verify_password,
)

_PUBLIC_COLUMNS = 'SELECT id, name, email, login, status_id FROM "user" WHERE id = ?'
ACTIVE = 1
BLOCKED = 2
# Well-formed record that matches no password: an unknown login still costs one
# KDF run, so its timing is closer to a wrong password (not a full defence).
_DUMMY_RECORD = RECORD_PREFIX + "0" * 64
_DUMMY_SALT = "0" * 32


def _public(row) -> UserPublic:
    return UserPublic(id=row["id"], name=row["name"], email=row["email"],
                      login=row["login"], status_id=row["status_id"])


class UserNotFound(Exception):
    """No account with the requested id."""


class UserConflict(Exception):
    """The canonical login or email is already used."""


class UserReferenced(Exception):
    """Academic records prohibit physical deletion."""


class UserRepository:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)

    def register_user(self, data: UserCreate) -> UserPublic:
        """TODO: hash, parameterized INSERT, transaction, safe output.

        Do not assign privileged roles or accept client id/hash/salt fields.
        Return only id, name, email, login, status_id. Map UNIQUE conflicts to
        UserConflict; preserve the database on failure. No shared connection.
        """
        record, salt = make_password_record(data.password.get_secret_value())
        values = (data.name, str(data.email), data.login, record, salt, data.status_id)
        with open_database(self.database_path) as con:
            try:
                with write_transaction(con):
                    cursor = con.execute(
                        'INSERT INTO "user"(name, email, login, password, salt, status_id) '
                        "VALUES (?, ?, ?, ?, ?, ?)", values)
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError as exc:
                if "UNIQUE" in str(exc):
                    raise UserConflict() from None
                raise
        return UserPublic(id=user_id, name=data.name, email=str(data.email),
                          login=data.login, status_id=data.status_id)

    def delete_user(self, user_id: int) -> None:
        """TODO: DELETE in one transaction; missing -> UserNotFound.

        A grade reference to this user as student OR teacher -> UserReferenced.
        Check user existence and grade references inside the SAME write
        transaction as DELETE; retain FK enforcement as the database backstop.
        Roll back the whole transaction, including any role cascades. Never
        manually delete grades to make the account DELETE succeed.
        """
        with open_database(self.database_path) as con, write_transaction(con):
            if con.execute('SELECT 1 FROM "user" WHERE id = ?', (user_id,)).fetchone() is None:
                raise UserNotFound()
            referenced = con.execute(
                "SELECT 1 FROM grade WHERE student_id = ? OR teacher_id = ? LIMIT 1",
                (user_id, user_id)).fetchone()
            if referenced is not None:
                raise UserReferenced()
            try:
                con.execute('DELETE FROM "user" WHERE id = ?', (user_id,))
            except sqlite3.IntegrityError:
                # FK RESTRICT is the database backstop; the whole transaction rolls back.
                raise UserReferenced() from None

    def block_user(self, user_id: int) -> UserPublic:
        """Set status_id=2 only; other fields unchanged; repeat is safe (200)."""
        with open_database(self.database_path) as con, write_transaction(con):
            cursor = con.execute('UPDATE "user" SET status_id = ? WHERE id = ?',
                                 (BLOCKED, user_id))
            if cursor.rowcount == 0:
                raise UserNotFound()
            row = con.execute(_PUBLIC_COLUMNS, (user_id,)).fetchone()
        return _public(row)

    def login(self, login: str, password: str) -> bool:
        """TODO: parameterized lookup, verify password AND status_id == 1.

        Unknown login, wrong password, malformed stored record, inactive or
        blocked user -> False. Do not return the row, account id or secrets.
        No session or access token is issued by this educational operation.
        """
        with open_database(self.database_path) as con:
            row = con.execute(
                'SELECT password, salt, status_id FROM "user" WHERE login = ?',
                (login,)).fetchone()
        if row is None:
            verify_password(password, _DUMMY_RECORD, _DUMMY_SALT)
            return False
        password_ok = verify_password(password, row["password"], row["salt"])
        return bool(password_ok and row["status_id"] == ACTIVE)
