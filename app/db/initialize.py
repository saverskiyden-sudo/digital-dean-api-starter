"""Atomic, repeatable schema creation and lookup initialization (practice 5).

    python -m app.db.initialize

Creates var/ if needed, runs every DDL statement and the parameterized lookup
inserts inside ONE write transaction, then verifies the exact lookup rows.
A repeated run neither duplicates lookups nor touches user, user_role,
course or grade. No default/admin account is ever created.
"""
from pathlib import Path
import sqlite3

from app.db.connection import DB_PATH, open_database, write_transaction
from app.db.schema import DDL_STATEMENTS, ROLE_ROWS, STATUS_ROWS

_SEEDS = (
    ("status", "INSERT INTO status(id, name) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
     "SELECT id, name FROM status ORDER BY id", STATUS_ROWS),
    ("role", "INSERT INTO role(id, name) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
     "SELECT id, name FROM role ORDER BY id", ROLE_ROWS),
)


def initialize_database(path: Path = DB_PATH) -> None:
    """Create parent directory and all tables; preserve users on repeat runs.

    A lookup table whose content differs from the fixed rows (another name for
    a used id, an extra row) is NOT overwritten: ValueError, full rollback.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open_database(path) as connection, write_transaction(connection):
        for statement in DDL_STATEMENTS:          # each statement separately, no executescript
            connection.execute(statement)
        for table, insert, select, expected in _SEEDS:
            try:
                connection.executemany(insert, expected)
            except sqlite3.IntegrityError as exc:  # e.g. the same name under another id
                raise ValueError(f"{table} lookup does not match the fixed rows") from exc
            actual = tuple(tuple(row) for row in connection.execute(select))
            if actual != tuple(expected):
                raise ValueError(f"{table} lookup does not match the fixed rows")


if __name__ == "__main__":
    initialize_database()
    print("Database initialized; no default accounts created.")
