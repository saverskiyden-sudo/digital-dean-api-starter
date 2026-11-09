"""Власні тести практичної 5: додаткові негативні сценарії, транзакції, збій і
зайнятість сховища, перезапуск процесу, безпечні відповіді та регресії.
Кожен тест має власну тимчасову базу (tmp_path); робоча база не використовується."""
import json
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.accounts import get_user_repository
from app.db import initialize as init_module
from app.db.connection import DB_PATH, open_database, write_transaction
from app.db.initialize import initialize_database
from app.main import app
from app.repositories.user_repository import UserRepository
from app.security import passwords
from tests.practice05_support import (
    PASSWORD, PUBLIC_KEYS, account_client, account_data, account_database,
    account_repository,
)

ROOT = Path(__file__).resolve().parents[1]


def body(login="demo_student", status_id=0, **changes):
    data = dict(name="Навчальний користувач", email=f"{login}@example.com",
                login=login, password=PASSWORD, status_id=status_id)
    data.update(changes)
    return data


def stored(path, user_id):
    with open_database(path) as con:
        return dict(con.execute('SELECT * FROM "user" WHERE id=?', (user_id,)).fetchone())


# ---------- Ініціалізація ----------

def test_initializer_creates_directory_and_is_repeatable(tmp_path):
    path = tmp_path / "nested" / "var" / "db.sqlite3"
    initialize_database(path)
    initialize_database(path)
    with open_database(path) as con:
        assert con.execute("SELECT count(*) FROM status").fetchone()[0] == 3
        assert con.execute("SELECT count(*) FROM role").fetchone()[0] == 4
        assert con.execute('SELECT count(*) FROM "user"').fetchone()[0] == 0


def test_initializer_failure_leaves_no_partial_schema(tmp_path, monkeypatch):
    path = tmp_path / "db.sqlite3"
    broken = init_module.DDL_STATEMENTS[:3] + ("CREATE TABLE broken (",)
    monkeypatch.setattr(init_module, "DDL_STATEMENTS", broken)
    with pytest.raises(sqlite3.Error):
        initialize_database(path)
    with open_database(path) as con:
        assert con.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == 0


def test_extra_lookup_row_is_rejected_not_deleted(account_database):
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO role(id, name) VALUES (?, ?)", (5, "guest"))
    with pytest.raises(ValueError):
        initialize_database(account_database)
    with open_database(account_database) as con:
        assert con.execute("SELECT name FROM role WHERE id=5").fetchone()[0] == "guest"


def test_repeat_initialization_keeps_courses_grades_and_roles(account_repository, account_database):
    student = account_repository.register_user(account_data("demo_student"))
    teacher = account_repository.register_user(account_data("demo_teacher"))
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO course VALUES (?,?)", (1, "Synthetic course"))
        con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student.id, teacher.id, 1, 77))
        con.execute("INSERT INTO user_role VALUES (?,?)", (teacher.id, 3))
    initialize_database(account_database)
    with open_database(account_database) as con:
        assert con.execute("SELECT grade FROM grade").fetchone()[0] == 77
        assert con.execute("SELECT count(*) FROM user_role").fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM course").fetchone()[0] == 1


def test_working_database_path_is_fixed_and_ignored_by_git():
    assert DB_PATH == ROOT / "var" / "digital-dean.sqlite3"
    ignore = (ROOT / "var" / ".gitignore").read_text(encoding="utf-8").split()
    assert "*" in ignore and "!.gitignore" in ignore


# ---------- SQLite-обмеження без HTTP ----------

def test_user_role_duplicate_and_missing_references(account_repository, account_database):
    user = account_repository.register_user(account_data())
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO user_role VALUES (?,?)", (user.id, 4))
    for values in [(user.id, 4), (user.id, 99), (9999, 4)]:
        with pytest.raises(sqlite3.IntegrityError):
            with open_database(account_database) as con, write_transaction(con):
                con.execute("INSERT INTO user_role VALUES (?,?)", values)


def test_text_number_affinity_is_not_strict_json(account_repository, account_database):
    """SQLite може перетворити придатний текст числа на INTEGER: це не JSON-валідація."""
    student = account_repository.register_user(account_data("demo_student"))
    teacher = account_repository.register_user(account_data("demo_teacher"))
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO course VALUES (?,?)", (1, "Synthetic course"))
        con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student.id, teacher.id, 1, "90"))
    with open_database(account_database) as con:
        assert tuple(con.execute("SELECT typeof(grade), grade FROM grade").fetchone()) == ("integer", 90)


def test_status_and_login_constraints_in_database(account_database):
    for row in [("Name", "a@example.com", "Upper", "p", "s", 0),
                ("Name", "b@example.com", "ok_login", "p", "s", 7),
                ("   ", "c@example.com", "ok_login2", "p", "s", 0)]:
        with pytest.raises(sqlite3.IntegrityError):
            with open_database(account_database) as con, write_transaction(con):
                con.execute('INSERT INTO "user"(name,email,login,password,salt,status_id) '
                            "VALUES (?,?,?,?,?,?)", row)


# ---------- Паролі в базі ----------

def test_same_password_gives_different_stored_records(account_repository, account_database):
    first = account_repository.register_user(account_data("first_user"))
    second = account_repository.register_user(account_data("second_user"))
    a, b = stored(account_database, first.id), stored(account_database, second.id)
    assert a["salt"] != b["salt"] and a["password"] != b["password"]
    assert PASSWORD not in json.dumps([a, b], ensure_ascii=False)


def test_corrupted_stored_record_gives_false_without_kdf(account_repository, account_database, monkeypatch):
    user = account_repository.register_user(account_data(status_id=1))
    with open_database(account_database) as con, write_transaction(con):
        con.execute('UPDATE "user" SET password=? WHERE id=?',
                    ("pbkdf2_sha256$999999999$" + "0" * 64, user.id))
    calls = []
    original = passwords.hashlib.pbkdf2_hmac
    monkeypatch.setattr(passwords.hashlib, "pbkdf2_hmac",
                        lambda *a, **k: calls.append(a[3]) or original(*a, **k))
    assert account_repository.login("demo_student", PASSWORD) is False
    assert 999999999 not in calls


def test_password_is_not_normalized_in_login(account_client):
    password = "  Пароль Для Навчання 5  "
    assert account_client.post("/api/v1/users", json=body(status_id=1, password=password)).status_code == 201
    for candidate, expected in [(password, True), (password.strip(), False),
                                (password.lower(), False)]:
        response = account_client.post("/api/v1/auth/login",
                                        json={"login": "demo_student", "password": candidate})
        assert response.json() is expected


# ---------- API: реєстрація, блокування, видалення ----------

def test_explicit_status_values_and_public_fields(account_client):
    for status_id in (0, 1, 2):
        response = account_client.post("/api/v1/users",
                                       json=body(f"user_{status_id}", status_id=status_id))
        assert response.status_code == 201
        assert set(response.json()) == PUBLIC_KEYS
        assert response.json()["status_id"] == status_id


@pytest.mark.parametrize("change", [{"status_id": None}, {"is_admin": True},
                                  {"password": None}, {"login": "Demo_Student"},
                                  {"login": "ab"}, {"name": "x" * 121}])
def test_more_invalid_registration_cases(account_client, change):
    response = account_client.post("/api/v1/users", json=body(**change))
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert all("input" not in item and "ctx" not in item for item in detail)
    assert PASSWORD not in response.text


def test_block_changes_only_status(account_client, account_database):
    created = account_client.post("/api/v1/users", json=body(status_id=1)).json()
    before = stored(account_database, created["id"])
    account_client.patch(f'/api/v1/users/{created["id"]}/block')
    after = stored(account_database, created["id"])
    assert after == {**before, "status_id": 2}


def test_delete_teacher_with_grade_is_409_and_keeps_everything(account_client, account_database):
    student = account_client.post("/api/v1/users", json=body("demo_student")).json()
    teacher = account_client.post("/api/v1/users", json=body("demo_teacher")).json()
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO course VALUES (?,?)", (1, "Synthetic course"))
        con.execute("INSERT INTO user_role VALUES (?,?)", (teacher["id"], 3))
        con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student["id"], teacher["id"], 1, 88))
    for user in (teacher, student):
        response = account_client.delete(f'/api/v1/users/{user["id"]}')
        assert response.status_code == 409
        assert response.json() == {"detail": "user has grade references"}
    with open_database(account_database) as con:
        assert con.execute('SELECT count(*) FROM "user"').fetchone()[0] == 2
        assert con.execute("SELECT count(*) FROM grade").fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM user_role").fetchone()[0] == 1


def test_not_found_detail_is_controlled(account_client):
    for response in (account_client.delete("/api/v1/users/999"),
                     account_client.patch("/api/v1/users/999/block")):
        assert response.status_code == 404
        assert response.json() == {"detail": "user not found"}


def test_login_rejects_wrong_body_shape(account_client):
    for payload in [{"login": "demo_student"}, {"password": PASSWORD},
                    {"login": "demo_student", "password": PASSWORD, "extra": 1},
                    {"login": 123, "password": PASSWORD}, [], {"login": "", "password": "x"}]:
        response = account_client.post("/api/v1/auth/login", json=payload)
        assert response.status_code == 422 and PASSWORD not in response.text


def test_sql_like_login_does_not_change_database(account_client, account_database):
    account_client.post("/api/v1/users", json=body(status_id=1))
    for login in ['x"; DROP TABLE "user"; --', "demo_student' --", "' OR '1'='1"]:
        response = account_client.post("/api/v1/auth/login",
                                       json={"login": login, "password": PASSWORD})
        assert response.json() is False
    with open_database(account_database) as con:
        assert con.execute('SELECT count(*) FROM "user"').fetchone()[0] == 1


# ---------- Збій і зайнятість бази ----------

def test_database_failure_is_safe_500(tmp_path):
    broken = tmp_path / "not-initialized.sqlite3"
    app.dependency_overrides[get_user_repository] = lambda: UserRepository(broken)
    try:
        client = TestClient(app, raise_server_exceptions=False)
        responses = [client.post("/api/v1/users", json=body()),
                     client.post("/api/v1/auth/login", json={"login": "demo_student", "password": PASSWORD}),
                     client.patch("/api/v1/users/1/block"), client.delete("/api/v1/users/1")]
    finally:
        app.dependency_overrides.pop(get_user_repository, None)
    for response in responses:
        assert response.status_code == 500
        assert response.json() == {"detail": "database unavailable"}
        assert str(tmp_path) not in response.text and "sqlite" not in response.text.lower()


def test_busy_storage_gives_500_and_no_partial_write(account_database, account_client):
    locked = threading.Event()
    release = threading.Event()

    def hold_write_lock():
        with open_database(account_database) as con, write_transaction(con):
            locked.set()
            release.wait(10)

    holder = threading.Thread(target=hold_write_lock)
    holder.start()
    try:
        assert locked.wait(5)
        response = account_client.post("/api/v1/users", json=body())
    finally:
        release.set()
        holder.join()
    assert response.status_code == 500
    assert response.json() == {"detail": "database unavailable"}
    with open_database(account_database) as con:
        assert con.execute('SELECT count(*) FROM "user"').fetchone()[0] == 0


# ---------- Сталість після перезапуску процесу ----------

def test_data_survives_new_process(account_database):
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from app.repositories.user_repository import UserRepository\n"
        "from app.schemas.user_account import UserCreate\n"
        "repo = UserRepository(Path(sys.argv[1]))\n"
        "if sys.argv[2] == 'create':\n"
        "    repo.register_user(UserCreate(name='Restart user', email='restart@example.com',\n"
        "        login='restart_user', password='Learning only 05!', status_id=1))\n"
        "elif sys.argv[2] == 'block':\n"
        "    repo.block_user(1)\n"
        "print(repo.login('restart_user', 'Learning only 05!'))\n"
    )

    def run(action):
        out = subprocess.run([sys.executable, "-c", script, str(account_database), action],
                             cwd=ROOT, capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr[-500:]
        return out.stdout.strip()

    assert run("create") == "True"
    assert run("check") == "True"       # окремий новий процес
    assert run("block") == "False"
    assert run("check") == "False"


# ---------- OpenAPI та регресії ----------

def test_openapi_has_safe_public_model_and_codes():
    schema = app.openapi()
    assert schema["info"]["version"] == "0.5.0"
    public = schema["components"]["schemas"]["UserPublic"]["properties"]
    assert set(public) == PUBLIC_KEYS
    paths = schema["paths"]
    assert set(paths["/api/v1/users"]["post"]["responses"]) >= {"201", "409", "422", "500"}
    assert set(paths["/api/v1/users/{user_id}"]["delete"]["responses"]) >= {"204", "404", "409", "422", "500"}
    assert set(paths["/api/v1/users/{user_id}/block"]["patch"]["responses"]) >= {"200", "404", "422", "500"}
    assert set(paths["/api/v1/auth/login"]["post"]["responses"]) >= {"200", "422", "500"}


def test_previous_validation_contract_unchanged(account_client):
    # SensitiveRoute applies only to new routes: old routes keep FastAPI's detail.
    response = account_client.post("/api/v1/students", json={"full_name": ""})
    assert response.status_code == 422
    assert response.json()["detail"][0].get("loc") != ["request"]


def test_previous_routes_still_work(account_client):
    assert account_client.get("/health").json() == {"status": "ok"}
    assert account_client.get("/api/v1/lab/crypto/hash-benchmark-results",
                              params={"payload_bytes": 65}).status_code == 422
