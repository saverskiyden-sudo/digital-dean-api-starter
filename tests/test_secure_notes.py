"""Моделі та HTTP-контракт; усі записи вигадані."""

import dataclasses
import json
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api import crypto_lab
from app.main import app
from app.repositories.secure_note_repository import EncryptedNote, repository
from app.repositories.student_repository import student_repository
from app.schemas.secure_note import NoteCreate
from app.security import keys
from app.security.adapters import CiphertextError, open_bytes
from app.security.context import note_aad
from benchmarks.crypto_benchmark import OPERATIONS, SIZES_BYTES
from app.security.profiles import BACKENDS, KEY_BYTES

client = TestClient(app)
STUDENTS = "/api/v1/students"
UNAVAILABLE = {"detail": "Protected note unavailable"}
REPORT_URL = "/api/v1/lab/crypto/benchmark-results"


@pytest.fixture(autouse=True)
def clean_state():
    """Чисте сховище й новий ключ із власним лічильником на кожен тест."""
    original = keys.get_process_key()
    student_repository.clear()
    repository.clear()
    keys.replace_process_key(keys.create_process_key(limit=1000))
    yield
    repository.clear()
    student_repository.clear()
    keys.replace_process_key(original)


def make_student(index: int = 0) -> str:
    """Кожен виклик створює нового вигаданого студента з унікальною поштою."""
    response = client.post(
        STUDENTS,
        json={
            "full_name": "Олена Коваль",
            "email": f"student{index}-{uuid4().hex[:8]}@example.com",
            "group_code": "КН-31",
            "enrollment_year": 2024,
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def post_note(student_id: str, text: str = "Навчальна примітка", **extra):
    return client.post(
        f"{STUDENTS}/{student_id}/secure-notes", json={"text": text, **extra}
    )


def get_note(student_id: str, note_id: str):
    return client.get(f"{STUDENTS}/{student_id}/secure-notes/{note_id}")


def create_note(text: str = "Навчальна примітка", **extra) -> tuple[str, str]:
    student_id = make_student()
    response = post_note(student_id, text, **extra)
    assert response.status_code == 201
    return student_id, response.json()["id"]


def stored(note_id: str) -> EncryptedNote:
    return repository._items[UUID(note_id)]


def replace_stored(note_id: str, **changes) -> None:
    """Пошкодження сховища лише в тестовій підготовці, не через HTTP."""
    repository._items[UUID(note_id)] = dataclasses.replace(stored(note_id), **changes)


def flip(value: bytes) -> bytes:
    return bytes([value[0] ^ 1]) + value[1:]




@pytest.mark.parametrize("text", ("x" * 4096, "я" * 2048, "  текст  "))
def test_accepted_text_is_preserved(text):
    assert NoteCreate(text=text).text == text


@pytest.mark.parametrize("payload", (
    {"text": ""}, {"text": " "}, {"text": "x" * 4097},
    {"text": "я" * 2049}, {"text": 42},
    {"text": "demo", "key": "do-not-accept"},
))
def test_invalid_note_input(payload):
    with pytest.raises(ValidationError):
        NoteCreate(**payload)


def test_unknown_student_is_not_found():
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/students/{uuid4()}/secure-notes/{uuid4()}"
        )
    assert response.status_code == 404


def test_note_api_and_internal_storage():
    student_id = make_student()
    text = "  Навчальна примітка з пробілами  "

    created = post_note(student_id, text)
    assert created.status_code == 201
    meta = created.json()
    assert set(meta) == {"id", "student_id", "algorithm", "category"}
    assert meta["student_id"] == student_id
    assert meta["algorithm"] == "AES-256-GCM"
    for hidden in ("text", "key", "key_id", "nonce", "tag", "ciphertext"):
        assert hidden not in meta

    read = get_note(student_id, meta["id"])
    assert read.status_code == 200
    assert read.json() == {**meta, "text": text}

    # Внутрішній запис: конверт без відкритого тексту й ключа.
    envelope = stored(meta["id"])
    field_names = {f.name for f in dataclasses.fields(envelope)}
    assert "text" not in field_names and "key" not in field_names
    assert envelope.version == 1
    assert envelope.backend == "cryptography"
    assert envelope.algorithm == "AES-256-GCM"
    assert len(envelope.nonce) == 12
    assert len(envelope.tag) == 16
    assert len(envelope.ciphertext) == len(text.encode("utf-8"))
    process_key = keys.get_process_key()
    assert envelope.key_id == process_key.key_id
    assert text.encode("utf-8") not in envelope.ciphertext
    for value in dataclasses.astuple(envelope):
        assert value != process_key.key
        if isinstance(value, bytes):
            assert process_key.key not in value


def test_note_text_round_trips_exactly():
    for text in ("x", " a ", "Привіт, світе! 🙂", "рядок\nз переносом\t", "я" * 2048):
        student_id, note_id = create_note(text)
        assert get_note(student_id, note_id).json()["text"] == text


@pytest.mark.parametrize(
    "damage",
    (
        lambda n: {"ciphertext": flip(n.ciphertext)},
        lambda n: {"tag": flip(n.tag)},
        lambda n: {"tag": n.tag[:8]},
        lambda n: {"nonce": flip(n.nonce)},
        lambda n: {"nonce": n.nonce[:-1]},
        lambda n: {"key_id": uuid4()},
        lambda n: {"version": 2},
        lambda n: {"algorithm": "AES-128-GCM"},
        lambda n: {"algorithm": "unknown"},
        lambda n: {"backend": "unknown"},
        lambda n: {"category": "academic" if n.category != "academic" else "general"},
        lambda n: {"category": "secret"},
    ),
    ids=(
        "ciphertext", "tag", "short-tag", "nonce", "short-nonce", "key-id",
        "version", "algorithm-128", "algorithm-unknown", "backend", "category",
        "category-unknown",
    ),
)
def test_damaged_note_is_rejected_without_plaintext(damage):
    secret_text = "СЕКРЕТНИЙ-ВИГАДАНИЙ-ТЕКСТ"
    student_id, note_id = create_note(secret_text)
    replace_stored(note_id, **damage(stored(note_id)))

    response = get_note(student_id, note_id)

    assert response.status_code == 500
    assert response.json() == UNAVAILABLE
    assert secret_text not in response.text
    assert keys.get_process_key().key.hex() not in response.text
    assert "Traceback" not in response.text
    assert "Error" not in response.text


def test_note_envelope_copied_to_another_student_is_rejected():
    owner_id, note_id = create_note("Примітка першого студента")
    other_id = make_student(1)
    copied_id = uuid4()
    repository._items[copied_id] = dataclasses.replace(
        stored(note_id), student_id=UUID(other_id), note_id=copied_id
    )

    response = get_note(other_id, str(copied_id))

    assert response.status_code == 500
    assert response.json() == UNAVAILABLE
    assert get_note(owner_id, note_id).status_code == 200


def test_note_envelope_copied_under_another_note_id_is_rejected():
    student_id, note_id = create_note("Примітка")
    copied_id = uuid4()
    repository._items[copied_id] = dataclasses.replace(
        stored(note_id), note_id=copied_id
    )

    response = get_note(student_id, str(copied_id))

    assert response.status_code == 500
    assert response.json() == UNAVAILABLE


def test_nonce_limit_rejects_only_new_writes():
    keys.replace_process_key(keys.create_process_key(limit=2))
    student_id = make_student()
    first = post_note(student_id, "перша")
    second = post_note(student_id, "друга")
    assert first.status_code == second.status_code == 201

    third = post_note(student_id, "третя")
    assert third.status_code == 503
    assert third.json() == UNAVAILABLE
    assert len(repository._items) == 2

    # Старі примітки читаються; очищення сховища не скидає лічильник.
    assert get_note(student_id, first.json()["id"]).json()["text"] == "перша"
    assert get_note(student_id, second.json()["id"]).json()["text"] == "друга"
    repository.clear()
    assert post_note(student_id, "після очищення").status_code == 503


def test_clear_does_not_reset_counter_or_reuse_nonce():
    keys.replace_process_key(keys.create_process_key(limit=3))
    student_id = make_student()
    first = post_note(student_id)
    first_nonce = stored(first.json()["id"]).nonce
    repository.clear()
    second = post_note(student_id)
    assert second.status_code == 201
    assert stored(second.json()["id"]).nonce != first_nonce
    assert post_note(student_id).status_code == 201
    assert post_note(student_id).status_code == 503


def test_every_note_gets_a_new_nonce_and_the_same_key():
    student_id = make_student()
    ids = [post_note(student_id, f"примітка {i}").json()["id"] for i in range(25)]
    nonces = {stored(i).nonce for i in ids}
    assert len(nonces) == 25
    assert {stored(i).key_id for i in ids} == {keys.get_process_key().key_id}


def test_validation_error_does_not_consume_nonce_or_store_anything():
    student_id = make_student()
    assert post_note(student_id, "  ").status_code == 422
    assert repository._items == {}
    note_id = post_note(student_id, "перша").json()["id"]
    assert stored(note_id).nonce == (0).to_bytes(12, "big")


# 4096-байтна межа та невідомі поля.
@pytest.mark.parametrize("text", ("x" * 4096, "я" * 2048, "  " + "x" * 4094))
def test_text_up_to_4096_bytes_is_accepted(text):
    student_id = make_student()
    assert post_note(student_id, text).status_code == 201


@pytest.mark.parametrize("text", ("x" * 4097, "я" * 2049, "🙂" * 1025, "", " ", "\t\n "))
def test_text_outside_the_limits_is_rejected(text):
    student_id = make_student()
    assert post_note(student_id, text).status_code == 422
    assert repository._items == {}


@pytest.mark.parametrize(
    "extra",
    (
        {"key": "do-not-accept"},
        {"key_id": str(uuid4())},
        {"nonce": "AAAA"},
        {"tag": "AAAA"},
        {"algorithm": "ChaCha20-Poly1305"},
        {"backend": "pycryptodome"},
        {"id": str(uuid4())},
    ),
)
def test_client_cannot_send_crypto_fields(extra):
    student_id = make_student()
    response = post_note(student_id, "demo", **extra)
    assert response.status_code == 422
    assert repository._items == {}


@pytest.mark.parametrize("text", (42, None, ["a"], {"a": 1}, True))
def test_text_must_be_a_string(text):
    student_id = make_student()
    response = client.post(
        f"{STUDENTS}/{student_id}/secure-notes", json={"text": text}
    )
    assert response.status_code == 422


def test_missing_text_and_malformed_json_are_rejected():
    student_id = make_student()
    url = f"{STUDENTS}/{student_id}/secure-notes"
    assert client.post(url, json={}).status_code == 422
    bad = client.post(url, content="{bad", headers={"Content-Type": "application/json"})
    assert bad.status_code == 422


def test_invalid_uuid_is_rejected():
    student_id, note_id = create_note()
    assert post_note("not-a-uuid").status_code == 422
    assert get_note("not-a-uuid", note_id).status_code == 422
    assert get_note(student_id, "not-a-uuid").status_code == 422


def test_unknown_student_and_unknown_note_are_not_found():
    assert post_note(str(uuid4())).status_code == 404
    student_id, _ = create_note()
    assert get_note(student_id, str(uuid4())).status_code == 404
    assert get_note(str(uuid4()), str(uuid4())).status_code == 404


def test_note_of_another_student_is_not_found():
    # Таблиця 5, крок 7.
    owner_id, note_id = create_note("Приватна вигадана примітка")
    other_id = make_student(1)
    response = get_note(other_id, note_id)
    assert response.status_code == 404
    assert "Приватна" not in response.text
    assert get_note(owner_id, note_id).status_code == 200


def test_read_does_not_change_state():
    student_id, note_id = create_note("стабільний текст")
    before = stored(note_id)
    for _ in range(3):
        assert get_note(student_id, note_id).json()["text"] == "стабільний текст"
    assert stored(note_id) == before


def test_one_process_key_is_used_for_all_requests():
    first_id = keys.get_process_key().key_id
    student_id, note_id = create_note()
    get_note(student_id, note_id)
    assert keys.get_process_key().key_id == first_id
    assert stored(note_id).key_id == first_id


# --- Індивідуальний варіант 1: категорія примітки ----------------------------
@pytest.mark.parametrize("category", ("general", "academic", "administrative"))
def test_category_round_trip(category):
    student_id = make_student()
    created = post_note(student_id, "Текст із категорією", category=category)
    assert created.status_code == 201
    assert created.json()["category"] == category
    assert stored(created.json()["id"]).category == category

    read = get_note(student_id, created.json()["id"])
    assert read.status_code == 200
    assert read.json()["category"] == category
    assert read.json()["text"] == "Текст із категорією"


def test_category_defaults_to_general():
    student_id, note_id = create_note("без категорії")
    assert get_note(student_id, note_id).json()["category"] == "general"


@pytest.mark.parametrize(
    "category", ("secret", "General", "", " general", "ACADEMIC", 1, None, ["general"])
)
def test_unknown_category_is_rejected(category):
    student_id = make_student()
    response = client.post(
        f"{STUDENTS}/{student_id}/secure-notes",
        json={"text": "demo", "category": category},
    )
    assert response.status_code == 422
    assert repository._items == {}


def test_changed_stored_category_fails_verification():
    student_id, note_id = create_note("Академічна примітка", category="academic")
    assert get_note(student_id, note_id).status_code == 200

    replace_stored(note_id, category="administrative")

    response = get_note(student_id, note_id)
    assert response.status_code == 500
    assert response.json() == UNAVAILABLE
    assert "Академічна" not in response.text


def test_category_is_part_of_the_authenticated_context():
    student_id, note_id = create_note("Текст", category="academic")
    envelope = stored(note_id)
    process_key = keys.get_process_key()

    def attempt(category):
        aad = note_aad(
            envelope.student_id, envelope.note_id, envelope.algorithm,
            envelope.key_id, category,
        )
        return open_bytes(
            envelope.backend, envelope.algorithm, process_key.key, envelope.nonce,
            envelope.ciphertext, envelope.tag, aad,
        )

    assert attempt("academic") == "Текст".encode("utf-8")
    for wrong in ("general", "administrative", None):
        with pytest.raises(CiphertextError):
            attempt(wrong)


def test_openapi_describes_secure_notes_and_category():
    schema = client.get("/openapi.json").json()
    assert schema["info"]["version"] == "0.5.0"
    paths = schema["paths"]
    assert "post" in paths["/api/v1/students/{student_id}/secure-notes"]
    assert "get" in paths["/api/v1/students/{student_id}/secure-notes/{note_id}"]
    assert "get" in paths[REPORT_URL]
    create_schema = schema["components"]["schemas"]["NoteCreate"]
    assert create_schema["properties"]["category"]["enum"] == [
        "general", "academic", "administrative",
    ]
    assert "category" in schema["components"]["schemas"]["NoteMetadata"]["properties"]
    assert "category" in schema["components"]["schemas"]["NoteRead"]["properties"]


# --- Регресія роботи 1 -------------------------------------------------------
def test_students_still_work_with_secure_notes_enabled():
    student_id = make_student()
    assert client.get(f"{STUDENTS}/{student_id}").status_code == 200
    changed = client.patch(f"{STUDENTS}/{student_id}", json={"group_code": "КН-32"})
    assert changed.status_code == 200
    assert changed.json()["enrollment_year"] == 2024
    listed = client.get(STUDENTS, params={"enrollment_year": 2024})
    assert [item["id"] for item in listed.json()] == [student_id]
    assert client.get("/health").json() == {"status": "ok"}


# --- Звіт вимірювань ----------------------------------------------------------
def build_report(sizes=SIZES_BYTES) -> dict:
    results = [
        {
            "backend": backend,
            "algorithm": algorithm,
            "size_bytes": size,
            "operation": operation,
            "series_mean_ns": [1000.0, 1100.0, 1200.0, 1300.0, 1400.0],
            "median_ns": 1200.0,
            "iqr_ns": 200.0,
            "throughput_mib_s": 10.0,
        }
        for backend in BACKENDS
        for algorithm in KEY_BYTES
        for size in sizes
        for operation in OPERATIONS
    ]
    return {
        "schema_version": 1,
        "run_id": "test-run",
        "environment": {"python": "test"},
        "parameters": {"sizes_bytes": list(sizes), "warmup": 10, "series": 5,
                       "operations_per_series": 100},
        "results": results,
    }


def use_report(monkeypatch, tmp_path, content) -> None:
    path = tmp_path / "report.json"
    if content is not None:
        path.write_text(
            content if isinstance(content, str) else json.dumps(content),
            encoding="utf-8",
        )
    monkeypatch.setattr(crypto_lab, "REPORT_PATH", path)


def test_benchmark_report_reader(monkeypatch, tmp_path):
    report = build_report()
    use_report(monkeypatch, tmp_path, report)
    ok = client.get(REPORT_URL)
    assert ok.status_code == 200
    assert ok.json() == report
    assert ok.json()["schema_version"] == 1
    assert len(ok.json()["results"]) == 36

    use_report(monkeypatch, tmp_path / "nowhere", None)
    missing = client.get(REPORT_URL)
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Benchmark results unavailable"}

    use_report(monkeypatch, tmp_path, "{not json")
    broken = client.get(REPORT_URL)
    assert broken.status_code == 500
    assert broken.json() == {"detail": "Benchmark results unavailable"}
    assert str(tmp_path) not in broken.text


def _drop_row(report):
    report["results"].pop()


def _break_schema(report):
    report["schema_version"] = 2


def _duplicate_row(report):
    report["results"][0] = dict(report["results"][1])


def _bad_series(report):
    report["results"][0]["series_mean_ns"] = [1.0, 2.0]


def _negative_metric(report):
    report["results"][0]["throughput_mib_s"] = -1


def _unknown_backend(report):
    report["results"][0]["backend"] = "other"


def _no_environment(report):
    del report["environment"]


@pytest.mark.parametrize(
    "damage",
    (_drop_row, _break_schema, _duplicate_row, _bad_series, _negative_metric,
     _unknown_backend, _no_environment),
)
def test_benchmark_report_with_invalid_structure_is_rejected(
    monkeypatch, tmp_path, damage
):
    report = build_report()
    damage(report)
    use_report(monkeypatch, tmp_path, report)
    response = client.get(REPORT_URL)
    assert response.status_code == 500
    assert response.json() == {"detail": "Benchmark results unavailable"}


@pytest.mark.parametrize("content", ("[]", "null", "42", '"text"', ""))
def test_benchmark_report_with_wrong_json_type_is_rejected(
    monkeypatch, tmp_path, content
):
    use_report(monkeypatch, tmp_path, content)
    assert client.get(REPORT_URL).status_code == 500


def test_benchmark_report_path_is_not_taken_from_the_client(monkeypatch, tmp_path):
    use_report(monkeypatch, tmp_path / "nowhere", None)
    response = client.get(REPORT_URL, params={"path": "/etc/passwd", "file": "x"})
    assert response.status_code == 404
    assert client.post(REPORT_URL).status_code == 405
