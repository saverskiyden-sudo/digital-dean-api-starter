"""API нового маршруту, індивідуальний варіант 1 (payload_bytes) і регресії."""
import inspect
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api import asymmetric_lab as lab
from app.main import app
from tests.report_factory import make_report

client = TestClient(app)
ROUTE = "/api/v1/lab/crypto/asymmetric-benchmark-results"


@pytest.fixture
def saved_report(tmp_path, monkeypatch):
    """Підміна серверного шляху на тимчасовий файл із синтетичним звітом."""
    path = tmp_path / "report.json"
    path.write_text(json.dumps(make_report()), encoding="utf-8")
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    return path


def test_full_report_200(saved_report):
    response = client.get(ROUTE)
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == 1
    assert len(body["key_generation"]) == 4
    assert len(body["results"]) == 22
    assert len(body["checks"]) == 22
    assert all(item["passed"] for item in body["checks"])


@pytest.mark.parametrize("size,count", [(64, 4), (1024, 6), (65536, 6), (1048576, 6)])
def test_payload_bytes_filters_only_results(saved_report, size, count):
    body = client.get(ROUTE, params={"payload_bytes": size}).json()
    assert len(body["results"]) == count
    assert {item["payload_bytes"] for item in body["results"]} == {size}
    assert len(body["key_generation"]) == 4
    assert len(body["checks"]) == 22


@pytest.mark.parametrize("value", ["0", "1", "63", "100", "1025", "2097152", "-64", "abc", "64.5"])
def test_unsupported_payload_bytes_is_422(saved_report, value):
    response = client.get(ROUTE, params={"payload_bytes": value})
    assert response.status_code == 422


def test_422_is_checked_before_reading_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    assert client.get(ROUTE, params={"payload_bytes": 7}).status_code == 422
    assert client.get(ROUTE, params={"payload_bytes": 64}).status_code == 404


def test_filter_result_is_not_a_full_report_shortcut(saved_report):
    # Фільтр не зберігається і не впливає на наступний запит без параметра.
    assert len(client.get(ROUTE, params={"payload_bytes": 64}).json()["results"]) == 4
    assert len(client.get(ROUTE).json()["results"]) == 22


def test_missing_file_404_safe_detail(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    response = client.get(ROUTE)
    assert response.status_code == 404
    assert response.json() == {"detail": "benchmark report not found"}


@pytest.mark.parametrize("raw", [
    b"{", b"[]", b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}',
    b'{"x":Infinity}', b"\xff\xfe", b"",
])
def test_broken_file_500_without_path_or_trace(tmp_path, monkeypatch, raw):
    path = tmp_path / "secret-local-name.json"
    path.write_bytes(raw)
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    response = client.get(ROUTE)
    assert response.status_code == 500
    assert response.json() == {"detail": "benchmark report invalid"}
    assert "secret-local-name" not in response.text and "Traceback" not in response.text


def test_semantically_invalid_report_500(saved_report):
    data = make_report()
    data["results"][1] = dict(data["results"][0])
    saved_report.write_text(json.dumps(data), encoding="utf-8")
    response = client.get(ROUTE)
    assert response.status_code == 500
    assert response.json() == {"detail": "benchmark report invalid"}


def test_oversized_file_500(tmp_path, monkeypatch):
    path = tmp_path / "huge.json"
    path.write_bytes(b" " * (lab.MAX_REPORT_BYTES + 10))
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    assert client.get(ROUTE).status_code == 500


def test_failed_check_is_visible_through_the_api(saved_report):
    data = make_report()
    data["checks"][2]["passed"] = False
    saved_report.write_text(json.dumps(data), encoding="utf-8")
    body = client.get(ROUTE).json()
    assert [item["passed"] for item in body["checks"]].count(False) == 1
    filtered = client.get(ROUTE, params={"payload_bytes": 1024}).json()
    assert [item["passed"] for item in filtered["checks"]].count(False) == 1


def test_client_cannot_choose_file_or_algorithm(saved_report, tmp_path):
    other = tmp_path / "other.json"
    other.write_text("{}", encoding="utf-8")
    for extra in ({"path": str(other)}, {"profile": "x"}, {"algorithm": "rsa"}):
        response = client.get(ROUTE, params=extra)
        assert response.status_code == 200
        assert len(response.json()["results"]) == 22


def test_get_does_not_run_the_experiment(saved_report, monkeypatch):
    from benchmarks import asymmetric_benchmark

    def forbidden(*args, **kwargs):
        raise AssertionError("benchmark must not run during an HTTP request")

    monkeypatch.setattr(asymmetric_benchmark, "run_experiment", forbidden)
    monkeypatch.setattr(asymmetric_benchmark, "measure_batch", forbidden)
    assert client.get(ROUTE).status_code == 200
    source = inspect.getsource(lab)
    assert "import benchmarks" not in source and "from benchmarks" not in source
    assert "run_experiment" not in source


def test_response_has_no_secret_like_content(saved_report):
    text = client.get(ROUTE).text
    for marker in ("PRIVATE KEY", "BEGIN", "ciphertext\"", "plaintext", "token", "/home", "C:\\"):
        assert marker not in text


def test_openapi_describes_route_parameter_and_version():
    schema = app.openapi()
    operation = schema["paths"][ROUTE]["get"]
    parameters = {item["name"]: item for item in operation["parameters"]}
    assert set(parameters) == {"payload_bytes"}
    assert parameters["payload_bytes"]["in"] == "query"
    assert not parameters["payload_bytes"].get("required", False)
    assert "integer" in json.dumps(parameters["payload_bytes"]["schema"])
    assert {"404", "422", "500"} <= set(operation["responses"])
    assert app.version == "0.4.0"


def test_previous_routes_still_registered():
    paths = app.openapi()["paths"]
    for path in (
        "/health",
        "/api/v1/students",
        "/api/v1/students/{student_id}/secure-notes",
        "/api/v1/lab/crypto/benchmark-results",
        ROUTE,
    ):
        assert path in paths


# --- Регресія практичних 1 і 2 ----------------------------------------------
def _student() -> str:
    payload = {
        "full_name": "Тест Студент",
        "email": f"p3-{uuid.uuid4().hex}@example.com",
        "group_code": "КН-31",
        "enrollment_year": 2024,
    }
    response = client.post("/api/v1/students", json=payload)
    assert response.status_code == 201
    return response.json()["id"]


def test_practice_1_students_and_variant_filter_unchanged():
    student_id = _student()
    assert client.get(f"/api/v1/students/{student_id}").status_code == 200
    listed = client.get("/api/v1/students", params={"enrollment_year": 2024})
    assert listed.status_code == 200
    assert student_id in {item["id"] for item in listed.json()}
    assert client.get("/api/v1/students", params={"enrollment_year": 1900}).status_code == 422


def test_practice_2_secure_notes_unchanged():
    student_id = _student()
    created = client.post(
        f"/api/v1/students/{student_id}/secure-notes",
        json={"text": "синтетична примітка", "category": "academic"},
    )
    assert created.status_code == 201
    assert created.json()["algorithm"] == "AES-256-GCM"
    note_id = created.json()["id"]
    read = client.get(f"/api/v1/students/{student_id}/secure-notes/{note_id}")
    assert read.status_code == 200
    assert read.json()["text"] == "синтетична примітка"
    assert read.json()["category"] == "academic"
    bad = client.post(
        f"/api/v1/students/{student_id}/secure-notes",
        json={"text": "x", "category": "unknown"},
    )
    assert bad.status_code == 422
