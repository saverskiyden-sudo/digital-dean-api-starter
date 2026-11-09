"""Власні тести практичної 4: варіант 1 (payload_bytes), змістова перевірка звіту,
сирі дані експерименту та межі HTTP-маршруту. Фікстури синтетичні, не вимірювання."""
import ast
import copy
import csv
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import hash_lab
from app.main import app
from app.schemas.hash_report import filter_by_payload, validate_report
from app.security.hashing import profiles
from app.security.hashing.adapters import hamming_bits, hash_bytes, prepare_operation
from app.security.hashing.profiles import CHECK_NAMES, PAYLOAD_SIZES, PROFILES
from benchmarks import hash_benchmark as hb
from tests.test_hash_report import PATH, synthetic_report

client = TestClient(app)


@pytest.fixture
def report_file(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(synthetic_report()), encoding="utf-8")
    monkeypatch.setattr(hash_lab, "REPORT_PATH", path)
    return path


# ---------- Варіант 1: payload_bytes ----------

def test_variant_no_parameter_returns_full_results(report_file):
    body = client.get(PATH).json()
    assert len(body["results"]) == 56 and body["summary"] is None


@pytest.mark.parametrize("size", PAYLOAD_SIZES)
def test_variant_filters_only_results(report_file, size):
    response = client.get(PATH, params={"payload_bytes": size})
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 7 * 2
    assert {r["payload_bytes"] for r in body["results"]} == {size}
    # Інші поля залишаються повними.
    assert len(body["algorithms"]) == 7
    assert len(body["avalanche"]) == 7
    assert len(body["checks"]) == 42


@pytest.mark.parametrize("value", ["65", "0", "-64", "1048577", "abc", "true"])
def test_variant_rejects_unsupported_values(report_file, value):
    assert client.get(PATH, params={"payload_bytes": value}).status_code == 422


def test_variant_422_does_not_depend_on_report(tmp_path, monkeypatch):
    monkeypatch.setattr(hash_lab, "REPORT_PATH", tmp_path / "absent.json")
    assert client.get(PATH, params={"payload_bytes": 65}).status_code == 422
    assert client.get(PATH, params={"payload_bytes": 64}).status_code == 404


def test_variant_full_validation_before_filter(report_file):
    data = synthetic_report()
    # Пошкоджено рядок іншого розміру: фільтр 64 не повинен його приховати.
    broken = next(r for r in data["results"] if r["payload_bytes"] == 1048576)
    broken["throughput_mib_s"] = 1.0
    report_file.write_text(json.dumps(data), encoding="utf-8")
    response = client.get(PATH, params={"payload_bytes": 64})
    assert response.status_code == 500
    assert response.json() == {"detail": "hash report invalid"}


def test_variant_keeps_failed_checks_visible(report_file):
    data = synthetic_report()
    data["checks"][3]["passed"] = False
    report_file.write_text(json.dumps(data), encoding="utf-8")
    body = client.get(PATH, params={"payload_bytes": 1024}).json()
    assert body["checks"][3]["passed"] is False


def test_variant_with_unavailable_legacy_profiles():
    data = synthetic_report()
    for row in data["algorithms"]:
        if row["algorithm"] in ("md5", "sha1"):
            row.update(available=False, reason="not_available_in_environment",
                       implementation=None)
    for field in ("results", "avalanche", "checks"):
        data[field] = [x for x in data[field] if x["algorithm"] not in ("md5", "sha1")]
    response = filter_by_payload(validate_report(data), 65536)
    assert len(response.results) == 5 * 2
    assert len(response.algorithms) == 7


def test_openapi_describes_variant_parameter():
    schema = client.get("/openapi.json").json()
    assert schema["info"]["version"] == "0.5.0"
    operation = schema["paths"][PATH]["get"]
    names = [p["name"] for p in operation["parameters"]]
    assert names == ["payload_bytes"]
    assert "422" in operation["responses"]


# ---------- Змістова перевірка звіту ----------

@pytest.mark.parametrize("value", ["2026-10-23T00:00:00+00:00", "2026-10-23T00:00:00Z"])
def test_accepts_utc_forms(value):
    data = synthetic_report()
    data["created_at"] = value
    validate_report(data)


@pytest.mark.parametrize("value", [
    "2026-10-23T00:00:00+02:00", "2026-13-01T00:00:00Z", "23.10.2026 00:00:00Z",
    "2999-01-01T00:00:00Z",
])
def test_rejects_bad_dates(value):
    data = synthetic_report()
    data["created_at"] = value
    with pytest.raises(ValueError):
        validate_report(data)


@pytest.mark.parametrize("field", ["results", "avalanche", "checks"])
def test_rejects_missing_rows(field):
    data = synthetic_report()
    data[field].pop()
    with pytest.raises(ValueError):
        validate_report(data)


def test_rejects_unavailable_legacy_with_leftover_numbers():
    data = synthetic_report()
    row = next(r for r in data["algorithms"] if r["algorithm"] == "md5")
    row.update(available=False, reason="not_available_in_environment", implementation=None)
    with pytest.raises(ValueError):
        validate_report(data)       # results/avalanche/checks md5 ще присутні


@pytest.mark.parametrize("change", [
    dict(reason=None, implementation=None),
    dict(reason="not_available_in_environment", implementation="x.Y"),
])
def test_rejects_inconsistent_unavailable_status(change):
    data = synthetic_report()
    row = next(r for r in data["algorithms"] if r["algorithm"] == "sha1")
    row.update(available=False, **change)
    for field in ("results", "avalanche", "checks"):
        data[field] = [x for x in data[field] if x["algorithm"] != "sha1"]
    with pytest.raises(ValueError):
        validate_report(data)


def test_rejects_available_without_implementation():
    data = synthetic_report()
    data["algorithms"][0]["implementation"] = None
    with pytest.raises(ValueError):
        validate_report(data)


@pytest.mark.parametrize("path,value", [
    (("results", 0, "median_ns"), float("inf")),
    (("results", 0, "iqr_ns"), -1.0),
    (("results", 0, "median_ns"), "1000.0"),
    (("parameters", "warmup"), True),
    (("parameters", "repeats_small"), "1000"),
    (("avalanche", 0, "min_flipped_bits"), 200),
    (("avalanche", 0, "digest_bits"), 512),
    (("checks", 0, "name"), "known-xyz"),
    (("environment", "cpu"), ""),
])
def test_rejects_more_numeric_and_semantic_errors(path, value):
    data = synthetic_report()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        validate_report(data)


# ---------- Адаптери: додаткові негативні випадки ----------

@pytest.mark.parametrize("data", [bytearray(b"a"), memoryview(b"a"), None, 1])
def test_hash_bytes_requires_exact_bytes(data):
    with pytest.raises(TypeError):
        hash_bytes("sha256", data)


def test_prepare_operation_validates_before_timing():
    with pytest.raises(ValueError):
        prepare_operation("sha256", b"x", "parallel")
    with pytest.raises(ValueError):
        prepare_operation("keccak-256", b"x")


def test_hamming_rejects_non_bytes():
    with pytest.raises(TypeError):
        hamming_bits(bytearray(b"a"), b"a")


def test_blake2_is_not_truncated_blake2b512():
    import hashlib
    full = hashlib.blake2b(b"abc", digest_size=64).digest()
    assert hash_bytes("blake2b-256", b"abc") != full[:32]


# ---------- Сирі дані та експеримент ----------

@pytest.fixture
def quick_experiment(tmp_path, monkeypatch):
    """Швидкий прогін логіки експерименту: 2 повтори, вимірювання не зберігаються в репозиторії."""
    monkeypatch.setattr(hb, "repeat_count", lambda size: 2)
    monkeypatch.setattr(hb, "validate_report", lambda report: report)
    report, ok = hb.run_experiment(tmp_path, commit="a" * 40, quiet=True)
    return tmp_path, report, ok


def test_experiment_writes_consistent_raw_data(quick_experiment):
    out, report, ok = quick_experiment
    assert ok
    with open(out / "raw.csv", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    available = [a["algorithm"] for a in report["algorithms"] if a["available"]]
    assert len(rows) == 40 * len(available)
    keys = set()
    for row in rows:
        elapsed, repeats = int(row["elapsed_ns"]), int(row["repeats"])
        assert elapsed > 0 and repeats == 2
        assert float(row["ns_per_op"]) == pytest.approx(elapsed / repeats)
        assert row["series"] in {"1", "2", "3", "4", "5"}
        keys.add((row["algorithm"], row["mode"], row["payload_bytes"], row["series"]))
    assert len(keys) == len(rows)
    # Агрегат JSON — медіана п'яти ns_per_op відповідної серії.
    first = report["results"][0]
    series = sorted(float(r["ns_per_op"]) for r in rows
                    if (r["algorithm"], r["mode"], int(r["payload_bytes"]))
                    == (first["algorithm"], first["mode"], first["payload_bytes"]))
    assert first["median_ns"] == pytest.approx(series[2])


def test_experiment_writes_consistent_avalanche(quick_experiment):
    out, report, _ = quick_experiment
    with open(out / "avalanche.csv", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 100 * len(report["avalanche"])
    for row in rows:
        assert int(row["bit_index"]) == int(row["trial"]) - 1
        assert float(row["fraction"]) == pytest.approx(
            int(row["flipped_bits"]) / int(row["digest_bits"]))
    for agg in report["avalanche"]:
        mine = [int(r["flipped_bits"]) for r in rows if r["algorithm"] == agg["algorithm"]]
        assert (min(mine), max(mine)) == (agg["min_flipped_bits"], agg["max_flipped_bits"])
        assert agg["mean_flipped_bits"] == pytest.approx(sum(mine) / 100)


def test_experiment_report_has_no_local_paths_or_payloads(quick_experiment):
    out, _, _ = quick_experiment
    text = (out / "report.json").read_text(encoding="utf-8")
    assert str(Path.home()) not in text and str(out) not in text
    assert "Digital Dean synthetic export" not in text


def test_all_checks_pass_for_every_available_profile():
    for status in profiles.probe_profiles():
        if status["available"]:
            checks = hb.run_checks(status["algorithm"])
            assert [c["name"] for c in checks] == list(CHECK_NAMES)
            assert all(c["passed"] for c in checks)


def test_failed_check_is_kept_not_hidden(monkeypatch):
    monkeypatch.setitem(hb.KNOWN_VECTORS, "sha256", ("00", "00"))
    checks = {c["name"]: c["passed"] for c in hb.run_checks("sha256")}
    assert checks["known-abc"] is False and checks["known-empty"] is False


def test_source_commit_refuses_dirty_tree(monkeypatch):
    answers = {"rev-parse": "a" * 40, "status": " M app/main.py"}
    monkeypatch.setattr(hb, "_git", lambda *args: answers[args[0]])
    with pytest.raises(RuntimeError):
        hb.source_commit()
    assert hb.source_commit(allow_dirty=True) == "a" * 40


def test_route_does_not_import_or_run_benchmark():
    source = Path(hash_lab.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    imported += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    assert not any(name and name.startswith("benchmarks") for name in imported)
    assert "perf_counter" not in source and "run_experiment" not in source


def test_route_has_no_path_or_upload_parameters():
    operation = client.get("/openapi.json").json()["paths"][PATH]
    assert set(operation) == {"get"}
    assert "requestBody" not in operation["get"]


# ---------- Регресії практичних 1–3 ----------

def test_previous_routes_still_registered():
    paths = client.get("/openapi.json").json()["paths"]
    for path in ("/health", "/api/v1/students",
                 "/api/v1/students/{student_id}/secure-notes",
                 "/api/v1/lab/crypto/benchmark-results",
                 "/api/v1/lab/crypto/asymmetric-benchmark-results", PATH):
        assert path in paths


def test_previous_api_still_works():
    created = client.post("/api/v1/students", json={
        "full_name": "Олена Коваль", "email": "hash-regression@example.com",
        "group_code": "КН-31", "enrollment_year": 2024})
    assert created.status_code == 201
    student_id = created.json()["id"]
    note = client.post(f"/api/v1/students/{student_id}/secure-notes",
                       json={"text": "Синтетична примітка", "category": "academic"})
    assert note.status_code == 201
    read = client.get(f"/api/v1/students/{student_id}/secure-notes/{note.json()['id']}")
    assert read.status_code == 200 and read.json()["text"] == "Синтетична примітка"
    assert client.get("/api/v1/lab/crypto/asymmetric-benchmark-results",
                      params={"payload_bytes": 65}).status_code == 422
