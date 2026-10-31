"""Маршрут тільки читає звіт; не запускає вимірювання через HTTP."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, status

from app.security.profiles import BACKENDS, KEY_BYTES

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["crypto-lab"])
# Фіксований шлях із конфігурації; клієнт його не задає. Тести підміняють
# саме цю константу.
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-02/report.json"

UNAVAILABLE = "Benchmark results unavailable"
OPERATIONS = ("encrypt", "decrypt")
SERIES_COUNT = 5
RESULT_METRICS = ("median_ns", "iqr_ns", "throughput_mib_s")


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_result(row, sizes: list) -> tuple:
    if not isinstance(row, dict):
        raise ValueError("Result row must be an object")
    backend, algorithm = row.get("backend"), row.get("algorithm")
    size, operation = row.get("size_bytes"), row.get("operation")
    if backend not in BACKENDS or algorithm not in KEY_BYTES:
        raise ValueError("Unknown profile in report")
    if operation not in OPERATIONS or size not in sizes:
        raise ValueError("Unknown operation or size in report")
    series = row.get("series_mean_ns")
    if (
        not isinstance(series, list)
        or len(series) != SERIES_COUNT
        or not all(_is_number(v) and v > 0 for v in series)
    ):
        raise ValueError("Invalid series")
    for name in RESULT_METRICS:
        value = row.get(name)
        if not _is_number(value) or value < 0:
            raise ValueError("Invalid metric")
    if row["median_ns"] <= 0 or row["throughput_mib_s"] <= 0:
        raise ValueError("Invalid metric")
    return backend, algorithm, size, operation


def load_benchmark_report(path: Path) -> dict:
    """Читає й перевіряє report.json.

    Відсутній файл → FileNotFoundError; будь-яка інша проблема → ValueError.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("Unreadable report") from exc
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON") from exc

    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("Unsupported report schema")
    if not isinstance(report.get("run_id"), str) or not report["run_id"]:
        raise ValueError("Missing run_id")
    if not isinstance(report.get("environment"), dict):
        raise ValueError("Missing environment")
    parameters = report.get("parameters")
    if not isinstance(parameters, dict):
        raise ValueError("Missing parameters")
    sizes = parameters.get("sizes_bytes")
    if (
        not isinstance(sizes, list)
        or not sizes
        or not all(isinstance(s, int) and not isinstance(s, bool) and s > 0 for s in sizes)
    ):
        raise ValueError("Invalid sizes")
    results = report.get("results")
    expected = len(BACKENDS) * len(KEY_BYTES) * len(OPERATIONS) * len(sizes)
    if not isinstance(results, list) or len(results) != expected:
        raise ValueError("Unexpected number of results")
    seen = {_validate_result(row, sizes) for row in results}
    if len(seen) != expected:
        raise ValueError("Duplicate result rows")
    return report


@router.get("/benchmark-results")
def benchmark_results() -> dict:
    try:
        return load_benchmark_report(REPORT_PATH)
    except FileNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=UNAVAILABLE)
    except ValueError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=UNAVAILABLE)
