"""GET-маршрут збереженого звіту асиметричного експерименту (практична 3).

Маршрут лише читає results/practice-03/report.json: експеримент із HTTP не
запускається, шлях файлу задає тільки сервер.
"""
import json
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.schemas.asymmetric_report import (
    ALLOWED_PAYLOAD_BYTES,
    BenchmarkReport,
    BenchmarkResponse,
    filter_report,
    validate_complete_report,
)

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["asymmetric-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-03/report.json"
MAX_REPORT_BYTES = 1048576  # Local teaching limit, not a universal JSON limit.


def _reject_constant(value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def load_report() -> BenchmarkReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
        return validate_complete_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "benchmark report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "benchmark report invalid") from exc


@router.get(
    "/asymmetric-benchmark-results",
    response_model=BenchmarkResponse,
    summary="Збережений звіт асиметричного й гібридного експерименту",
    responses={
        404: {"description": "benchmark report not found"},
        422: {"description": "unsupported payload_bytes"},
        500: {"description": "benchmark report invalid"},
    },
)
def get_asymmetric_benchmark_results(
    payload_bytes: Annotated[
        int | None,
        Query(
            description=(
                "Необов'язковий фільтр results за розміром повідомлення: "
                "64, 1024, 65536 або 1048576 байтів."
            ),
        ),
    ] = None,
) -> BenchmarkResponse:
    # Індивідуальний варіант 1: перевірка переліку явна, а не лише типом int.
    if payload_bytes is not None and payload_bytes not in ALLOWED_PAYLOAD_BYTES:
        raise HTTPException(422, "unsupported payload_bytes")
    # Спочатку перевіряється повний файл, потім фільтрується лише results.
    return filter_report(load_report(), payload_bytes)
