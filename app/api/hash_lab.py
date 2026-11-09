"""GET-маршрут збереженого звіту хешування (практична 4), підключений до app/main.py.

Маршрут лише читає results/practice-04/report.json: експеримент із HTTP не
запускається, шлях файлу задає тільки сервер, документи й паролі не приймаються.
"""
import json
from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError
from app.schemas.hash_report import (
    HashReport, HashResponse, filter_by_payload, validate_report,
)
from app.security.hashing.profiles import PAYLOAD_SIZES

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["hash-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-04/report.json"
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


def load_report() -> HashReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
        return validate_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "hash report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "hash report invalid") from exc


@router.get(
    "/hash-benchmark-results",
    response_model=HashResponse,
    summary="Збережений звіт експерименту хешування",
    description=(
        "Повертає перевірений звіт results/practice-04/report.json. "
        "Індивідуальний варіант 1: необов'язковий параметр payload_bytes "
        "фільтрує лише results; algorithms, avalanche і checks лишаються повними."
    ),
    responses={
        404: {"description": "hash report not found"},
        422: {"description": "unsupported payload_bytes"},
        500: {"description": "hash report invalid"},
    },
)
def get_hash_benchmark_results(
    payload_bytes: Annotated[
        int | None,
        Query(description="Фільтр results: 64, 1024, 65536 або 1048576 байтів."),
    ] = None,
) -> HashResponse:
    # Варіант 1: тип int перевіряє FastAPI, перелік розмірів — явна перевірка.
    if payload_bytes is not None and payload_bytes not in PAYLOAD_SIZES:
        raise HTTPException(422, "unsupported payload_bytes")
    # Спочатку перевіряється весь файл як HashReport, потім фільтр.
    return filter_by_payload(load_report(), payload_bytes)
