"""Структура звіту практичної 4 та повна змістова перевірка validate_report."""
from datetime import datetime, timedelta, timezone
from math import isclose, isfinite
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictInt
from app.security.hashing.profiles import (
    CHECK_NAMES, PAYLOAD_SIZES, PROFILES, AlgorithmID, Mode, repeat_count,
)

MODES = ("whole", "chunked")
LEGACY_ALGORITHMS = tuple(name for name, profile in PROFILES.items() if profile.legacy)
# Допуск для порівняння збереженої пропускної здатності з формулою 2 (округлення float).
THROUGHPUT_REL_TOL = 1e-9
# Допуск на розбіжність годинників: звіт не може бути створений «у майбутньому».
CLOCK_SKEW = timedelta(minutes=10)


def _exact_int(value):
    if type(value) is not int:
        raise ValueError("integer required; bool/float/string is not an integer")
    return value


Version = Annotated[Literal[1], BeforeValidator(_exact_int)]
Int5 = Annotated[Literal[5], BeforeValidator(_exact_int)]
Int10 = Annotated[Literal[10], BeforeValidator(_exact_int)]
Int100 = Annotated[Literal[100], BeforeValidator(_exact_int)]
Int1000 = Annotated[Literal[1000], BeforeValidator(_exact_int)]
Int1024 = Annotated[Literal[1024], BeforeValidator(_exact_int)]
Int16384 = Annotated[Literal[16384], BeforeValidator(_exact_int)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonnegativeInt = Annotated[StrictInt, Field(ge=0)]
Positive = Annotated[float, Field(gt=0)]
Nonnegative = Annotated[float, Field(ge=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)


class Parameters(StrictModel):
    sizes: list[PositiveInt] = Field(min_length=4, max_length=4)
    chunk_bytes: Int16384
    warmup: Int10
    series: Int5
    repeats_small: Int1000
    repeats_large: Int100
    avalanche_trials: Int100
    avalanche_bytes: Int1024


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=160)
    openssl_ssl: str = Field(min_length=1, max_length=160)
    os: str = Field(min_length=1, max_length=240)
    cpu: str = Field(min_length=1, max_length=160)
    architecture: str = Field(min_length=1, max_length=80)


class AlgorithmStatus(StrictModel):
    algorithm: AlgorithmID
    available: bool
    reason: Literal["not_available_in_environment"] | None
    implementation: str | None = Field(max_length=160)


class PerformanceResult(StrictModel):
    algorithm: AlgorithmID
    mode: Mode
    payload_bytes: PositiveInt
    digest_bytes: PositiveInt
    repeats: PositiveInt
    median_ns: Positive
    iqr_ns: Nonnegative
    throughput_mib_s: Positive


class AvalancheResult(StrictModel):
    algorithm: AlgorithmID
    input_bytes: Int1024
    trials: Int100
    digest_bits: PositiveInt
    min_flipped_bits: NonnegativeInt
    max_flipped_bits: NonnegativeInt
    mean_flipped_bits: Nonnegative
    mean_fraction: float = Field(ge=0, le=1)


class CorrectnessCheck(StrictModel):
    algorithm: AlgorithmID
    name: Literal["known-abc", "known-empty", "unicode-utf8", "determinism",
                  "digest-length", "stream-equivalence"]
    passed: bool


class Summary(StrictModel):
    algorithms_count: PositiveInt
    available_count: PositiveInt
    results_count: NonnegativeInt
    checks_count: NonnegativeInt
    all_checks_passed: bool


class HashReport(StrictModel):
    schema_version: Version
    created_at: str = Field(min_length=20, max_length=40)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    parameters: Parameters
    environment: Environment
    algorithms: list[AlgorithmStatus] = Field(min_length=7, max_length=7)
    results: list[PerformanceResult] = Field(min_length=40, max_length=56)
    avalanche: list[AvalancheResult] = Field(min_length=5, max_length=7)
    checks: list[CorrectnessCheck] = Field(min_length=30, max_length=42)


class HashResponse(HashReport):
    # Filtering may return fewer results; full disk report must stay complete.
    results: list[PerformanceResult] = Field(max_length=56)
    summary: Summary | None = None


def _parse_utc(value: str) -> datetime:
    """Чинний момент UTC: Z або +00:00; дата перевіряється розбором, а не regex."""
    if not (value.endswith("Z") or value.endswith("+00:00")):
        raise ValueError("created_at must end with Z or +00:00")
    try:
        moment = datetime.fromisoformat(value.removesuffix("Z") + "+00:00"
                                        if value.endswith("Z") else value)
    except ValueError as exc:
        raise ValueError("created_at is not a valid date and time") from exc
    if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
        raise ValueError("created_at must be UTC")
    if moment > datetime.now(timezone.utc) + CLOCK_SKEW:
        raise ValueError("created_at is in the future")
    return moment


def _unique(keys: list[tuple], what: str) -> set[tuple]:
    if len(keys) != len(set(keys)):
        raise ValueError(f"duplicate {what} records")
    return set(keys)


def validate_report(data: object) -> HashReport:
    """Повна перевірка збереженого звіту; ValidationError теж є ValueError.

    Записи checks з passed=False є допустимими діагностичними даними й не
    вилучаються: звіт залишається структурно валідним.
    """
    report = HashReport.model_validate(data)
    _parse_utc(report.created_at)

    if report.parameters.sizes != list(PAYLOAD_SIZES):
        raise ValueError("parameters.sizes must be exactly 64, 1024, 65536, 1048576")

    # Статуси: рівно сім унікальних профілів; недоступними можуть бути лише legacy.
    names = _unique([(row.algorithm,) for row in report.algorithms], "algorithm")
    if names != {(name,) for name in PROFILES}:
        raise ValueError("algorithms must list each of the seven profiles once")
    available = []
    for row in report.algorithms:
        if row.available:
            if row.reason is not None or not row.implementation:
                raise ValueError("available profile needs implementation and no reason")
            available.append(row.algorithm)
        else:
            if row.algorithm not in LEGACY_ALGORITHMS:
                raise ValueError("a required profile cannot be unavailable")
            if row.reason != "not_available_in_environment" or row.implementation is not None:
                raise ValueError("unavailable profile needs reason and null implementation")
    available_set = set(available)

    # Матриця швидкодії: усі доступні профілі × 4 розміри × 2 способи, без дублікатів.
    expected = {(a, m, s) for a in available for m in MODES for s in PAYLOAD_SIZES}
    actual = _unique([(r.algorithm, r.mode, r.payload_bytes) for r in report.results],
                     "results")
    if actual != expected:
        raise ValueError("results must cover exactly the available matrix")
    for r in report.results:
        if r.digest_bytes != PROFILES[r.algorithm].digest_bytes:
            raise ValueError("digest_bytes does not match the profile")
        if r.repeats != repeat_count(r.payload_bytes):
            raise ValueError("repeats does not match the payload size")
        for value in (r.median_ns, r.iqr_ns, r.throughput_mib_s):
            if not isfinite(value):
                raise ValueError("measurements must be finite")
        formula = r.payload_bytes * 1e9 / (2**20 * r.median_ns)
        if not isclose(r.throughput_mib_s, formula, rel_tol=THROUGHPUT_REL_TOL):
            raise ValueError("throughput_mib_s does not follow formula 2")

    # Лавинний дослід: один агрегат на доступний профіль, межі й частка узгоджені.
    lav = _unique([(a.algorithm,) for a in report.avalanche], "avalanche")
    if lav != {(a,) for a in available_set}:
        raise ValueError("avalanche must have one record per available profile")
    for a in report.avalanche:
        bits = 8 * PROFILES[a.algorithm].digest_bytes
        if a.digest_bits != bits:
            raise ValueError("digest_bits does not match the profile")
        if not (0 <= a.min_flipped_bits <= a.mean_flipped_bits
                <= a.max_flipped_bits <= bits):
            raise ValueError("avalanche distances are inconsistent")
        if not isclose(a.mean_fraction, a.mean_flipped_bits / bits,
                       rel_tol=1e-9, abs_tol=1e-12):
            raise ValueError("mean_fraction must equal mean_flipped_bits / digest_bits")

    # Перевірки: кожна з шести назв рівно раз для кожного доступного профілю.
    got = _unique([(c.algorithm, c.name) for c in report.checks], "checks")
    if got != {(a, n) for a in available_set for n in CHECK_NAMES}:
        raise ValueError("checks must contain six named checks per available profile")
    return report


def filter_by_payload(report: HashReport, payload_bytes: int | None) -> HashResponse:
    """Варіант 1: фільтр лише поля results; algorithms/avalanche/checks повні."""
    data = report.model_dump()
    if payload_bytes is not None:
        data["results"] = [r for r in data["results"]
                           if r["payload_bytes"] == payload_bytes]
    return HashResponse.model_validate(data)
