"""Структура базового звіту та семантична перевірка збереженого JSON."""
from datetime import datetime, timedelta
from math import isclose
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.security.asymmetric.profiles import (
    DIRECT_SIZE,
    HYBRID_SIZES,
    KEY_PROFILES,
    PROFILES,
    expected_ciphertext_bytes,
)


def _exact_integer(value: object) -> int:
    # Numeric Literal comparisons alone can accept True or 5.0 as integers.
    if type(value) is not int:
        raise ValueError("an exact integer is required")
    return value


One = Annotated[Literal[1], BeforeValidator(_exact_integer)]
Five = Annotated[Literal[5], BeforeValidator(_exact_integer)]
Ten = Annotated[Literal[10], BeforeValidator(_exact_integer)]
Twenty = Annotated[Literal[20], BeforeValidator(_exact_integer)]
SixtyFour = Annotated[Literal[64], BeforeValidator(_exact_integer)]

ProfileId = Literal[
    "rsa2048-oaep", "rsa3072-oaep", "rsa3072-oaep-aes256gcm",
    "hpke-x25519-aes256gcm", "hpke-p256-aes256gcm",
]
KeyId = Literal["rsa-2048", "rsa-3072", "x25519", "p256"]
PositiveFloat = Annotated[float, Field(gt=0, allow_inf_nan=False)]
NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Experiment(StrictModel):
    series: Five
    operations_per_series: Twenty
    warmup: Ten
    keygen_runs: Five
    direct_payload_bytes: SixtyFour
    hybrid_sizes_bytes: list[int]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    created_at_utc: str = Field(min_length=20, max_length=40)


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=100)
    cryptography: Literal["48.0.1"]
    openssl: str = Field(min_length=1, max_length=150)
    os: str = Field(min_length=1, max_length=150)
    cpu: str = Field(min_length=1, max_length=200)


class KeyGeneration(StrictModel):
    key_profile: KeyId
    runs: Five
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    public_key_der_bytes: int = Field(gt=0, le=4096)


class Result(StrictModel):
    profile: ProfileId
    group: Literal["direct", "hybrid"]
    operation: Literal["encrypt", "decrypt"]
    payload_bytes: int = Field(gt=0, le=1048576)
    series: Five
    operations_per_series: Twenty
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    ciphertext_bytes: int = Field(gt=0, le=1048988)
    throughput_mib_s: PositiveFloat | None


class Check(StrictModel):
    profile: ProfileId
    name: Literal["roundtrip", "wrong_key", "tamper", "wrong_context", "oaep_boundary"]
    passed: bool


class BenchmarkReport(StrictModel):
    schema_version: One
    experiment: Experiment
    environment: Environment
    key_generation: list[KeyGeneration] = Field(min_length=4, max_length=4)
    results: list[Result] = Field(min_length=22, max_length=22)
    checks: list[Check] = Field(min_length=22, max_length=22)


class BenchmarkResponse(BenchmarkReport):
    # First validate the complete saved report, then filter only results.
    # Keep key_generation and checks complete. An empty filtered list is valid.
    results: list[Result] = Field(max_length=22)


# Довжина відкритого ключа в DER SubjectPublicKeyInfo (e = 65537 для RSA).
EXPECTED_DER_BYTES = {"rsa-2048": 294, "rsa-3072": 422, "x25519": 44, "p256": 91}
EXPECTED_CHECKS = {
    (profile, name)
    for profile in PROFILES
    for name in ("roundtrip", "wrong_key", "tamper", "wrong_context")
} | {("rsa2048-oaep", "oaep_boundary"), ("rsa3072-oaep", "oaep_boundary")}


def _expected_results() -> set[tuple[str, str, int]]:
    return {
        (profile, operation, size)
        for profile, spec in PROFILES.items()
        for operation in ("encrypt", "decrypt")
        for size in spec.sizes
    }


def _check_metadata(report: "BenchmarkReport") -> None:
    experiment = report.experiment
    if experiment.hybrid_sizes_bytes != list(HYBRID_SIZES):
        raise ValueError("unexpected hybrid sizes")
    if experiment.direct_payload_bytes != DIRECT_SIZE:
        raise ValueError("unexpected direct payload size")
    try:
        created = datetime.fromisoformat(experiment.created_at_utc.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at_utc is not ISO 8601") from exc
    if created.tzinfo is None or created.utcoffset() != timedelta(0):
        raise ValueError("created_at_utc must be in UTC")


def _check_key_generation(report: "BenchmarkReport") -> None:
    profiles = [item.key_profile for item in report.key_generation]
    if sorted(profiles) != sorted(KEY_PROFILES):
        raise ValueError("key generation coverage is not exact")
    for item in report.key_generation:
        if item.public_key_der_bytes != EXPECTED_DER_BYTES[item.key_profile]:
            raise ValueError("unexpected public key DER size")


def _check_results(report: "BenchmarkReport") -> None:
    seen: set[tuple[str, str, int]] = set()
    for item in report.results:
        spec = PROFILES[item.profile]
        combo = (item.profile, item.operation, item.payload_bytes)
        if combo in seen:
            raise ValueError("duplicate result")
        seen.add(combo)
        if item.group != spec.group or item.payload_bytes not in spec.sizes:
            raise ValueError("result does not match its profile")
        if item.ciphertext_bytes != expected_ciphertext_bytes(
            item.profile, item.payload_bytes
        ):
            raise ValueError("unexpected ciphertext length")
        if spec.group == "direct":
            if item.throughput_mib_s is not None:
                raise ValueError("direct profiles have no throughput")
            continue
        if item.throughput_mib_s is None:
            raise ValueError("hybrid profiles need throughput")
        formula = item.payload_bytes * 1e9 / (2**20 * item.median_ns)
        if not isclose(item.throughput_mib_s, formula, rel_tol=1e-6):
            raise ValueError("throughput does not match the formula")
    if seen != _expected_results():
        raise ValueError("result coverage is not exact")


def _check_checks(report: "BenchmarkReport") -> None:
    keys = [(item.profile, item.name) for item in report.checks]
    if len(set(keys)) != len(keys) or set(keys) != EXPECTED_CHECKS:
        raise ValueError("check coverage is not exact")
    # passed=false не відхиляється: це чесний результат невдалої перевірки.


def validate_complete_report(data: object) -> BenchmarkReport:
    report = BenchmarkReport.model_validate(data)
    _check_metadata(report)
    _check_key_generation(report)
    _check_results(report)
    _check_checks(report)
    return report


# Індивідуальний варіант 1 (номер 17, 17 mod 4 = 1): фільтр payload_bytes.
ALLOWED_PAYLOAD_BYTES = (DIRECT_SIZE, *HYBRID_SIZES)


def filter_report(report: BenchmarkReport, payload_bytes: int | None) -> BenchmarkResponse:
    """Фільтрує лише results; key_generation і checks лишаються повними.

    Повний файл уже перевірено validate_complete_report. Порожній результат
    фільтрації допустимий, тому вимога «рівно 22» тут не застосовується.
    """
    data = report.model_dump()
    if payload_bytes is not None:
        data["results"] = [
            item for item in data["results"] if item["payload_bytes"] == payload_bytes
        ]
    return BenchmarkResponse.model_validate(data)
