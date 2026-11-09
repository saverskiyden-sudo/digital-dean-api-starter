"""Синтетичний звіт лише для автоматичних тестів (не результат вимірювань).

Числа часу тут умовні й потрібні, щоб перевірити структуру, покриття та
формули валідатора. Справжні вимірювання створює benchmarks.asymmetric_benchmark.
"""
import copy

from app.schemas.asymmetric_report import EXPECTED_CHECKS, EXPECTED_DER_BYTES
from app.security.asymmetric.profiles import (
    HYBRID_SIZES,
    KEY_PROFILES,
    PROFILES,
    expected_ciphertext_bytes,
)


def make_report() -> dict:
    results = []
    for index, (profile, spec) in enumerate(PROFILES.items(), start=1):
        for operation in ("encrypt", "decrypt"):
            for size in spec.sizes:
                median = 1000.0 * index * (size // 64 + 1)
                results.append({
                    "profile": profile,
                    "group": spec.group,
                    "operation": operation,
                    "payload_bytes": size,
                    "series": 5,
                    "operations_per_series": 20,
                    "median_ns": median,
                    "iqr_ns": median / 10,
                    "ciphertext_bytes": expected_ciphertext_bytes(profile, size),
                    "throughput_mib_s": (
                        size * 1e9 / (2**20 * median) if spec.group == "hybrid" else None
                    ),
                })
    return {
        "schema_version": 1,
        "experiment": {
            "series": 5,
            "operations_per_series": 20,
            "warmup": 10,
            "keygen_runs": 5,
            "direct_payload_bytes": 64,
            "hybrid_sizes_bytes": list(HYBRID_SIZES),
            "source_commit": "a" * 40,
            "created_at_utc": "2026-11-01T12:00:00+00:00",
        },
        "environment": {
            "python": "3.13.0",
            "cryptography": "48.0.1",
            "openssl": "OpenSSL test",
            "os": "TestOS",
            "cpu": "Test CPU",
        },
        "key_generation": [
            {
                "key_profile": name,
                "runs": 5,
                "median_ns": 5000.0,
                "iqr_ns": 100.0,
                "public_key_der_bytes": EXPECTED_DER_BYTES[name],
            }
            for name in KEY_PROFILES
        ],
        "results": results,
        "checks": [
            {"profile": profile, "name": name, "passed": True}
            for profile, name in sorted(EXPECTED_CHECKS)
        ],
    }


def mutated(**changes) -> dict:
    """Копія валідного звіту; ключі верхнього рівня замінюються через changes."""
    report = copy.deepcopy(make_report())
    report.update(changes)
    return report
