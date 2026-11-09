"""Окремий експеримент практичної роботи 3, не виклик з HTTP.

Запуск з кореня проєкту (після фіксації коду в Git):
    python -m benchmarks.asymmetric_benchmark

Створює results/practice-03/raw.csv (130 рядків) і report.json
(4 генерації ключа, 22 результати, 22 перевірки). Усі повідомлення
синтетичні; ключі, повідомлення й шифротексти нікуди не записуються.
"""
import argparse
import csv
import gc
import json
import os
import platform
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from secrets import token_bytes
from time import perf_counter_ns

from cryptography.hazmat.primitives import serialization

from app.schemas.asymmetric_report import validate_complete_report
from app.security.asymmetric.adapters import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import (
    CONTEXT,
    DIRECT_SIZE,
    HYBRID_SIZES,
    KEY_PROFILES,
    PROFILES,
    expected_ciphertext_bytes,
    oaep_max_bytes,
)

SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5
OPERATION_NAMES = ("encrypt", "decrypt")
DEFAULT_OUTPUT_DIR = Path("results/practice-03")
CSV_COLUMNS = (
    "group", "profile", "operation", "payload_bytes", "series_index",
    "operations", "elapsed_ns", "ns_per_operation", "ciphertext_bytes",
)


def measure_batch(operation, count: int = OPERATIONS) -> tuple[int, float]:
    if count < 1:
        raise ValueError("count must be positive")
    started = perf_counter_ns()
    for _ in range(count):
        operation()
    elapsed = perf_counter_ns() - started
    return elapsed, elapsed / count


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != SERIES:
        raise ValueError("five series required")
    q1, _, q3 = statistics.quantiles(samples, n=4, method="inclusive")
    return float(statistics.median(samples)), float(q3 - q1)


def combinations() -> list[tuple[str, str, int]]:
    """22 комбінації (профіль, операція, розмір) у фіксованому базовому порядку."""
    return [
        (profile, operation, size)
        for profile, spec in PROFILES.items()
        for operation in OPERATION_NAMES
        for size in spec.sizes
    ]


def rotate(items: list, shift: int) -> list:
    shift %= len(items)
    return items[shift:] + items[:shift]


def _der_size(public: object) -> int:
    return len(public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def measure_key_generation() -> tuple[list[dict], list[dict]]:
    """П'ять незалежних вимірювань генерації кожного типу ключа."""
    rows, summary = [], []
    for key_profile in KEY_PROFILES:
        generate_keypair(key_profile)  # прогрів, не записується
    samples: dict[str, list[int]] = {name: [] for name in KEY_PROFILES}
    der_sizes: dict[str, int] = {}
    for run in range(1, KEYGEN_RUNS + 1):
        for key_profile in KEY_PROFILES:
            gc.collect()
            started = perf_counter_ns()
            _, public = generate_keypair(key_profile)
            elapsed = perf_counter_ns() - started
            samples[key_profile].append(elapsed)
            der_sizes[key_profile] = _der_size(public)  # поза таймером
            rows.append({
                "group": "key_generation", "profile": key_profile,
                "operation": "keygen", "payload_bytes": 0,
                "series_index": run, "operations": 1, "elapsed_ns": elapsed,
                "ns_per_operation": float(elapsed), "ciphertext_bytes": 0,
            })
    for key_profile in KEY_PROFILES:
        median_ns, iqr_ns = summarize([float(v) for v in samples[key_profile]])
        summary.append({
            "key_profile": key_profile, "runs": KEYGEN_RUNS,
            "median_ns": median_ns, "iqr_ns": iqr_ns,
            "public_key_der_bytes": der_sizes[key_profile],
        })
    return rows, summary


def run_checks(keys: dict[str, tuple[object, object]]) -> list[dict]:
    """22 перевірки коректності (таблиця 8 завдання)."""
    checks = []

    def add(profile: str, name: str, passed: bool) -> None:
        checks.append({"profile": profile, "name": name, "passed": bool(passed)})

    def rejected(profile: str, private: object, envelope: bytes, **kw) -> bool:
        try:
            decrypt(profile, private, envelope, **kw)
        except DecryptionError:
            return True
        return False

    for profile, spec in PROFILES.items():
        private, public = keys[spec.key_profile]
        other_private, _ = generate_keypair(spec.key_profile)
        try:
            ok = True
            for size in spec.sizes:
                message = token_bytes(size)
                envelope = encrypt(profile, public, message)
                ok = ok and decrypt(profile, private, envelope) == message
                ok = ok and len(envelope) == expected_ciphertext_bytes(profile, size)
        except Exception:
            ok = False
        add(profile, "roundtrip", ok)
        envelope = encrypt(profile, public, b"synthetic-record")
        add(profile, "wrong_key", rejected(profile, other_private, envelope))
        changed = envelope[:-1] + bytes([envelope[-1] ^ 1])
        add(profile, "tamper", rejected(profile, private, changed))
        add(profile, "wrong_context",
            rejected(profile, private, envelope, context=b"wrong-context"))
    for bits in (2048, 3072):
        profile = f"rsa{bits}-oaep"
        private, public = keys[f"rsa-{bits}"]
        limit = oaep_max_bytes(bits)
        message = token_bytes(limit)
        try:
            passes = decrypt(profile, private, encrypt(profile, public, message)) == message
        except Exception:
            passes = False
        try:
            encrypt(profile, public, token_bytes(limit + 1))
            refused = False
        except ValueError:
            refused = True
        add(profile, "oaep_boundary", passes and refused)
    return checks


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, timeout=10, check=True
    ).stdout.strip()


def source_commit(allow_dirty: bool = False) -> str:
    """SHA коду перед запуском; відмовляє, якщо код ще не зафіксовано."""
    commit = _git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("cannot determine the source commit")
    if not allow_dirty and _git("status", "--porcelain", "--", "app", "benchmarks"):
        raise RuntimeError("commit the code in app/ and benchmarks/ before the experiment")
    return commit


def _cpu_model() -> str:
    try:
        if sys.platform == "win32":
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as handle:
                return str(winreg.QueryValueEx(handle, "ProcessorNameString")[0]).strip()
        if sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True, timeout=5)
            if out.stdout.strip():
                return out.stdout.strip()
        else:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def _openssl_version() -> str:
    """Версія OpenSSL, з якою зібрано саме бібліотеку cryptography."""
    try:
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl

        return str(rust_openssl.CRYPTOGRAPHY_OPENSSL_VERSION_TEXT)
    except Exception:
        pass
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text()
    except Exception:
        return "unknown"


def collect_environment() -> dict:
    return {
        "python": platform.python_version(),
        "cryptography": metadata.version("cryptography"),
        "openssl": _openssl_version(),
        "os": platform.platform(),
        "cpu": _cpu_model(),
    }


def _atomic_write(path: Path, writer) -> None:
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "w", newline="", encoding="utf-8") as handle:
        writer(handle)
    os.replace(temp, path)


def run_experiment(output_dir: Path = DEFAULT_OUTPUT_DIR, *,
                   commit: str | None = None, allow_dirty: bool = False) -> dict:
    output_dir = Path(output_dir)
    commit = commit or source_commit(allow_dirty)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    environment = collect_environment()

    # Ключі одержувачів: поза таймером, окремо від вимірювання генерації.
    keys = {name: generate_keypair(name) for name in KEY_PROFILES}
    messages = {size: token_bytes(size) for size in {DIRECT_SIZE, *HYBRID_SIZES}}

    def prepare(combo):
        profile, operation, size = combo
        private, public = keys[PROFILES[profile].key_profile]
        message = messages[size]
        if operation == "encrypt":
            state = {"envelope": b""}

            def run():
                state["envelope"] = encrypt(profile, public, message)
            return run, state, message, private
        envelopes = iter([encrypt(profile, public, message) for _ in range(OPERATIONS)])
        state = {"plain": b""}

        def run():
            state["plain"] = decrypt(profile, private, next(envelopes))
        return run, state, message, private

    # Прогрів: 10 операцій на комбінацію, у CSV не потрапляє.
    for combo in combinations():
        profile, operation, size = combo
        _, public = keys[PROFILES[profile].key_profile]
        private = keys[PROFILES[profile].key_profile][0]
        for _ in range(WARMUP):
            envelope = encrypt(profile, public, messages[size])
            if operation == "decrypt":
                decrypt(profile, private, envelope)

    rows, key_generation = measure_key_generation()
    samples: dict[tuple, list[float]] = {combo: [] for combo in combinations()}
    ciphertext_len: dict[tuple, int] = {}
    base = combinations()
    for series_index in range(1, SERIES + 1):
        # Порядок профілів циклічно змінюється перед кожною серією.
        for combo in rotate(base, series_index - 1):
            run, state, message, private = prepare(combo)
            gc.collect()
            elapsed, per_operation = measure_batch(run, OPERATIONS)
            profile, operation, size = combo
            if operation == "encrypt":
                envelope = state["envelope"]
                if decrypt(profile, private, envelope) != message:
                    raise RuntimeError("round trip failed during measurement")
                ciphertext_len[combo] = len(envelope)
            else:
                if state["plain"] != message:
                    raise RuntimeError("decryption returned unexpected data")
                ciphertext_len.setdefault(
                    combo, expected_ciphertext_bytes(profile, size))
            samples[combo].append(per_operation)
            rows.append({
                "group": PROFILES[profile].group, "profile": profile,
                "operation": operation, "payload_bytes": size,
                "series_index": series_index, "operations": OPERATIONS,
                "elapsed_ns": elapsed, "ns_per_operation": per_operation,
                "ciphertext_bytes": ciphertext_len[combo],
            })

    results = []
    for combo in base:
        profile, operation, size = combo
        median_ns, iqr_ns = summarize(samples[combo])
        group = PROFILES[profile].group
        results.append({
            "profile": profile, "group": group, "operation": operation,
            "payload_bytes": size, "series": SERIES,
            "operations_per_series": OPERATIONS,
            "median_ns": median_ns, "iqr_ns": iqr_ns,
            "ciphertext_bytes": ciphertext_len[combo],
            "throughput_mib_s": (
                size * 1e9 / (2**20 * median_ns) if group == "hybrid" else None
            ),
        })
    report = {
        "schema_version": 1,
        "experiment": {
            "series": SERIES, "operations_per_series": OPERATIONS,
            "warmup": WARMUP, "keygen_runs": KEYGEN_RUNS,
            "direct_payload_bytes": DIRECT_SIZE,
            "hybrid_sizes_bytes": list(HYBRID_SIZES),
            "source_commit": commit, "created_at_utc": created_at,
        },
        "environment": environment,
        "key_generation": key_generation,
        "results": results,
        "checks": run_checks(keys),
    }
    validate_complete_report(report)  # структурна й семантична перевірка до запису
    if len(rows) != 130:
        raise RuntimeError("unexpected number of raw rows")

    output_dir.mkdir(parents=True, exist_ok=True)

    def write_csv(handle):
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    def write_json(handle):
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    _atomic_write(output_dir / "raw.csv", write_csv)
    _atomic_write(output_dir / "report.json", write_json)
    failed = [c for c in report["checks"] if not c["passed"]]
    print(f"Готово: {len(rows)} рядків raw.csv, {len(results)} результатів, "
          f"{len(report['checks'])} перевірок (невдалих: {len(failed)}) -> {output_dir}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Practice 3 asymmetric benchmark")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--allow-dirty", action="store_true",
                        help="лише для розробки: дозволити незафіксований код")
    args = parser.parse_args(argv)
    try:
        run_experiment(args.output_dir, allow_dirty=args.allow_dirty)
    except (NotImplementedError, RuntimeError) as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
