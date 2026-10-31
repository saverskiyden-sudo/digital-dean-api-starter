"""Відтворюваний дослід: 6 комбінацій × 3 розміри × 2 операції.

Запуск з кореня проєкту:
    python -m benchmarks.crypto_benchmark --output-dir results/practice-02
"""

import argparse
import csv
import gc
import json
import os
import platform
import random
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from secrets import token_bytes
from statistics import median, quantiles
from time import perf_counter_ns

from app.security.adapters import open_bytes, seal_bytes
from app.security.nonce import NonceSequence
from app.security.profiles import BACKENDS, KEY_BYTES

SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100
BENCHMARK_AAD = b"digital-dean-practice-02-benchmark".ljust(64, b".")
OPERATIONS = ("encrypt", "decrypt")
ORDER_SEED = 20260101  # лише для порядку комбінацій, не для ключів
CSV_COLUMNS = (
    "run_id", "backend", "algorithm", "size_bytes", "operation",
    "series_index", "operations", "total_ns", "mean_ns",
)


def measure_batch(operation, arguments) -> float:
    """Середній час однієї операції в серії, нс (perf_counter_ns)."""
    if not arguments:
        raise ValueError("Empty batch")
    started = perf_counter_ns()
    for item in arguments:
        operation(*item)
    elapsed = perf_counter_ns() - started
    if elapsed <= 0:
        raise RuntimeError("Invalid elapsed time")
    return elapsed / len(arguments)


def summarize(series_mean_ns, size_bytes) -> dict:
    """Медіана 5 середніх, inclusive IQR і МіБ/с за початковими байтами."""
    if len(series_mean_ns) != 5:
        raise ValueError("Five series required")
    q1, _, q3 = quantiles(series_mean_ns, n=4, method="inclusive")
    typical = median(series_mean_ns)
    if typical <= 0:
        raise ValueError("Time must be positive")
    return {
        "median_ns": typical,
        "iqr_ns": q3 - q1,
        "throughput_mib_s": size_bytes * 1e9 / (2**20 * typical),
    }


class _Combo:
    """Окремий випадковий ключ і спільний лічильник на бібліотеку/профіль."""

    def __init__(self, backend: str, algorithm: str):
        self.backend = backend
        self.algorithm = algorithm
        self.key = token_bytes(KEY_BYTES[algorithm])
        self.nonces = NonceSequence()

    def seal_args(self, data: bytes, count: int) -> list:
        return [
            (self.backend, self.algorithm, self.key, self.nonces.next(), data,
             BENCHMARK_AAD)
            for _ in range(count)
        ]

    def open_args(self, data: bytes, count: int) -> list:
        items = []
        for _ in range(count):
            nonce = self.nonces.next()
            ct, tag = seal_bytes(
                self.backend, self.algorithm, self.key, nonce, data, BENCHMARK_AAD
            )
            items.append(
                (self.backend, self.algorithm, self.key, nonce, ct, tag,
                 BENCHMARK_AAD)
            )
        return items

    def args(self, operation: str, data: bytes, count: int) -> list:
        return (self.seal_args if operation == "encrypt" else self.open_args)(
            data, count
        )


def _verify_round_trips(combos, sizes) -> None:
    for combo in combos:
        for size in sizes:
            data = token_bytes(size)
            nonce = combo.nonces.next()
            ct, tag = seal_bytes(
                combo.backend, combo.algorithm, combo.key, nonce, data, BENCHMARK_AAD
            )
            restored = open_bytes(
                combo.backend, combo.algorithm, combo.key, nonce, ct, tag,
                BENCHMARK_AAD,
            )
            if restored != data:
                raise RuntimeError(
                    f"Round trip failed: {combo.backend} {combo.algorithm}"
                )


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
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5,
            )
            if out.stdout.strip():
                return out.stdout.strip()
        else:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def _cpu_aes_flag() -> str:
    """Лише те, що відомо напевно; інакше «unknown»."""
    try:
        if sys.platform.startswith("linux"):
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("flags"):
                    flags = line.split(":", 1)[1].split()
                    return "AES-NI flag present" if "aes" in flags else "AES flag absent"
    except Exception:
        pass
    return "unknown (not detected by this script)"


def _openssl_version() -> str:
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text()
    except Exception:
        pass
    try:
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl

        return str(rust_openssl.CRYPTOGRAPHY_OPENSSL_VERSION_TEXT)
    except Exception:
        return "unknown"


def _git_state() -> str:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "app", "benchmarks"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if commit:
            return commit + (" (uncommitted changes in app/benchmarks)" if dirty else "")
    except Exception:
        pass
    return "unknown"


def _version(package: str) -> str:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return "unknown"


def collect_environment() -> dict:
    return {
        "cpu_model": _cpu_model(),
        "cpu_logical_cores": os.cpu_count(),
        "hardware_acceleration": _cpu_aes_flag(),
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "cryptography": _version("cryptography"),
        "pycryptodome": _version("pycryptodome"),
        "cryptography_openssl": _openssl_version(),
        "timer": "time.perf_counter_ns",
        "timer_resolution_s": time.get_clock_info("perf_counter").resolution,
        "code_commit": _git_state(),
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def run_benchmark(
    output_dir: Path,
    *,
    sizes=SIZES_BYTES,
    warmup: int = WARMUP,
    operations_per_series: int = OPERATIONS_PER_SERIES,
) -> None:
    """Виконує дослід і записує raw.csv та report.json (без ключів і даних)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:6]
    environment = collect_environment()

    combos = [_Combo(b, a) for b in BACKENDS for a in KEY_BYTES]
    _verify_round_trips(combos, sizes)

    rng = random.Random(ORDER_SEED)
    raw_rows: list = []
    results: list = []

    for size in sizes:
        data = token_bytes(size)  # однакові байти для всіх реалізацій розміру
        for operation in OPERATIONS:
            operation_fn = seal_bytes if operation == "encrypt" else open_bytes
            # Прогрівання (нові nonce також для шифрування) поза статистикою.
            for combo in combos:
                for item in combo.args(operation, data, warmup):
                    operation_fn(*item)
            series_means = {(c.backend, c.algorithm): [] for c in combos}
            for series_index in range(1, SERIES + 1):
                order = combos[:]
                rng.shuffle(order)  # порядок комбінацій змінюється між серіями
                for combo in order:
                    arguments = combo.args(operation, data, operations_per_series)
                    gc.collect()
                    mean_ns = measure_batch(operation_fn, arguments)
                    del arguments
                    series_means[(combo.backend, combo.algorithm)].append(mean_ns)
                    raw_rows.append({
                        "run_id": run_id,
                        "backend": combo.backend,
                        "algorithm": combo.algorithm,
                        "size_bytes": size,
                        "operation": operation,
                        "series_index": series_index,
                        "operations": operations_per_series,
                        "total_ns": round(mean_ns * operations_per_series),
                        "mean_ns": mean_ns,
                    })
            for combo in combos:
                means = series_means[(combo.backend, combo.algorithm)]
                results.append({
                    "backend": combo.backend,
                    "algorithm": combo.algorithm,
                    "size_bytes": size,
                    "operation": operation,
                    "series_mean_ns": means,
                    **summarize(means, size),
                })

    report = {
        "schema_version": 1,
        "run_id": run_id,
        "environment": environment,
        "parameters": {
            "sizes_bytes": list(sizes),
            "warmup": warmup,
            "series": SERIES,
            "operations_per_series": operations_per_series,
            "context_bytes": len(BENCHMARK_AAD),
            "includes_cipher_object_creation": True,
            "operations": list(OPERATIONS),
            "combination_order": f"shuffled between series, seed {ORDER_SEED}",
        },
        "results": results,
    }
    with open(output_dir / "raw.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(raw_rows)
    with open(output_dir / "report.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    expected_raw = len(BACKENDS) * len(KEY_BYTES) * len(sizes) * len(OPERATIONS) * SERIES
    if len(raw_rows) != expected_raw or len(results) != expected_raw // SERIES:
        raise RuntimeError("Unexpected number of result rows")
    print(
        f"Готово: {len(raw_rows)} серій у raw.csv, "
        f"{len(results)} підсумкових рядків у report.json ({output_dir})"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 2 symmetric benchmark")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    run_benchmark(args.output_dir)


if __name__ == "__main__":
    main()
