"""Локальний відтворюваний експеримент хешування (практична 4).

Запуск із кореня проєкту після фіксації коду:

    python -m benchmarks.hash_benchmark

Створює results/practice-04/raw.csv, avalanche.csv і report.json. Перед
вимірюванням вимагає чистого робочого каталогу (без незафіксованих змін у
відстежуваних файлах) і записує git rev-parse HEAD у source_commit.
У таймер входять лише створення об'єкта, update, digest і цикл повторів;
генерація байтів, нарізання блоків, прогрів, перевірки, hex і файли — поза ним.
"""
import argparse
import csv
import json
import os
import platform
import re
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter_ns

from app.schemas.hash_report import validate_report
from app.security.hashing import profiles
from app.security.hashing.adapters import hamming_bits, hash_bytes, prepare_operation
from app.security.hashing.profiles import (
    AVALANCHE_BYTES, AVALANCHE_TRIALS, CHECK_NAMES, CHUNK_BYTES, PAYLOAD_SIZES,
    PROFILES, SERIES, WARMUP, repeat_count, synthetic_payload,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "results" / "practice-04"
MODES = ("whole", "chunked")
RAW_COLUMNS = ["algorithm", "mode", "payload_bytes", "series", "repeats",
               "elapsed_ns", "ns_per_op"]
AVALANCHE_COLUMNS = ["algorithm", "trial", "bit_index", "digest_bits",
                     "flipped_bits", "fraction"]

# Офіційні вектори (FIPS 180-4, FIPS 202, RFC 1321, RFC 3174/6234) та
# BLAKE2 з digest_size=32, незалежно перевірені PyCryptodome. Задані тут як
# сталі, а не обчислені тією самою функцією, яку перевіряють: (порожні, b"abc").
KNOWN_VECTORS = {
    "sha256": (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    "sha512": (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192"
        "992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    "sha3-256": (
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    "blake2b-256": (
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
    "blake2s-256": (
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    "md5": ("d41d8cd98f00b204e9800998ecf8427e", "900150983cd24fb0d6963f7d28e17f72"),
    "sha1": ("da39a3ee5e6b4b0d3255bfef95601890afd80709",
             "a9993e364706816aba3e25717850c26c9cd0d89d"),
}

# Перевірка Unicode: текст і його явні байти UTF-8, записані окремо.
UNICODE_TEXT = "Відомість Цифрового деканату"
UNICODE_UTF8 = bytes.fromhex(
    "d092d196d0b4d0bed0bcd196d181d182d18c20d0a6d0b8d184d180d0bed0b2d0bed0b3d0be"
    "20d0b4d0b5d0bad0b0d0bdd0b0d182d183")


def measure_batch(operation, repeats: int) -> float:
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")
    start = perf_counter_ns()
    for _ in range(repeats):
        operation()
    elapsed_ns = perf_counter_ns() - start
    return elapsed_ns / repeats


def _timed_series(operation, repeats: int) -> int:
    """Час однієї серії в наносекундах (додатне ціле)."""
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")
    start = perf_counter_ns()
    for _ in range(repeats):
        operation()
    return max(perf_counter_ns() - start, 1)


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != 5:
        raise ValueError("five series required")
    q1, _, q3 = quantiles(samples, n=4, method="inclusive")
    return median(samples), q3 - q1


def throughput(size: int, median_ns: float) -> float:
    return size * 1e9 / (2**20 * median_ns)


# ---------- Git і середовище ----------

def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True,
                          timeout=15, check=True, cwd=ROOT).stdout.strip()


def source_commit(allow_dirty: bool = False) -> str:
    """SHA зафіксованого коду перед запуском; відмова за незафіксованих змін."""
    commit = _git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("cannot determine the source commit")
    if not allow_dirty and _git("status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError("commit your changes before the experiment (git status is not clean)")
    return commit


def _cpu_model() -> str:
    try:
        if sys.platform == "win32":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
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


def collect_environment() -> dict:
    """Лише метадані середовища, без приватних шляхів чи імен користувачів."""
    return {
        "python": platform.python_version(),
        "openssl_ssl": ssl.OPENSSL_VERSION,
        "os": platform.platform(),
        "cpu": _cpu_model()[:160],
        "architecture": platform.machine() or "unknown",
    }


# ---------- Перевірки коректності ----------

def run_checks(algorithm: str) -> list[dict]:
    digest_bytes = PROFILES[algorithm].digest_bytes
    empty_hex, abc_hex = KNOWN_VECTORS[algorithm]

    def safe(test) -> bool:
        try:
            return bool(test())
        except Exception:
            return False

    def unicode_check() -> bool:
        data = UNICODE_TEXT.encode("utf-8")
        if data != UNICODE_UTF8:
            return False
        stream = profiles.make_hasher(algorithm)
        for i in range(len(UNICODE_UTF8)):          # побайтова подача тих самих байтів
            stream.update(UNICODE_UTF8[i:i + 1])
        return hash_bytes(algorithm, data) == stream.digest() and \
            hash_bytes(algorithm, data) != hash_bytes(algorithm, UNICODE_TEXT.encode("utf-16"))

    def determinism() -> bool:
        data = synthetic_payload(1024)
        first = hash_bytes(algorithm, data)
        hash_bytes(algorithm, b"another synthetic message")   # інший виклик між ними
        return first == hash_bytes(algorithm, data) == hash_bytes(algorithm, bytes(data))

    def lengths() -> bool:
        samples = [b"", b"abc"] + [synthetic_payload(s) for s in PAYLOAD_SIZES]
        return all(len(hash_bytes(algorithm, d, m)) == digest_bytes
                   for d in samples for m in MODES)

    def stream_equivalence() -> bool:
        return all(hash_bytes(algorithm, synthetic_payload(s), "whole")
                   == hash_bytes(algorithm, synthetic_payload(s), "chunked")
                   for s in PAYLOAD_SIZES)

    tests = {
        "known-abc": lambda: hash_bytes(algorithm, b"abc").hex() == abc_hex,
        "known-empty": lambda: hash_bytes(algorithm, b"").hex() == empty_hex,
        "unicode-utf8": unicode_check,
        "determinism": determinism,
        "digest-length": lengths,
        "stream-equivalence": stream_equivalence,
    }
    return [dict(algorithm=algorithm, name=name, passed=safe(tests[name]))
            for name in CHECK_NAMES]


# ---------- Лавинний дослід ----------

def avalanche(algorithm: str) -> tuple[list[dict], dict]:
    original = synthetic_payload(AVALANCHE_BYTES)
    reference = hash_bytes(algorithm, original)
    bits = 8 * len(reference)
    rows = []
    for trial in range(1, AVALANCHE_TRIALS + 1):
        index = trial - 1
        changed = bytearray(original)                 # нова копія оригіналу щоразу
        changed[index // 8] ^= 1 << (index % 8)
        flipped = hamming_bits(reference, hash_bytes(algorithm, bytes(changed)))
        rows.append(dict(algorithm=algorithm, trial=trial, bit_index=index,
                         digest_bits=bits, flipped_bits=flipped,
                         fraction=flipped / bits))
    counts = [r["flipped_bits"] for r in rows]
    mean_bits = sum(counts) / len(counts)
    summary = dict(algorithm=algorithm, input_bytes=AVALANCHE_BYTES,
                   trials=AVALANCHE_TRIALS, digest_bits=bits,
                   min_flipped_bits=min(counts), max_flipped_bits=max(counts),
                   mean_flipped_bits=mean_bits, mean_fraction=mean_bits / bits)
    return rows, summary


# ---------- Експеримент ----------

def _atomic_write(path: Path, writer) -> None:
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "w", newline="", encoding="utf-8") as handle:
        writer(handle)
    os.replace(temp, path)


def run_experiment(output_dir: Path = DEFAULT_OUTPUT_DIR, *,
                   commit: str | None = None, allow_dirty: bool = False,
                   quiet: bool = False) -> tuple[dict, bool]:
    """Повертає (звіт, усі_перевірки_пройдено). Файли пишуться в будь-якому разі."""
    output_dir = Path(output_dir)
    commit = commit or source_commit(allow_dirty)
    statuses = profiles.probe_profiles()     # RuntimeError, якщо немає основного профілю
    available = [s["algorithm"] for s in statuses if s["available"]]
    environment = collect_environment()

    # Підготовка поза таймером: байти й операції (з нарізаними блоками) — один раз.
    payloads = {size: synthetic_payload(size) for size in PAYLOAD_SIZES}
    combos = [(a, m, s) for a in available for m in MODES for s in PAYLOAD_SIZES]
    operations = {c: prepare_operation(c[0], payloads[c[2]], c[1]) for c in combos}

    for combo in combos:                      # прогрів: 10 повних операцій на поєднання
        op = operations[combo]
        for _ in range(WARMUP):
            op()

    raw_rows, samples = [], {c: [] for c in combos}
    for series in range(1, SERIES + 1):       # серії чергуються між поєднаннями
        if not quiet:
            print(f"Серія {series}/{SERIES}...", flush=True)
        for combo in combos:
            repeats = repeat_count(combo[2])
            elapsed = _timed_series(operations[combo], repeats)
            per_op = elapsed / repeats
            samples[combo].append(per_op)
            raw_rows.append(dict(algorithm=combo[0], mode=combo[1],
                                 payload_bytes=combo[2], series=series,
                                 repeats=repeats, elapsed_ns=elapsed,
                                 ns_per_op=per_op))

    results = []
    for combo in combos:
        med, iqr = summarize(samples[combo])
        results.append(dict(algorithm=combo[0], mode=combo[1], payload_bytes=combo[2],
                            digest_bytes=PROFILES[combo[0]].digest_bytes,
                            repeats=repeat_count(combo[2]), median_ns=med, iqr_ns=iqr,
                            throughput_mib_s=throughput(combo[2], med)))

    checks, avalanche_rows, avalanche_summary = [], [], []
    for algorithm in available:
        checks.extend(run_checks(algorithm))
        rows, summary = avalanche(algorithm)
        avalanche_rows.extend(rows)
        avalanche_summary.append(summary)

    report = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_commit": commit,
        "parameters": {
            "sizes": list(PAYLOAD_SIZES), "chunk_bytes": CHUNK_BYTES,
            "warmup": WARMUP, "series": SERIES,
            "repeats_small": repeat_count(64), "repeats_large": repeat_count(1048576),
            "avalanche_trials": AVALANCHE_TRIALS, "avalanche_bytes": AVALANCHE_BYTES,
        },
        "environment": environment,
        "algorithms": statuses,
        "results": results,
        "avalanche": avalanche_summary,
        "checks": checks,
    }
    validate_report(report)                   # та сама функція, що й в API
    a = len(available)
    if (len(raw_rows), len(results), len(avalanche_rows), len(checks)) != (40 * a, 8 * a, 100 * a, 6 * a):
        raise RuntimeError("unexpected matrix size")

    output_dir.mkdir(parents=True, exist_ok=True)

    def csv_writer(rows, columns):
        def write(handle):
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        return write

    def write_json(handle):
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    _atomic_write(output_dir / "raw.csv", csv_writer(raw_rows, RAW_COLUMNS))
    _atomic_write(output_dir / "avalanche.csv", csv_writer(avalanche_rows, AVALANCHE_COLUMNS))
    _atomic_write(output_dir / "report.json", write_json)
    failed = [c for c in checks if not c["passed"]]
    if not quiet:
        print(f"Готово: профілів {a}, raw.csv {len(raw_rows)}, results {len(results)}, "
              f"avalanche.csv {len(avalanche_rows)}, checks {len(checks)} "
              f"(невдалих: {len(failed)})")
    return report, not failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Practice 4 hashing experiment")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--allow-dirty", action="store_true",
                        help="лише для розробки: дозволити незафіксований код")
    args = parser.parse_args(argv)
    try:
        _, ok = run_experiment(args.output_dir, allow_dirty=args.allow_dirty)
    except (NotImplementedError, RuntimeError) as exc:
        print(str(exc))
        return 2
    if not ok:
        print("Є невдалі перевірки коректності: звіт записано для діагностики.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
